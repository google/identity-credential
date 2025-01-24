package com.android.identity.server.openid4vci

import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.toDataItem
import com.android.identity.cose.Cose
import com.android.identity.cose.CoseLabel
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.flow.handler.InvalidRequestException
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.Resources
import com.android.identity.flow.cache
import com.android.identity.flow.server.getTable
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.sdjwt.Issuer
import com.android.identity.sdjwt.SdJwtVcGenerator
import com.android.identity.sdjwt.util.JsonWebKey
import com.android.identity.util.fromBase64Url
import com.android.identity.util.toBase64Url
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.random.Random
import kotlin.time.Duration.Companion.days

/**
 * Issues a credential based on access token issued by [TokenServlet].
 *
 * TODO: assess token is meant to a single use (verify that). Add replay protection.
 */
class CredentialServlet : BaseServlet() {
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val authorization = req.getHeader("Authorization")
        if (authorization == null || authorization.substring(0, 5).lowercase() != "dpop ") {
            throw InvalidRequestException("Authorization header invalid or missing")
        }
        val accessToken = authorization.substring(5)
        val id = codeToId(OpaqueIdType.ACCESS_TOKEN, accessToken)
        val state = runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
        }
        authorizeWithDpop(state.dpopKey, req, state.dpopNonce!!.toByteArray().toBase64Url(), accessToken)
        val nonce = state.cNonce!!.toByteArray().toBase64Url()  // credential nonce
        state.dpopNonce = null
        state.cNonce = null
        runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            storage.update(id, ByteString(state.toCbor()))
        }
        val requestString = String(req.inputStream.readNBytes(req.contentLength))
        val json = Json.parseToJsonElement(requestString) as JsonObject
        val format = Openid4VciFormat.fromJson(json)
        val factory = CredentialFactory.byOfferId.values.find { factory ->
            factory.format == format && factory.scope == state.scope
        }
        if (factory == null) {
            throw IllegalStateException(
                "No credential can be created for scope '${state.scope}' and the given format")
        }
        if (factory.cryptographicBindingMethods.isEmpty()) {
            // Keyless credential: no need for proof/proofs parameter.
            val credential = runBlocking {
                factory.makeCredential(environment, state, null)
            }
            resp.writer.write(Json.encodeToString(buildJsonObject {
                put("credential", credential)
            }))
            return
        }
        val proofsObj = json["proofs"]?.jsonObject
        val singleProof = proofsObj == null
        val proofs: JsonArray
        val proofType: String
        if (proofsObj == null) {
            val proof = json["proof"]
                ?: throw InvalidRequestException("neither 'proof' or 'proofs' parameter provided")
            proofType = proof.jsonObject["proof_type"]?.jsonPrimitive?.content!!
            proofs = buildJsonArray { add(proof.jsonObject[proofType]!!) }
        } else {
            proofType = if (proofsObj.containsKey("jwt")) {
                "jwt"
            } else if (proofsObj.containsKey("attestation")) {
                "attestation"
            } else {
                throw InvalidRequestException("Unsupported proof type")
            }
            proofs = proofsObj[proofType]!!.jsonArray
            if (proofs.size == 0) {
                throw InvalidRequestException("'proofs' is empty")
            }
        }

        val authenticationKeys = when (proofType) {
            "attestation" -> {
                val keyAttestationCertificate = runBlocking {
                    environment.cache(
                        KeyAttestationCertificate::class,
                        state.clientId
                    ) { configuration, resources ->
                        // By default using the same key/certificate as for client attestation
                        val certificateName =
                            configuration.getValue("openid4vci.key-attestation.certificate")
                                ?: "attestation/certificate.pem"
                        val certificate =
                            X509Cert.fromPem(resources.getStringResource(certificateName)!!)
                        KeyAttestationCertificate(certificate)
                    }
                }

                proofs.flatMap { proof ->
                    val keyAttestation = proof.jsonPrimitive.content
                    checkJwtSignature(
                        keyAttestationCertificate.certificate.ecPublicKey,
                        keyAttestation
                    )
                    val parts = keyAttestation.split(".")

                    if (parts.size != 3) {
                        throw InvalidRequestException("invalid value for 'proof(s).attestation' parameter")
                    }
                    val body = Json.parseToJsonElement(String(parts[1].fromBase64Url())).jsonObject
                    if (body["nonce"]?.jsonPrimitive?.content != nonce) {
                        throw InvalidRequestException("invalid nonce in 'proof(s).attestation' parameter")
                    }
                    body["attested_keys"]!!.jsonArray.map { key ->
                        JsonWebKey(buildJsonObject {
                            put("jwk", key)
                        }).asEcPublicKey
                    }
                }
            }
            "jwt" -> {
                if (!isStandaloneProofOfPossessionAccepted(environment)) {
                    throw InvalidRequestException("jwt proofs are not accepted by this server")
                }
                proofs.map { proof ->
                    val jwt = proof.jsonObject["jwt"]?.jsonPrimitive?.content
                        ?: throw InvalidRequestException("either 'proof.attestation' or 'proof.jwt' parameter is required")
                    val parts = jwt.split(".")
                    if (parts.size != 3) {
                        throw InvalidRequestException("invalid value for 'proof.jwt' parameter")
                    }
                    val head =
                        Json.parseToJsonElement(String(parts[0].fromBase64Url())) as JsonObject
                    val authenticationKey = JsonWebKey(head).asEcPublicKey
                    checkJwtSignature(authenticationKey, jwt)
                    authenticationKey
                }
            }
            else -> {
                throw InvalidRequestException("unsupported proof type")
            }
        }

        val credentials =
            runBlocking {
                authenticationKeys.map { key ->
                    factory.makeCredential(environment, state, key)
                }
            }

        val result = if (singleProof && credentials.size == 1) {
            buildJsonObject {
                put("credential", credentials[0])
            }
        } else {
            buildJsonObject {
                put("credentials", buildJsonArray {
                    for (credential in credentials) {
                        add(JsonPrimitive(credential))
                    }
                })
            }
        }
        resp.writer.write(Json.encodeToString(result))
    }

    private fun createCredentialSdJwt(
        state: IssuanceState,
        authenticationKey: EcPublicKey
    ): String {

        val data = state.credentialData!!
        val identityAttributes = buildJsonObject {
            put("given_name", JsonPrimitive(data.getDataElementString(EUPersonalID.EUPID_NAMESPACE, "given_name")))
            put("family_name", JsonPrimitive(data.getDataElementString(EUPersonalID.EUPID_NAMESPACE, "family_name")))
        }

        val sdJwtVcGenerator = SdJwtVcGenerator(
            random = Random,
            payload = identityAttributes,
            docType = EUPersonalID.EUPID_VCT,
            issuer = Issuer("https://example-issuer.com", Algorithm.ES256, "key-1")
        )

        val now = Clock.System.now()

        val timeSigned = now
        val validFrom = now
        val validUntil = validFrom + 30.days

        sdJwtVcGenerator.publicKey = JsonWebKey(authenticationKey)
        sdJwtVcGenerator.timeSigned = timeSigned
        sdJwtVcGenerator.timeValidityBegin = validFrom
        sdJwtVcGenerator.timeValidityEnd = validUntil

        val resources = environment.getInterface(Resources::class)!!
        val documentSigningKeyCert =
            X509Cert.fromPem(resources.getStringResource("ds_certificate.pem")!!)
        val documentSigningKey = EcPrivateKey.fromPem(
            resources.getStringResource("ds_private_key.pem")!!,
            documentSigningKeyCert.ecPublicKey)
        val sdJwt = sdJwtVcGenerator.generateSdJwt(documentSigningKey)

        return sdJwt.toString()
    }

    private fun createCredentialMdoc(
        state: IssuanceState,
        authenticationKey: EcPublicKey
    ): ByteArray {
        val now = Clock.System.now()

        // Create AuthKeys and MSOs, make sure they're valid for 30 days. Also make
        // sure to not use fractional seconds as 18013-5 calls for this (clauses 7.1
        // and 9.1.2.4)
        //
        val timeSigned = Instant.fromEpochSeconds(now.epochSeconds, 0)
        val validFrom = Instant.fromEpochSeconds(now.epochSeconds, 0)
        val validUntil = validFrom + 30.days

        // Generate an MSO and issuer-signed data for this authentication key.
        val docType = EUPersonalID.EUPID_DOCTYPE
        val msoGenerator = MobileSecurityObjectGenerator(
            "SHA-256",
            docType,
            authenticationKey
        )
        msoGenerator.setValidityInfo(timeSigned, validFrom, validUntil, null)

        val randomProvider = Random.Default
        val issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
            state.credentialData!!,
            randomProvider,
            16,
            null
        )
        for (nameSpaceName in issuerNameSpaces.keys) {
            val digests = MdocUtil.calculateDigestsForNameSpace(
                nameSpaceName,
                issuerNameSpaces,
                Algorithm.SHA256
            )
            msoGenerator.addDigestIdsForNamespace(nameSpaceName, digests)
        }

        val resources = environment.getInterface(Resources::class)!!
        val documentSigningKeyCert = X509Cert.fromPem(
            resources.getStringResource("ds_certificate.pem")!!)
        val documentSigningKey = EcPrivateKey.fromPem(
            resources.getStringResource("ds_private_key.pem")!!,
            documentSigningKeyCert.ecPublicKey
        )

        val mso = msoGenerator.generate()
        val taggedEncodedMso = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(mso)))
        val protectedHeaders = mapOf<CoseLabel, DataItem>(Pair(
            CoseNumberLabel(Cose.COSE_LABEL_ALG),
            Algorithm.ES256.coseAlgorithmIdentifier.toDataItem()
        ))
        val unprotectedHeaders = mapOf<CoseLabel, DataItem>(Pair(
            CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
            X509CertChain(listOf(
                X509Cert(documentSigningKeyCert.encodedCertificate))
            ).toDataItem()
        ))
        val encodedIssuerAuth = Cbor.encode(
            Cose.coseSign1Sign(
                documentSigningKey,
                taggedEncodedMso,
                true,
                Algorithm.ES256,
                protectedHeaders,
                unprotectedHeaders
            ).toDataItem()
        )

        val issuerProvidedAuthenticationData = StaticAuthDataGenerator(
            issuerNameSpaces,
            encodedIssuerAuth
        ).generate()

        return issuerProvidedAuthenticationData
    }

    private data class KeyAttestationCertificate(val certificate: X509Cert)

    companion object {
        /**
         * Checks if this server accepts proof of possession **without** key attestation.
         *
         * Our code does not support proof of possession with key attestation (only standalone
         * key attestation or standalone proof of possession). Standalone proof of possession
         * is disabled by default, as it does not really guarantee where the private key is
         * stored. Don't enable this unless you are sure you understand the tradeoffs involved!
         *
         * NB: Proof of possession **with** key attestation, if implemented, could be just enabled
         * unconditionally, as it does not have this issue (as long as key attestation is required).
         */
        internal fun isStandaloneProofOfPossessionAccepted(environment: FlowEnvironment): Boolean {
            val allowProofOfPossession = environment.getInterface(Configuration::class)
                ?.getValue("openid4vci.allow-proof-of-possession")
            return allowProofOfPossession == "true"
        }
    }
}