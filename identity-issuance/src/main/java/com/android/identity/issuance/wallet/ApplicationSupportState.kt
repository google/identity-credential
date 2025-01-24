package com.android.identity.issuance.wallet

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.X509Cert
import com.android.identity.device.AssertionDPoPKey
import com.android.identity.device.DeviceAssertion
import com.android.identity.device.DeviceAttestationAndroid
import com.android.identity.flow.annotation.FlowMethod
import com.android.identity.flow.annotation.FlowState
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.issuance.ApplicationSupport
import com.android.identity.issuance.LandingUrlUnknownException
import com.android.identity.issuance.WalletServerSettings
import com.android.identity.flow.cache
import com.android.identity.flow.server.getTable
import com.android.identity.issuance.funke.toJson
import com.android.identity.issuance.validateDeviceAssertionBindingKeys
import com.android.identity.securearea.KeyAttestation
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.Logger
import com.android.identity.util.toBase64Url
import com.android.identity.util.validateAndroidKeyAttestation
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

@FlowState(flowInterface = ApplicationSupport::class)
@CborSerializable
class ApplicationSupportState(
    var clientId: String
) {
    companion object {
        const val URL_PREFIX = "landing/"
        const val TAG = "ApplicationSupportState"

        // This is the ID that was allocated to our app in the context of Funke. Use it as
        // default OpenId4VCI client id for ease of development. It is NOT used as value for
        // clientId field above! It identifies our wallet app to OpenId4VCI servers, whereas
        // clientId identifies a particular wallet app instance to the wallet server.
        const val FUNKE_CLIENT_ID = "60f8c117-b692-4de8-8f7f-636ff852baa6"

        val landingTableSpec = StorageTableSpec(
            name = "LandingUrls",
            supportPartitions = false,
            supportExpiration = true
        )

        private val EXPIRATION = 1.days
    }

    @FlowMethod
    suspend fun createLandingUrl(env: FlowEnvironment): String {
        val storage = env.getTable(landingTableSpec)
        val id = storage.insert(
            key = null,
            data = ByteString(LandingRecord(clientId).toCbor()),
            expiration = Clock.System.now() + EXPIRATION
        )
        Logger.i(TAG, "Created landing URL '$id'")
        val configuration = env.getInterface(Configuration::class)!!
        val baseUrl = configuration.getValue("base_url")!!
        return "$baseUrl/$URL_PREFIX$id"
    }

    @FlowMethod
    suspend fun getLandingUrlStatus(env: FlowEnvironment, landingUrl: String): String? {
        val configuration = env.getInterface(Configuration::class)!!
        val baseUrl = configuration.getValue("base_url")!!
        val prefix = "$baseUrl/$URL_PREFIX"
        if (!landingUrl.startsWith(prefix)) {
            Logger.e(TAG, "baseUrl must start with $prefix, actual '$landingUrl'")
            throw IllegalStateException("baseUrl must start with $prefix")
        }
        val storage = env.getTable(landingTableSpec)
        val id = landingUrl.substring(prefix.length)
        Logger.i(TAG, "Querying landing URL '$id'")
        val recordData = storage.get(id)
            ?: throw LandingUrlUnknownException("No landing url '$id'")
        val record = LandingRecord.fromCbor(recordData.toByteArray())
        if (record.resolved != null) {
            Logger.i(TAG, "Removed landing URL '$id'")
            storage.delete(id)
        }
        return record.resolved
    }

    @FlowMethod
    suspend fun createJwtClientAssertion(
        env: FlowEnvironment,
        keyAttestation: KeyAttestation,
        keyAssertion: DeviceAssertion
    ): String {
        val storage = env.getTable(AuthenticationState.clientTableSpec)
        val clientRecord = ClientRecord.fromCbor(storage.get(clientId)!!.toByteArray())

        clientRecord.deviceAttestation.validateAssertion(keyAssertion)

        val assertion = keyAssertion.assertion as AssertionDPoPKey

        if (clientRecord.deviceAttestation is DeviceAttestationAndroid) {
            val settings = WalletServerSettings(env.getInterface(Configuration::class)!!)
            val certChain = keyAttestation.certChain!!
            check(assertion.publicKey == certChain.certificates.first().ecPublicKey)
            validateAndroidKeyAttestation(
                certChain,
                null,  // no challenge check needed
                settings.androidRequireGmsAttestation,
                settings.androidRequireVerifiedBootGreen,
                settings.androidRequireAppSignatureCertificateDigests
            )
        }

        check(keyAttestation.certChain!!.certificates[0].ecPublicKey == keyAttestation.publicKey)
        return createJwtClientAssertion(env, keyAttestation.publicKey, assertion.targetUrl)
    }

    @FlowMethod
    fun getClientAssertionId(env: FlowEnvironment, targetIssuanceUrl: String): String {
        return FUNKE_CLIENT_ID
    }

    @FlowMethod
    suspend fun createJwtKeyAttestation(
        env: FlowEnvironment,
        keyAttestations: List<KeyAttestation>,
        keysAssertion: DeviceAssertion // holds AssertionBindingKeys
    ): String {
        val storage = env.getTable(AuthenticationState.clientTableSpec)
        val clientRecord = ClientRecord.fromCbor(storage.get(clientId)!!.toByteArray())
        val assertion = validateDeviceAssertionBindingKeys(
            env = env,
            deviceAttestation = clientRecord.deviceAttestation,
            keyAttestations = keyAttestations,
            deviceAssertion = keysAssertion,
            nonce = null,  // no check
        )

        val nonce = String(assertion.nonce.toByteArray())
        val keyList = assertion.publicKeys

        val attestationData = env.cache(AttestationData::class) { configuration, resources ->
            // The key that we use here is unique for a particular Wallet ecosystem.
            // Use client attestation key as default for development (default is NOT suitable
            // for production, as private key CANNOT be in the source repository).
            val certificateName = configuration.getValue("openid4vci.key-attestation.certificate")
                ?: "attestation/certificate.pem"
            val certificate = X509Cert.fromPem(resources.getStringResource(certificateName)!!)
            val privateKeyName = configuration.getValue("openid4vci.key-attestation.privateKey")
                ?: "attestation/private_key.pem"
            val privateKey = EcPrivateKey.fromPem(
                resources.getStringResource(privateKeyName)!!,
                certificate.ecPublicKey
            )
            val issuer = configuration.getValue("openid4vci.key-attestation.issuer")
                ?: configuration.getValue("base_url")
                ?: "https://github.com/openwallet-foundation-labs/identity-credential"
            AttestationData(certificate, privateKey, issuer)
        }
        val publicKey = attestationData.certificate.ecPublicKey
        val privateKey = attestationData.privateKey
        val alg = publicKey.curve.defaultSigningAlgorithm.jwseAlgorithmIdentifier
        val head = buildJsonObject {
            put("typ", JsonPrimitive("keyattestation+jwt"))
            put("alg", JsonPrimitive(alg))
            put("jwk", publicKey.toJson(null))  // TODO: use x5c instead here?
        }.toString().toByteArray().toBase64Url()

        val now = Clock.System.now()
        val notBefore = now - 1.seconds
        val expiration = now + 5.minutes
        val payload = buildJsonObject {
            put("iss", attestationData.clientId)
            put("attested_keys", JsonArray(keyList.map { it.toJson(null) }))
            put("nonce", nonce)
            put("nbf", notBefore.epochSeconds)
            put("exp", expiration.epochSeconds)
            put("iat", now.epochSeconds)
            if (assertion.userAuthentication.isNotEmpty()) {
                put("user_authentication",
                    JsonArray(assertion.userAuthentication.map { JsonPrimitive(it) })
                )
            }
            if (assertion.keyStorage.isNotEmpty()) {
                put("key_storage",
                    JsonArray(assertion.keyStorage.map { JsonPrimitive(it) })
                )
            }
        }.toString().toByteArray().toBase64Url()

        val message = "$head.$payload"
        val sig = Crypto.sign(
            privateKey, privateKey.curve.defaultSigningAlgorithm, message.toByteArray()
        )
        val signature = sig.toCoseEncoded().toBase64Url()

        return "$message.$signature"
    }

    // Not exposed as RPC!
    suspend fun createJwtClientAssertion(
        env: FlowEnvironment,
        clientPublicKey: EcPublicKey,
        targetIssuanceUrl: String
    ): String {
        val attestationData = env.cache(
            AttestationData::class,
            targetIssuanceUrl
        ) { configuration, resources ->
            // These are basically our credentials to talk to a particular OpenID4VCI issuance
            // server. So in real life this may need to be parameterized by targetIssuanceUrl
            // if we support many issuance servers. Alternatively, we may have a single public key
            // to be registered with multiple issuers. For development we are OK using
            // a single key for everything.
            val certificateName = configuration.getValue("attestation.certificate")
                ?: "attestation/certificate.pem"
            val clientId = configuration.getValue("attestation.clientId") ?: FUNKE_CLIENT_ID
            val certificate = X509Cert.fromPem(resources.getStringResource(certificateName)!!)

            // NB: default private key is just an arbitrary value, so it can be checked into
            // git and work out of the box for our own OpenID4VCI issuer (in particular, this is
            // NOT the private key registered with Funke server!) It may or may not work for
            // development/prototype servers, but it, of course, should not be used in production!
            // In fact, in production this key may need to come from an HSM, not read from some
            // PEM resource!
            val privateKeyName = configuration.getValue("attestation.privateKey")
                ?: "attestation/private_key.pem"
            val privateKey = EcPrivateKey.fromPem(
                resources.getStringResource(privateKeyName)!!,
                certificate.ecPublicKey
            )
            AttestationData(certificate, privateKey, clientId)
        }
        val publicKey = attestationData.certificate.ecPublicKey
        val privateKey = attestationData.privateKey
        val alg = publicKey.curve.defaultSigningAlgorithm.jwseAlgorithmIdentifier
        val head = buildJsonObject {
            put("typ", JsonPrimitive("JWT"))
            put("alg", JsonPrimitive(alg))
            put("jwk", publicKey.toJson(null))
        }.toString().toByteArray().toBase64Url()

        val now = Clock.System.now()
        val notBefore = now - 1.seconds
        // Expiration here is only for the client assertion to be presented to the issuing server
        // in the given timeframe (which happens without user interaction). It does not imply that
        // the key becomes invalid at that point in time.
        val expiration = now + 5.minutes
        val payload = JsonObject(
            mapOf(
                "iss" to JsonPrimitive(attestationData.clientId),
                "sub" to JsonPrimitive(attestationData.clientId), // RFC 7523 Section 3, item 2.B
                "cnf" to JsonObject(
                    mapOf(
                        "jwk" to clientPublicKey.toJson(clientId)
                    )
                ),
                "nbf" to JsonPrimitive(notBefore.epochSeconds),
                "exp" to JsonPrimitive(expiration.epochSeconds),
                "iat" to JsonPrimitive(now.epochSeconds)
            )
        ).toString().toByteArray().toBase64Url()

        val message = "$head.$payload"
        val sig = Crypto.sign(
            privateKey, privateKey.curve.defaultSigningAlgorithm, message.toByteArray()
        )
        val signature = sig.toCoseEncoded().toBase64Url()

        return "$message.$signature"
    }

    internal data class AttestationData(
        val certificate: X509Cert,
        val privateKey: EcPrivateKey,
        val clientId: String
    )
}
