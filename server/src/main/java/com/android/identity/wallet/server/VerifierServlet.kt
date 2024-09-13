package com.android.identity.wallet.server

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DiagnosticOption
import com.android.identity.cbor.Simple
import com.android.identity.cbor.Tstr
import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.X509CertificateCreateOption
import com.android.identity.crypto.X509CertificateExtension
import com.android.identity.crypto.create
import com.android.identity.crypto.javaPrivateKey
import com.android.identity.crypto.javaPublicKey
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.Storage
import com.android.identity.mdoc.request.DeviceRequestGenerator
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.sdjwt.presentation.SdJwtVerifiablePresentation
import com.android.identity.sdjwt.vc.JwtBody
import com.android.identity.util.Logger
import com.android.identity.util.fromBase64Url
import com.android.identity.util.fromHex
import com.android.identity.util.toBase64Url
import com.android.identity.util.toHex
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import jakarta.servlet.ServletConfig
import jakarta.servlet.http.HttpServlet
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimePeriod
import kotlinx.datetime.TimeZone
import kotlinx.datetime.plus
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import net.minidev.json.JSONArray
import net.minidev.json.JSONObject
import net.minidev.json.JSONStyle
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.URLEncoder
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

enum class Protocol {
    W3C_DC_PREVIEW,
    W3C_DC_ARF,
    PLAIN_OPENID4VP,
    EUDI_OPENID4VP,
    MDOC_OPENID4VP,
}

enum class DocumentFormat {
    MDOC,
    SDJWT
}

enum class RequestType(val format: DocumentFormat) {
    PID_MDOC_AGE_OVER_18(DocumentFormat.MDOC),
    PID_MDOC_MANDATORY(DocumentFormat.MDOC),
    PID_MDOC_FULL(DocumentFormat.MDOC),
    PID_SDJWT_AGE_OVER_18(DocumentFormat.SDJWT),
    PID_SDJWT_MANDATORY(DocumentFormat.SDJWT),
    PID_SDJWT_FULL(DocumentFormat.SDJWT),
    MDL_MDOC_AGE_OVER_18(DocumentFormat.MDOC),
    MDL_MDOC_AGE_OVER_21(DocumentFormat.MDOC),
    MDL_MDOC_AGE_OVER_21_AND_PORTRAIT(DocumentFormat.MDOC),
    MDL_MDOC_MANDATORY(DocumentFormat.MDOC),
    MDL_MDOC_FULL(DocumentFormat.MDOC),
}

@Serializable
private data class OpenID4VPBeginRequest(
    val requestType: String,
    val protocol: String,
    val origin: String
)

@Serializable
private data class OpenID4VPBeginResponse(
    val uri: String
)

@Serializable
private data class OpenID4VPRedirectUriResponse(
    val redirect_uri: String
)

@Serializable
private data class OpenID4VPGetData(
    val sessionId: String
)

@Serializable
private data class OpenID4VPResultData(
    val lines: List<OpenID4VPResultLine>
)

@Serializable
private data class OpenID4VPResultLine(
    val key: String,
    val value: String
)

@CborSerializable
data class Session(
    val id: String,
    val requestType: RequestType,
    val protocol: Protocol,
    val nonce: String,
    val origin: String,
    val encryptionKey: EcPrivateKey,
    var responseUri: String? = null,
    var deviceResponse: ByteArray? = null,
    var sessionTranscript: ByteArray? = null
) {
    companion object
}

@Serializable
private data class DCBeginRequest(
    val requestType: String,
    val protocol: String,
    val origin: String
)

@Serializable
private data class DCBeginResponse(
    val sessionId: String,
    val dcRequestString: String
)

@Serializable
private data class DCGetDataRequest(
    val sessionId: String,
    val credentialResponse: String
)

@Serializable
private data class DCPreviewResponse(
    val token: String
)

@Serializable
private data class DCArfResponse(
    val encryptedResponse: String
)

/**
 * Verifier servlet.
 *
 * This is using the configuration and storage interfaces from [ServerEnvironment].
 */
class VerifierServlet : HttpServlet() {

    data class KeyMaterial(
        val readerRootKey: EcPrivateKey,
        val readerRootKeyCertificates: X509CertChain,
        val readerRootKeySignatureAlgorithm: Algorithm,
        val readerRootKeyIssuer: String,
    ) {
        fun toCbor() = Cbor.encode(
            CborArray.builder()
                .add(readerRootKey.toCoseKey().toDataItem())
                .add(readerRootKeyCertificates.toDataItem())
                .add(readerRootKeySignatureAlgorithm.coseAlgorithmIdentifier)
                .add(readerRootKeyIssuer)
                .end().build()
        )

        companion object {
            fun fromCbor(encodedCbor: ByteArray): KeyMaterial {
                val array = Cbor.decode(encodedCbor).asArray
                return KeyMaterial(
                    array[0].asCoseKey.ecPrivateKey,
                    array[1].asX509CertChain,
                    Algorithm.fromInt(array[2].asNumber.toInt()),
                    array[3].asTstr,
                )
            }

            fun createKeyMaterial(): KeyMaterial {
                val now = Clock.System.now()
                val validFrom = now
                val validUntil = now.plus(DateTimePeriod(years = 10), TimeZone.currentSystemDefault())

                val extensions = mutableListOf<X509CertificateExtension>()
                extensions.add(
                    X509CertificateExtension(
                        Extension.keyUsage.toString(),
                        true,
                        KeyUsage(KeyUsage.cRLSign + KeyUsage.keyCertSign).encoded
                    )
                )

                // Create Reader Root w/ self-signed certificate.
                //
                // TODO: Migrate to Curve P-384 once we migrate off com.nimbusds.* which
                // only supports Curve P-256.
                //
                val readerRootKey = Crypto.createEcPrivateKey(EcCurve.P256)
                val readerRootKeySignatureAlgorithm = Algorithm.ES256
                val readerRootKeySubject = "CN=OWF IC Online Verifier Reader Root Key"
                val readerRootKeyCertificate = X509Cert.create(
                    readerRootKey.publicKey,
                    readerRootKey,
                    null,
                    readerRootKeySignatureAlgorithm,
                    "1",
                    readerRootKeySubject,
                    readerRootKeySubject,
                    validFrom,
                    validUntil,
                    setOf(
                        X509CertificateCreateOption.INCLUDE_SUBJECT_KEY_IDENTIFIER,
                        X509CertificateCreateOption.INCLUDE_AUTHORITY_KEY_IDENTIFIER_AS_SUBJECT_KEY_IDENTIFIER
                    ),
                    extensions
                )

                return KeyMaterial(
                    readerRootKey,
                    X509CertChain(listOf(readerRootKeyCertificate)),
                    readerRootKeySignatureAlgorithm,
                    readerRootKeySubject,
                )
            }

        }
    }

    companion object {
        private const val TAG = "VerifierServlet"

        private const val STORAGE_TABLE_NAME = "VerifierSessions"

        private lateinit var serverEnvironment: ServerEnvironment
        private lateinit var storage: Storage
        private lateinit var configuration: Configuration

        @Synchronized
        private fun initialize(servletConfig: ServletConfig) {
            if (this::serverEnvironment.isInitialized) {
                return
            }

            serverEnvironment = ServerEnvironment(servletConfig)
            storage = serverEnvironment.getInterface(Storage::class)!!
            configuration = serverEnvironment.getInterface(Configuration::class)!!
        }

        private val keyMaterial: KeyMaterial by lazy {
            val storage = serverEnvironment.getInterface(Storage::class)!!
            val keyMaterialBlob = runBlocking {
                storage.get("RootState", "", "verifierKeyMaterial")?.toByteArray()
                    ?: let {
                        val blob = KeyMaterial.createKeyMaterial().toCbor()
                        storage.insert(
                            "RootState",
                            "",
                            ByteString(blob),
                            "verifierKeyMaterial"
                        )
                        blob
                    }
            }
            KeyMaterial.fromCbor(keyMaterialBlob)
        }

        private val documentTypeRepo: DocumentTypeRepository by lazy {
            val repo =  DocumentTypeRepository()
            repo.addDocumentType(DrivingLicense.getDocumentType())
            repo.addDocumentType(EUPersonalID.getDocumentType())
            repo
        }
    }

    @Override
    override fun init() {
        super.init()

        Security.addProvider(BouncyCastleProvider())

        initialize(servletConfig)
    }

    private fun getRemoteHost(req: HttpServletRequest): String {
        var remoteHost = req.remoteHost
        val forwardedFor = req.getHeader("X-Forwarded-For")
        if (forwardedFor != null) {
            remoteHost = forwardedFor
        }
        return remoteHost
    }

    // Helper to get the local IP address used...
    private fun calcLocalAddress(): InetAddress {
        try {
            var candidateAddress: InetAddress? = null
            for (iface in NetworkInterface.getNetworkInterfaces()) {
                for (inetAddress in iface.inetAddresses) {
                    if (!inetAddress.isLoopbackAddress) {
                        if (inetAddress.isSiteLocalAddress) {
                            return inetAddress
                        } else if (candidateAddress == null) {
                            candidateAddress = inetAddress
                        }
                    }
                }
            }
            if (candidateAddress != null) {
                return candidateAddress
            }
            val jdkSuppliedAddress = InetAddress.getLocalHost()
                ?: throw IllegalStateException("Unexpected null from InetAddress.getLocalHost()")
            return jdkSuppliedAddress
        } catch (e: Throwable) {
            Logger.e(TAG, "Failed to determine address", e)
            throw IllegalStateException("Failed to determine address", e)
        }
    }

    private val baseUrl: String by lazy {
        var ret = configuration.getValue("verifierBaseUrl")
        if (ret == null || ret.length == 0) {
            ret = "http://" + calcLocalAddress().toString() + ":8080" + servletContext.contextPath
            Logger.i(TAG, "Using baseUrl calculated from IP address: $ret")
        } else {
            Logger.i(TAG, "Using baseUrl from configuration: $ret")
        }
        ret
    }

    private val clientId: String by lazy {
        var ret = configuration.getValue("verifierClientId")
        if (ret == null || ret.length == 0) {
            ret = baseUrl
        }
        ret
    }

    private fun createSingleUseReaderKey(): Pair<EcPrivateKey, X509CertChain> {
        val now = Clock.System.now()
        val validFrom = now.plus(DateTimePeriod(minutes = -10), TimeZone.currentSystemDefault())
        val validUntil = now.plus(DateTimePeriod(minutes = 10), TimeZone.currentSystemDefault())
        val readerKey = Crypto.createEcPrivateKey(EcCurve.P256)

        val extensions = mutableListOf<X509CertificateExtension>()
        extensions.add(
            X509CertificateExtension(
                Extension.keyUsage.toString(),
                true,
                KeyUsage(KeyUsage.digitalSignature).encoded
            )
        )
        extensions.add(
            X509CertificateExtension(
                Extension.extendedKeyUsage.toString(),
                true,
                ExtendedKeyUsage(
                    KeyPurposeId.getInstance(ASN1ObjectIdentifier("1.0.18013.5.1.2"))
                ).encoded
            )
        )
        val readerKeySubject = "CN=OWF IC Online Verifier Single-Use Reader Key"

        // TODO: for now, instead of using the per-site Reader Root generated at first run, use the
        //  well-know OWF IC Reader root checked into Git.
        val owfIcReaderCert = X509Cert.fromPem("""
            -----BEGIN CERTIFICATE-----
            MIICCTCCAY+gAwIBAgIQMrJE21vV644Z1wKsQ0NmgDAKBggqhkjOPQQDAzA+MS8wLQYDVQQDDCZP
            V0YgSWRlbnRpdHkgQ3JlZGVudGlhbCBURVNUIFJlYWRlciBDQTELMAkGA1UEBhMCVVQwHhcNMjQw
            MjI4MTQxMjMzWhcNMjkwMjI4MTQxMjMzWjA+MS8wLQYDVQQDDCZPV0YgSWRlbnRpdHkgQ3JlZGVu
            dGlhbCBURVNUIFJlYWRlciBDQTELMAkGA1UEBhMCVVQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARP
            rmdJRF5/4GX+60fo9G5r10EevRrJ9TkGmW1Oyw7tK5FTtsUzG+DhlARSW1czAEVZOPvEOb4KwSH4
            Np4sgCtuZWrubLeXPwcxaF15DIv9F2mGqSB4vBIFIemMdXpl/HOjUjBQMB0GA1UdDgQWBBSh7AVU
            ngz0Xayp0/hfn2xxaSAIhzAfBgNVHSMEGDAWgBSh7AVUngz0Xayp0/hfn2xxaSAIhzAOBgNVHQ8B
            Af8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAPTyY0TzkxfnKdrcRttDBzMS8q/hF8l/odhk77lY
            tJPVgt+aOPumHHFiJvhqvKmQmAIwGKSkPXc6menkG2GpQRQQV7xBlALPO4zSJMoF90hEEK+SK+Ts
            u1Qtl0xtfSQC7wj0
            -----END CERTIFICATE-----
        """.trimIndent())

        val owfIcReaderRoot = EcPrivateKey.fromPem("""
            -----BEGIN PRIVATE KEY-----
            MFcCAQAwEAYHKoZIzj0CAQYFK4EEACIEQDA+AgEBBDAeNZSqN2mQ01YWI04MplJvL01+eQhHylTY
            STfsGrTqXzk0N7Ayx7OJOHnK5DkGV0agBwYFK4EEACI=
            -----END PRIVATE KEY-----
        """.trimIndent(),
            owfIcReaderCert.ecPublicKey)
        val owfIcReaderRootSignatureAlgorithm = Algorithm.ES384
        val owfIcReaderRootIssuer = owfIcReaderCert.javaX509Certificate.issuerX500Principal.name

        val readerKeyCertificate = X509Cert.create(
            readerKey.publicKey,
            owfIcReaderRoot,
            owfIcReaderCert,
            owfIcReaderRootSignatureAlgorithm,
            "1",
            readerKeySubject,
            owfIcReaderRootIssuer,
            validFrom,
            validUntil,
            setOf(
                X509CertificateCreateOption.INCLUDE_SUBJECT_KEY_IDENTIFIER,
                X509CertificateCreateOption.INCLUDE_AUTHORITY_KEY_IDENTIFIER_FROM_SIGNING_KEY_CERTIFICATE
            ),
            extensions
        )
        return Pair(
            readerKey,
            X509CertChain(listOf(readerKeyCertificate) + owfIcReaderCert)
        )

        /*
        val readerKeyCertificate = X509Cert.create(
            readerKey.publicKey,
            keyMaterial.readerRootKey,
            keyMaterial.readerRootKeyCertificates.certificates[0],
            keyMaterial.readerRootKeySignatureAlgorithm,
            "1",
            readerKeySubject,
            keyMaterial.readerRootKeyIssuer,
            validFrom,
            validUntil,
            setOf(
                X509CertificateCreateOption.INCLUDE_SUBJECT_KEY_IDENTIFIER,
                X509CertificateCreateOption.INCLUDE_AUTHORITY_KEY_IDENTIFIER_FROM_SIGNING_KEY_CERTIFICATE
            ),
            extensions
        )
        return Pair(
            readerKey,
            X509CertChain(listOf(readerKeyCertificate) + keyMaterial.readerRootKeyCertificates.certificates)
        )

         */
    }

    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val remoteHost = getRemoteHost(req)
        Logger.i(TAG, "$remoteHost: POST ${req.requestURI}")

        val requestLength = req.contentLength
        val requestData = req.inputStream.readNBytes(requestLength)

        if (req.requestURI.endsWith("verifier/openid4vpBegin")) {
            handleOpenID4VPBegin(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/openid4vpGetData")) {
            handleOpenID4VPGetData(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/openid4vpResponse")) {
            return handleOpenID4VPResponse(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/dcBegin")) {
            handleDcBegin(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/dcGetData")) {
            handleDcGetData(remoteHost, req, resp, requestData)
        } else {
            Logger.w(TAG, "$remoteHost: Unexpected URI ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
        }
    }

    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val remoteHost = getRemoteHost(req)

        Logger.i(TAG, "$remoteHost: GET ${req.requestURI}")

        if (req.requestURI.endsWith("verifier/openid4vpRequest")) {
            handleOpenID4VPRequest(remoteHost, req, resp)
        } else if (req.requestURI.endsWith("verifier/readerRootCert")) {
            handleGetReaderRootCert(remoteHost, req, resp)
        } else {
            Logger.w(TAG, "$remoteHost: Unexpected URI ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
        }
    }

    private fun handleDcBegin(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<DCBeginRequest>(requestString)

        val protocol = when (request.protocol) {
            // Keep in sync with verifier.html
            "w3c_dc_preview" -> Protocol.W3C_DC_PREVIEW
            "w3c_dc_arf" -> Protocol.W3C_DC_ARF
            "openid4vp_plain" -> Protocol.PLAIN_OPENID4VP
            "openid4vp_eudi" -> Protocol.EUDI_OPENID4VP
            "openid4vp_mdoc" -> Protocol.MDOC_OPENID4VP
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown protocol '$request.protocol'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }

        val requestType = when (request.requestType) {
            // Keep in sync with verifier.html
            "pid_mdoc_age_over_18" -> RequestType.PID_MDOC_AGE_OVER_18
            "pid_mdoc_mandatory" -> RequestType.PID_MDOC_MANDATORY
            "pid_mdoc_full" -> RequestType.PID_MDOC_FULL
            "mdl_mdoc_age_over_18" -> RequestType.MDL_MDOC_AGE_OVER_18
            "mdl_mdoc_age_over_21" -> RequestType.MDL_MDOC_AGE_OVER_21
            "mdl_mdoc_age_over_21_and_portrait" -> RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT
            "mdl_mdoc_mandatory" -> RequestType.MDL_MDOC_MANDATORY
            "mdl_mdoc_full" -> RequestType.MDL_MDOC_FULL
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown or unsupported request type '${request.requestType}'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }

        // Create a new session
        val session = Session(
            id = Random.Default.nextBytes(16).toHex(),
            nonce = Random.Default.nextBytes(16).toHex(),
            origin = request.origin,
            encryptionKey = Crypto.createEcPrivateKey(EcCurve.P256),
            requestType = requestType,
            protocol = protocol
        )
        runBlocking {
            storage.insert(
                STORAGE_TABLE_NAME,
                "",
                ByteString(session.toCbor()),
                session.id
            )
        }

        val (readerAuthKey, readerAuthKeyCertification) = createSingleUseReaderKey()

        // Uncomment when making test vectors...
        //Logger.iCbor(TAG, "readerKey: ", Cbor.encode(session.encryptionKey.toCoseKey().toDataItem()))

        val dcRequestString = mdocCalcDcRequestString(
            documentTypeRepo,
            requestType,
            session.protocol,
            session.nonce.fromHex(),
            session.origin,
            session.encryptionKey,
            session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate,
            readerAuthKey,
            readerAuthKeyCertification
        )
        Logger.i(TAG, "dcRequestString: $dcRequestString")
        val json = Json { ignoreUnknownKeys = true }
        val responseString = json.encodeToString(DCBeginResponse(session.id, dcRequestString))
        resp.status = HttpServletResponse.SC_OK
        resp.outputStream.write(responseString.encodeToByteArray())
        resp.contentType = "application/json"
    }

    private fun handleDcGetData(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<DCGetDataRequest>(requestString)

        val encodedSession = runBlocking {
            storage.get(
                STORAGE_TABLE_NAME,
                "",
                request.sessionId
            )
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId ${request.sessionId}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        Logger.i(TAG, "Data received from WC3 DC API: ${request.credentialResponse}")

        try {
            when (session.protocol) {
                Protocol.W3C_DC_PREVIEW ->handleDcGetDataPreview(session, request.credentialResponse)
                Protocol.W3C_DC_ARF -> handleDcGetDataArf(session, request.credentialResponse)
                else -> throw IllegalArgumentException("unsupported protocol ${session.protocol}")
            }
        } catch (e: Throwable) {
            Logger.e(TAG, "$remoteHost: failed with", e)
            e.printStackTrace()
            resp.status = HttpServletResponse.SC_BAD_REQUEST
        }

        try {
            handleGetDataMdoc(session, resp)
        } catch (e: Throwable) {
            Logger.e(TAG, "$remoteHost: Error validating DeviceResponse", e)
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }

        resp.contentType = "application/json"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleDcGetDataPreview(
        session: Session,
        credentialResponse: String
    ) {
        val tokenBase64 = Json.decodeFromString<DCPreviewResponse>(credentialResponse).token

        val (cipherText, encapsulatedPublicKey) = parseCredentialDocument(tokenBase64.fromBase64Url())
        val uncompressed = (session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate).asUncompressedPointEncoding
        session.sessionTranscript = generateBrowserSessionTranscript(
            session.nonce.fromHex(),
            session.origin,
            Crypto.digest(Algorithm.SHA256, uncompressed)
        )
        session.deviceResponse = Crypto.hpkeDecrypt(
            Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
            session.encryptionKey,
            cipherText,
            session.sessionTranscript!!,
            encapsulatedPublicKey)
    }

    private fun handleDcGetDataArf(
        session: Session,
        credentialResponse: String
    ) {
        val encryptedResponseBase64 = Json.decodeFromString<DCArfResponse>(credentialResponse).encryptedResponse

        val array = Cbor.decode(encryptedResponseBase64.fromBase64Url()).asArray
        if (array.get(0).asTstr != "ARFencryptionv2") {
            throw IllegalArgumentException("Excepted ARFencryptionv2 as first array element")
        }
        val encryptionParameters = array.get(1).asMap
        val encapsulatedPublicKey = encryptionParameters[Tstr("pkEm")]!!.asCoseKey.ecPublicKey
        val cipherText = encryptionParameters[Tstr("cipherText")]!!.asBstr

        val arfEncryptionInfo = CborMap.builder()
            .put("nonce", session.nonce.fromHex())
            .put("readerPublicKey", session.encryptionKey.publicKey.toCoseKey().toDataItem())
            .end()
            .build()
        val encryptionInfo = CborArray.builder()
            .add("ARFEncryptionv2")
            .add(arfEncryptionInfo)
            .end()
            .build()
        val base64EncryptionInfo = Cbor.encode(encryptionInfo).toBase64Url()

        session.sessionTranscript =
            Cbor.encode(
                CborArray.builder()
                    .add(Simple.NULL) // DeviceEngagementBytes
                    .add(Simple.NULL) // EReaderKeyBytes
                    .addArray() // BrowserHandover
                    .add("ARFHandoverv2")
                    .add(base64EncryptionInfo)
                    .add(session.origin)
                    .end()
                    .end()
                    .build()
            )

        session.deviceResponse = Crypto.hpkeDecrypt(
            Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
            session.encryptionKey,
            cipherText,
            session.sessionTranscript!!,
            encapsulatedPublicKey)

        Logger.iCbor(TAG, "decrypted DeviceResponse", session.deviceResponse!!)
        Logger.iCbor(TAG, "SessionTranscript", session.sessionTranscript!!)
    }

    private fun handleOpenID4VPBegin(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<OpenID4VPBeginRequest>(requestString)

        val protocol = when (request.protocol) {
            // Keep in sync with verifier.html
            "w3c_dc_preview" -> Protocol.W3C_DC_PREVIEW
            "w3c_dc_arf" -> Protocol.W3C_DC_ARF
            "openid4vp_plain" -> Protocol.PLAIN_OPENID4VP
            "openid4vp_eudi" -> Protocol.EUDI_OPENID4VP
            "openid4vp_mdoc" -> Protocol.MDOC_OPENID4VP
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown protocol '$request.protocol'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }

        val requestType = when (request.requestType) {
            // Keep in sync with verifier.html
            "pid_mdoc_age_over_18" -> RequestType.PID_MDOC_AGE_OVER_18
            "pid_mdoc_mandatory" -> RequestType.PID_MDOC_MANDATORY
            "pid_mdoc_full" -> RequestType.PID_MDOC_FULL
            "pid_sdjwt_age_over_18" -> RequestType.PID_SDJWT_AGE_OVER_18
            "pid_sdjwt_mandatory" -> RequestType.PID_SDJWT_MANDATORY
            "pid_sdjwt_full" -> RequestType.PID_SDJWT_FULL
            "mdl_mdoc_age_over_18" -> RequestType.MDL_MDOC_AGE_OVER_18
            "mdl_mdoc_age_over_21" -> RequestType.MDL_MDOC_AGE_OVER_21
            "mdl_mdoc_age_over_21_and_portrait" -> RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT
            "mdl_mdoc_mandatory" -> RequestType.MDL_MDOC_MANDATORY
            "mdl_mdoc_full" -> RequestType.MDL_MDOC_FULL
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown request type '${request.requestType}'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }

        // Create a new session
        val session = Session(
            id = Random.Default.nextBytes(16).toHex(),
            nonce = Random.Default.nextBytes(16).toHex(),
            origin = request.origin,
            encryptionKey = Crypto.createEcPrivateKey(EcCurve.P256),
            requestType = requestType,
            protocol = protocol
        )
        runBlocking {
            storage.insert(
                STORAGE_TABLE_NAME,
                "",
                ByteString(session.toCbor()),
                session.id
            )
        }

        val uriScheme = when (session.protocol) {
            Protocol.PLAIN_OPENID4VP -> "openid4vp://"
            Protocol.EUDI_OPENID4VP -> "eudi-openid4vp://"
            Protocol.MDOC_OPENID4VP -> "mdoc-openid4vp://"
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown protocol '${session.protocol}'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }
        val requestUri = baseUrl + "/verifier/openid4vpRequest?sessionId=${session.id}"
        val uri = uriScheme +
                "?client_id=" + URLEncoder.encode(clientId, Charsets.UTF_8) +
                "&request_uri=" + URLEncoder.encode(requestUri, Charsets.UTF_8)

        val json = Json { ignoreUnknownKeys = true }
        val responseString = json.encodeToString(OpenID4VPBeginResponse(uri))
        resp.status = HttpServletResponse.SC_OK
        resp.outputStream.write(responseString.encodeToByteArray())
        resp.contentType = "application/json"
        Logger.i(TAG, "Sending handleOpenID4VPBegin response: $responseString")
    }

    private fun handleOpenID4VPRequest(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
    ) {
        val sessionId = req.getParameter("sessionId")
        if (sessionId == null) {
            Logger.e(TAG, "$remoteHost: No session parameter ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val encodedSession = runBlocking {
            storage.get(
                STORAGE_TABLE_NAME,
                "",
                sessionId
            )
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId $sessionId")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        val responseUri = baseUrl + "/verifier/openid4vpResponse?sessionId=${session.id}"

        val (singleUseReaderKeyPriv, singleUseReaderKeyCertChain) = createSingleUseReaderKey()

        val readerPub = singleUseReaderKeyPriv.publicKey.javaPublicKey as ECPublicKey
        val readerPriv = singleUseReaderKeyPriv.javaPrivateKey as ECPrivateKey
        val readerKey = ECKey(
            Curve.P_256,
            readerPub,
            readerPriv,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        )

        val readerX5c = singleUseReaderKeyCertChain.certificates.map { cert ->
            Base64.from(cert.encodedCertificate.toBase64Url())
        }

        val presentationDefinition = when (session.requestType) {
            RequestType.PID_MDOC_AGE_OVER_18,
            RequestType.PID_MDOC_MANDATORY,
            RequestType.PID_MDOC_FULL,
            RequestType.MDL_MDOC_AGE_OVER_18,
            RequestType.MDL_MDOC_AGE_OVER_21,
            RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT,
            RequestType.MDL_MDOC_MANDATORY,
            RequestType.MDL_MDOC_FULL -> {
                mdocCalcPresentationDefinition(documentTypeRepo, session.requestType)
            }
            RequestType.PID_SDJWT_AGE_OVER_18,
            RequestType.PID_SDJWT_MANDATORY,
            RequestType.PID_SDJWT_FULL -> {
                sdjwtCalcPresentationDefinition(documentTypeRepo, session.requestType)
            }
        }

        val claimsSet = JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim("response_uri", responseUri)
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post.jwt")
            .claim("nonce", session.nonce)
            .claim("state", session.id)
            .claim("presentation_definition", presentationDefinition)
            .claim("client_metadata", calcClientMetadata(session, session.requestType.format))
            .build()
        Logger.i(TAG, "Sending OpenID4VPRequest claims set: $claimsSet")

        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(readerKey.getKeyID())
                .x509CertChain(readerX5c)
                .type(JOSEObjectType("oauth-authz-req+jwt"))
                .build(),
            claimsSet
        )

        val signer: JWSSigner = ECDSASigner(readerKey)
        signedJWT.sign(signer)

        val s = signedJWT.serialize()
        resp.contentType = "application/oauth-authz-req+jwt"
        resp.outputStream.write(s.encodeToByteArray())
        resp.status = HttpServletResponse.SC_OK

        // We'll need responseUri later (to calculate sessionTranscript)
        session.responseUri = responseUri
        runBlocking {
            storage.update(
                STORAGE_TABLE_NAME,
                "",
                sessionId,
                ByteString(session.toCbor())
            )
        }

    }

    private fun handleGetReaderRootCert(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
    ) {
        val readerCertPem = keyMaterial.readerRootKeyCertificates.certificates[0].toPem()
        resp.outputStream.write(readerCertPem.encodeToByteArray())
        resp.contentType = "text/plain"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleOpenID4VPResponse(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val sessionId = req.getParameter("sessionId")
        if (sessionId == null) {
            Logger.e(TAG, "$remoteHost: No session parameter ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val encodedSession = runBlocking {
            storage.get(
                STORAGE_TABLE_NAME,
                "",
                sessionId
            )
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId $sessionId")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        val responseString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        try {
            val kvPairs = mutableMapOf<String, String>()
            for (part in responseString.split("&")) {
                val parts = part.split("=", limit = 2)
                kvPairs[parts[0]] = parts[1]
            }

            val response = kvPairs["response"]
            val encryptedJWT = EncryptedJWT.parse(response)

            val encPub = session.encryptionKey.publicKey.javaPublicKey as ECPublicKey
            val encPriv = session.encryptionKey.javaPrivateKey as ECPrivateKey
            val encKey = ECKey(
                Curve.P_256,
                encPub,
                encPriv,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )

            val decrypter = ECDHDecrypter(encKey)
            encryptedJWT.decrypt(decrypter)

            val vpToken = encryptedJWT.jwtClaimsSet.getClaim("vp_token") as String
            session.deviceResponse = vpToken.fromBase64Url()
            session.sessionTranscript = createSessionTranscriptOpenID4VP(
                clientId = clientId,
                responseUri = session.responseUri!!,
                authorizationRequestNonce = encryptedJWT.header.agreementPartyVInfo.toString(),
                mdocGeneratedNonce = encryptedJWT.header.agreementPartyUInfo.toString()
            )

            // Save `deviceResponse` and `sessionTranscript`, for later
            runBlocking {
                storage.update(
                    STORAGE_TABLE_NAME,
                    "",
                    sessionId,
                    ByteString(session.toCbor())
                )
            }

        } catch (e: Throwable) {
            Logger.w(TAG, "$remoteHost: handleResponse: Error getting response", e)
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }

        val redirectUri = baseUrl + "/verifier_redirect.html?sessionId=${session.id}"
        val json = Json { ignoreUnknownKeys = true }
        resp.outputStream.write(
            json.encodeToString(OpenID4VPRedirectUriResponse(redirectUri))
                .encodeToByteArray()
        )
        resp.contentType = "application/json"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleOpenID4VPGetData(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<OpenID4VPGetData>(requestString)

        val encodedSession = runBlocking {
            storage.get(
                STORAGE_TABLE_NAME,
                "",
                request.sessionId
            )
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId ${request.sessionId}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        try {
            when (session.requestType) {
                RequestType.PID_MDOC_AGE_OVER_18,
                RequestType.PID_MDOC_MANDATORY,
                RequestType.PID_MDOC_FULL,
                RequestType.MDL_MDOC_AGE_OVER_18,
                RequestType.MDL_MDOC_AGE_OVER_21,
                RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT,
                RequestType.MDL_MDOC_MANDATORY,
                RequestType.MDL_MDOC_FULL -> {
                    handleGetDataMdoc(session, resp)
                }
                RequestType.PID_SDJWT_AGE_OVER_18,
                RequestType.PID_SDJWT_MANDATORY,
                RequestType.PID_SDJWT_FULL -> {
                    handleGetDataSdJwt(session, resp)
                }
            }
        } catch (e: Throwable) {
            Logger.e(TAG, "$remoteHost: Error validating DeviceResponse", e)
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }

        resp.contentType = "application/json"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleGetDataMdoc(
        session: Session,
        resp: HttpServletResponse
    ) {
        val parser = DeviceResponseParser(session.deviceResponse!!, session.sessionTranscript!!)
        val deviceResponse = parser.parse()
        Logger.i(TAG, "Validated DeviceResponse!")

        // TODO: Add more sophistication in how we convey the result to the webpage, for example
        //  support the following value types
        //  - textual string
        //  - images
        //  - etc/
        //
        // TODO: Also check whether IssuerSigned and DeviceSigned validates and whether we trust
        //  the IACA certificate. Also include a check/fail for every data element to convey if
        //  the IssuerSignedItem digest matches the expected value.
        //
        val lines = mutableListOf<OpenID4VPResultLine>()
        for (document in deviceResponse.documents) {
            lines.add(OpenID4VPResultLine("DocType", document.docType))
            for (namespaceName in document.issuerNamespaces) {
                lines.add(OpenID4VPResultLine("NameSpace", namespaceName))
                for (dataElementName in document.getIssuerEntryNames(namespaceName)) {
                    val value = document.getIssuerEntryData(namespaceName, dataElementName)
                    val dataItem = Cbor.decode(value)
                    val renderedValue = Cbor.toDiagnostics(
                        dataItem,
                        setOf(
                            DiagnosticOption.PRETTY_PRINT,
                            DiagnosticOption.BSTR_PRINT_LENGTH
                        )
                    )
                    lines.add(OpenID4VPResultLine(dataElementName, renderedValue))
                }
            }
        }

        val json = Json { ignoreUnknownKeys = true }
        resp.outputStream.write(json.encodeToString(OpenID4VPResultData(lines)).encodeToByteArray())
    }

    private fun handleGetDataSdJwt(
        session: Session,
        resp: HttpServletResponse,
    ) {
        val presentationString = session.deviceResponse!!.decodeToString()
        Logger.d(TAG, "Handling SD-JWT: $presentationString")
        val presentation = SdJwtVerifiablePresentation.fromString(presentationString)
        val nonceStr = session.nonce

        // on the verifier, check that the key binding can be verified with the
        // key mentioned in the SD-JWT:
        presentation.verifyKeyBinding(
            checkAudience = { clientId == it },
            checkNonce = { nonceStr == it },
            checkCreationTime = { true /* TODO: sometimes flaky it < Clock.System.now() */ }
        )

        // also on the verifier, check the signature over the SD-JWT from the issuer
        // TODO: We need to verify the issuer signature. Where do we get the public
        // key of the issuer?
        //presentation.sdJwtVc.verifyIssuerSignature(issuerCert.ecPublicKey)

        val lines = mutableListOf<OpenID4VPResultLine>()
        for (disclosure in presentation.sdJwtVc.disclosures.sortedBy { it.key }) {
            val valueToAdd = when (disclosure.value) {
                is JsonPrimitive -> disclosure.value.jsonPrimitive.content
                is JsonArray -> disclosure.value.jsonArray.toString()
                else -> "Unknown Response Type: ${disclosure.value}"
            }
            lines.add(OpenID4VPResultLine(disclosure.key, valueToAdd))
        }

        // Check for the actual claims we requested, in addition to what was supplied
        // in the response.
        val disclosedClaims = presentation.sdJwtVc.disclosures.map { it.key }.toMutableSet()
        // There are several special cases that aren't in the selective disclosures, which our
        // JwtBody implementation copies into its properties:
        val jwtBody = JwtBody.fromString(presentation.sdJwtVc.body)
        val specialCases: Map<String, String?> = mapOf(
            Pair("iss", jwtBody.issuer),
            Pair("vct", jwtBody.docType),
            Pair("iat", jwtBody.timeSigned?.toString()),
            Pair("nbf", jwtBody.timeValidityBegin?.toString()),
            Pair("exp", jwtBody.timeValidityEnd?.toString()),
            Pair("cnf", jwtBody.publicKey?.asJwk.toString())
        )
        for (key in specialCases.keys) {
            val value = specialCases[key] ?: continue
            lines.add(OpenID4VPResultLine(key, value))
            disclosedClaims.add(key)
            Logger.i(TAG, "Adding special case $key: $value")
        }

        val json = Json { ignoreUnknownKeys = true }
        resp.outputStream.write(json.encodeToString(OpenID4VPResultData(lines)).encodeToByteArray())
    }
}

// defined in ISO 18013-7 Annex B
private fun createSessionTranscriptOpenID4VP(
    clientId: String,
    responseUri: String,
    authorizationRequestNonce: String,
    mdocGeneratedNonce: String
): ByteArray {
    val clientIdToHash = Cbor.encode(CborArray.builder()
        .add(clientId)
        .add(mdocGeneratedNonce)
        .end()
        .build())
    val clientIdHash = Crypto.digest(Algorithm.SHA256, clientIdToHash)

    val responseUriToHash = Cbor.encode(CborArray.builder()
        .add(responseUri)
        .add(mdocGeneratedNonce)
        .end()
        .build())
    val responseUriHash = Crypto.digest(Algorithm.SHA256, responseUriToHash)

    val oid4vpHandover = CborArray.builder()
        .add(clientIdHash)
        .add(responseUriHash)
        .add(authorizationRequestNonce)
        .end()
        .build()

    return Cbor.encode(
        CborArray.builder()
            .add(Simple.NULL)
            .add(Simple.NULL)
            .add(oid4vpHandover)
            .end()
            .build()
    )
}

private fun mdocCalcDcRequestString(
    documentTypeRepository: DocumentTypeRepository,
    requestType: RequestType,
    protocol: Protocol,
    nonce: ByteArray,
    origin: String,
    readerKey: EcPrivateKey,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain
): String {
    when (protocol) {
        Protocol.W3C_DC_PREVIEW -> {
            return mdocCalcDcRequestStringPreview(
                documentTypeRepository,
                requestType,
                nonce,
                origin,
                readerPublicKey
            )
        }
        Protocol.W3C_DC_ARF -> {
            return mdocCalcDcRequestStringArf(
                documentTypeRepository,
                requestType,
                nonce,
                origin,
                readerKey,
                readerPublicKey,
                readerAuthKey,
                readerAuthKeyCertification
            )
        }
        else -> {
            throw IllegalStateException("Unsupported protocol $protocol")
        }
    }
}

private fun mdocCalcDcRequestStringPreview(
        documentTypeRepository: DocumentTypeRepository,
        requestType: RequestType,
        nonce: ByteArray,
        origin: String,
        readerPublicKey: EcPublicKeyDoubleCoordinate
    ): String {

    val pid = documentTypeRepository.getDocumentTypeForMdoc(EUPersonalID.EUPID_DOCTYPE)
    val mdl = documentTypeRepository.getDocumentTypeForMdoc(DrivingLicense.MDL_DOCTYPE)
    val request = when (requestType) {
        RequestType.PID_MDOC_AGE_OVER_18 -> pid?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.PID_MDOC_MANDATORY -> pid?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.PID_MDOC_FULL -> pid?.sampleRequests?.first { it.id == "full" }
        RequestType.MDL_MDOC_AGE_OVER_18 -> mdl?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.MDL_MDOC_AGE_OVER_21 -> mdl?.sampleRequests?.first { it.id == "age_over_21" }
        RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT -> mdl?.sampleRequests?.first { it.id == "age_over_21_and_portrait" }
        RequestType.MDL_MDOC_MANDATORY -> mdl?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.MDL_MDOC_FULL -> mdl?.sampleRequests?.first { it.id == "full" }
        else -> null
    }
    if (request == null) {
        throw IllegalStateException("Unknown request type $requestType")
    }

    val top = JSONObject()

    val selector = JSONObject()
    val format = JSONArray()
    format.add("mdoc")
    selector.put("format", format)
    top.put("selector", selector)

    selector.put("doctype", request.mdocRequest!!.docType)

    val fields = JSONArray()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for (de in ns.dataElementsToRequest) {
            val field = JSONObject()
            field.put("namespace", ns.namespace)
            field.put("name", de.attribute.identifier)
            field.put("intentToRetain", false)
            fields.add(field)
        }
    }
    selector.put("fields", fields)

    top.put("nonce", nonce.toBase64Url())
    top.put("readerPublicKey", readerPublicKey.asUncompressedPointEncoding.toBase64Url())

    return top.toString(JSONStyle.NO_COMPRESS)
}

private fun mdocCalcDcRequestStringArf(
    documentTypeRepository: DocumentTypeRepository,
    requestType: RequestType,
    nonce: ByteArray,
    origin: String,
    readerKey: EcPrivateKey,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain
): String {

    val pid = documentTypeRepository.getDocumentTypeForMdoc(EUPersonalID.EUPID_DOCTYPE)
    val mdl = documentTypeRepository.getDocumentTypeForMdoc(DrivingLicense.MDL_DOCTYPE)
    val request = when (requestType) {
        RequestType.PID_MDOC_AGE_OVER_18 -> pid?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.PID_MDOC_MANDATORY -> pid?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.PID_MDOC_FULL -> pid?.sampleRequests?.first { it.id == "full" }
        RequestType.MDL_MDOC_AGE_OVER_18 -> mdl?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.MDL_MDOC_AGE_OVER_21 -> mdl?.sampleRequests?.first { it.id == "age_over_21" }
        RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT -> mdl?.sampleRequests?.first { it.id == "age_over_21_and_portrait" }
        RequestType.MDL_MDOC_MANDATORY -> mdl?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.MDL_MDOC_FULL -> mdl?.sampleRequests?.first { it.id == "full" }
        else -> null
    }
    if (request == null) {
        throw IllegalStateException("Unknown request type $requestType")
    }

    val arfEncryptionInfo = CborMap.builder()
        .put("nonce", nonce)
        .put("readerPublicKey", readerPublicKey.toCoseKey().toDataItem())
        .end()
        .build()
    val encryptionInfo = CborArray.builder()
        .add("ARFEncryptionv2")
        .add(arfEncryptionInfo)
        .end()
        .build()
    val base64EncryptionInfo = Cbor.encode(encryptionInfo).toBase64Url()

    val sessionTranscript = Cbor.encode(
        CborArray.builder()
            .add(Simple.NULL) // DeviceEngagementBytes
            .add(Simple.NULL) // EReaderKeyBytes
            .addArray() // BrowserHandover
            .add("ARFHandoverv2")
            .add(base64EncryptionInfo)
            .add(origin)
            .end()
            .end()
            .build()
    )

    val itemsToRequest = mutableMapOf<String, MutableMap<String, Boolean>>()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for (de in ns.dataElementsToRequest) {
            itemsToRequest.getOrPut(ns.namespace) { mutableMapOf() }
                .put(de.attribute.identifier, false)
        }
    }
    val generator = DeviceRequestGenerator(sessionTranscript)
    generator.addDocumentRequest(
        docType = request.mdocRequest!!.docType,
        itemsToRequest = itemsToRequest,
        requestInfo = null,
        readerKey = readerAuthKey,
        signatureAlgorithm = Algorithm.ES256,
        readerKeyCertificateChain = readerAuthKeyCertification,
    )
    val deviceRequest = generator.generate()
    val base64DeviceRequest = deviceRequest.toBase64Url()

    val top = JSONObject()
    top.put("deviceRequest", base64DeviceRequest)
    top.put("encryptionInfo", base64EncryptionInfo)
    return top.toString(JSONStyle.NO_COMPRESS)
}

private fun mdocCalcPresentationDefinition(
    documentTypeRepository: DocumentTypeRepository,
    requestType: RequestType
): JSONObject {
    val pid = documentTypeRepository.getDocumentTypeForMdoc(EUPersonalID.EUPID_DOCTYPE)
    val mdl = documentTypeRepository.getDocumentTypeForMdoc(DrivingLicense.MDL_DOCTYPE)
    val request = when (requestType) {
        RequestType.PID_MDOC_AGE_OVER_18 -> pid?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.PID_MDOC_MANDATORY -> pid?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.PID_MDOC_FULL -> pid?.sampleRequests?.first { it.id == "full" }
        RequestType.MDL_MDOC_AGE_OVER_18 -> mdl?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.MDL_MDOC_AGE_OVER_21 -> mdl?.sampleRequests?.first { it.id == "age_over_21" }
        RequestType.MDL_MDOC_AGE_OVER_21_AND_PORTRAIT -> mdl?.sampleRequests?.first { it.id == "age_over_21_and_portrait" }
        RequestType.MDL_MDOC_MANDATORY -> mdl?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.MDL_MDOC_FULL -> mdl?.sampleRequests?.first { it.id == "full" }
        else -> null
    }
    if (request == null) {
        throw IllegalStateException("Unknown request type $requestType")
    }

    val alg = JSONArray()
    alg.addAll(listOf("ES256"))
    val mso_mdoc = JSONObject()
    mso_mdoc.put("alg", alg)
    val format = JSONObject()
    format.put("mso_mdoc", mso_mdoc)

    val fields = JSONArray()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for (de in ns.dataElementsToRequest) {
            var array = JSONArray()
            array.add("\$['${ns.namespace}']['${de.attribute.identifier}']")
            val field = JSONObject()
            field.put("path", array)
            field.put("intent_to_retain", false)
            fields.add(field)
        }
    }
    val constraints = JSONObject()
    constraints.put("limit_disclosure", "required")
    constraints.put("fields", fields)

    val input_descriptor_0 = JSONObject()
    input_descriptor_0.put("id", request.mdocRequest!!.docType)
    input_descriptor_0.put("format", format)
    input_descriptor_0.put("constraints", constraints)
    val input_descriptors = JSONArray()
    input_descriptors.add(input_descriptor_0)

    val presentation_definition = JSONObject()
    // TODO: Fill in a unique ID.
    presentation_definition.put("id", "request-TODO-id")
    presentation_definition.put("input_descriptors", input_descriptors)

    return presentation_definition
}

private fun sdjwtCalcPresentationDefinition(
    documentTypeRepository: DocumentTypeRepository,
    requestType: RequestType
): JSONObject {
    val pid = documentTypeRepository.getDocumentTypeForMdoc(EUPersonalID.EUPID_DOCTYPE)
    val request = when (requestType) {
        RequestType.PID_SDJWT_AGE_OVER_18 -> pid?.sampleRequests?.first { it.id == "age_over_18" }
        RequestType.PID_SDJWT_MANDATORY -> pid?.sampleRequests?.first { it.id == "mandatory" }
        RequestType.PID_SDJWT_FULL -> pid?.sampleRequests?.first { it.id == "full" }
        else -> null
    }
    if (request == null) {
        throw IllegalStateException("Unknown request type $requestType")
    }

    val alg = JSONArray()
    alg.addAll(listOf("ES256"))
    val algContainer = JSONObject()
    algContainer.put("alg", alg)
    val format = JSONObject()
    format.put("jwt_vc", algContainer)

    val fields = JSONArray()
    for (claim in request.vcRequest!!.claimsToRequest) {
        var array = JSONArray()
        array.add("\$.${claim.identifier}")
        val field = JSONObject()
        field.put("path", array)
        fields.add(field)
    }
    val constraints = JSONObject()
    constraints.put("limit_disclosure", "required")
    constraints.put("fields", fields)

    val input_descriptor_0 = JSONObject()
    input_descriptor_0.put("id", "Example PID")
    input_descriptor_0.put("format", format)
    input_descriptor_0.put("constraints", constraints)
    val input_descriptors = JSONArray()
    input_descriptors.add(input_descriptor_0)

    val presentation_definition = JSONObject()
    // TODO: Fill in a unique ID.
    presentation_definition.put("id", "request-TODO-id")
    presentation_definition.put("input_descriptors", input_descriptors)

    return presentation_definition
}

private fun calcClientMetadata(session: Session, format: DocumentFormat): JSONObject {
    val encPub = session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate

    val client_metadata = JSONObject()
    client_metadata.put("authorization_encrypted_response_alg", "ECDH-ES")
    client_metadata.put("authorization_encrypted_response_enc", "A128CBC-HS256")
    client_metadata.put("response_mode", "direct_post.jwt")

    val vpFormats = when (format) {
        DocumentFormat.SDJWT -> {
            val vpFormats = JSONObject()
            val algList = JSONArray()
            algList.addAll(listOf("ES256"))
            val algObj = JSONObject()
            algObj.put("alg", algList)
            vpFormats.put("jwt_vc", algObj)
            vpFormats
        }
        DocumentFormat.MDOC -> {
            val vpFormats = JSONObject()
            val algList = JSONArray()
            algList.addAll(listOf("ES256"))
            val algObj = JSONObject()
            algObj.put("alg", algList)
            vpFormats.put("mso_mdoc", algObj)
            vpFormats
        }
    }
    client_metadata.put("vp_formats", vpFormats)
    client_metadata.put("vp_formats_supported", vpFormats)

    val key = JSONObject()
    key.put("kty", "EC")
    key.put("use", "enc")
    key.put("crv", "P-256")
    key.put("alg", "ECDH-ES")
    key.put("x", encPub.x.toBase64Url())
    key.put("y", encPub.y.toBase64Url())

    val keys = JSONArray()
    keys.add(key)

    client_metadata.put("jwks", keys)

    return client_metadata
}

private const val BROWSER_HANDOVER_V1 = "BrowserHandoverv1"
private const val ANDROID_CREDENTIAL_DOCUMENT_VERSION = "ANDROID-HPKE-v1"

private fun parseCredentialDocument(encodedCredentialDocument: ByteArray
): Pair<ByteArray, EcPublicKey> {
    val map = Cbor.decode(encodedCredentialDocument)
    val version = map["version"].asTstr
    if (!version.equals(ANDROID_CREDENTIAL_DOCUMENT_VERSION)) {
        throw IllegalArgumentException("Unexpected version $version")
    }
    val encryptionParameters = map["encryptionParameters"]
    val pkEm = encryptionParameters["pkEm"].asBstr
    val encapsulatedPublicKey =
        EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(EcCurve.P256, pkEm)
    val cipherText = map["cipherText"].asBstr
    return Pair(cipherText, encapsulatedPublicKey)
}

//    SessionTranscript = [
//      null, // DeviceEngagementBytes not available
//      null, // EReaderKeyBytes not available
//      AndroidHandover // defined below
//    ]
//
//    From https://github.com/WICG/mobile-document-request-api
//
//    BrowserHandover = [
//      "BrowserHandoverv1",
//      nonce,
//      OriginInfoBytes, // origin of the request as defined in ISO/IEC 18013-7
//      RequesterIdentity, // ? (omitting)
//      pkRHash
//    ]
private fun generateBrowserSessionTranscript(
    nonce: ByteArray,
    origin: String,
    requesterIdHash: ByteArray
): ByteArray {
    // TODO: Instead of hand-rolling this, we should use OriginInfoDomain which
    //   uses `domain` instead of `baseUrl` which is what the latest version of 18013-7
    //   calls for.
    val originInfoBytes = Cbor.encode(
        CborMap.builder()
            .put("cat", 1)
            .put("type", 1)
            .putMap("details")
            .put("baseUrl", origin)
            .end()
            .end()
            .build()
    )
    return Cbor.encode(
        CborArray.builder()
            .add(Simple.NULL) // DeviceEngagementBytes
            .add(Simple.NULL) // EReaderKeyBytes
            .addArray() // BrowserHandover
            .add(BROWSER_HANDOVER_V1)
            .add(nonce)
            .add(originInfoBytes)
            .add(requesterIdHash)
            .end()
            .end()
            .build()
    )
}
