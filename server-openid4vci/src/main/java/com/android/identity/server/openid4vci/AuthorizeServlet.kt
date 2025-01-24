package com.android.identity.server.openid4vci

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.Simple
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.document.NameSpacedData
import com.android.identity.flow.handler.InvalidRequestException
import com.android.identity.flow.server.Resources
import com.android.identity.flow.server.getTable
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.util.fromBase64Url
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import kotlin.time.Duration.Companion.minutes

/**
 * Initialize authorization workflow of some sort, based on `request_uri` parameter.
 *
 * When `request_uri` starts with `urn:ietf:params:oauth:request_uri:` run web-based authorization.
 * In this case the request is typically sent from the browser. Specifics of how the web
 * authorization session is run actually do not matter much for the Wallet App and Wallet Server,
 * as long as the session results in redirecting (or resolving) `redirect_uri` supplied
 * to [ParServlet] on the previous step.
 */
class AuthorizeServlet : BaseServlet() {
    companion object {
        const val RESOURCE_BASE = "openid4vci"

        const val OAUTH_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"
        const val OPENID4VP_REQUEST_URI_PREFIX = "https://rp.example.com/oidc/request/"
    }

    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val requestUri = req.getParameter("request_uri") ?: ""
        if (requestUri.startsWith(OAUTH_REQUEST_URI_PREFIX)) {
            // Create a simple web page for the user to authorize the credential issuance.
            getHtml(requestUri.substring(OAUTH_REQUEST_URI_PREFIX.length), resp)
        } else if (requestUri.startsWith(OPENID4VP_REQUEST_URI_PREFIX)) {
            // Request a presentation using openid4vp
            getOpenid4Vp(requestUri.substring(OPENID4VP_REQUEST_URI_PREFIX.length), resp)
        } else {
            throw InvalidRequestException("Invalid or missing 'request_uri' parameter")
        }
    }

    private fun getHtml(code: String, resp: HttpServletResponse) {
        val resources = environment.getInterface(Resources::class)!!
        val id = codeToId(OpaqueIdType.PAR_CODE, code)
        val authorizationCode = idToCode(OpaqueIdType.AUTHORIZATION_STATE, id, 20.minutes)
        val pidReadingCode = idToCode(OpaqueIdType.PID_READING, id, 20.minutes)
        val authorizeHtml = resources.getStringResource("$RESOURCE_BASE/authorize.html")!!
        resp.contentType = "text/html"
        resp.writer.print(
            authorizeHtml
                .replace("\$authorizationCode", authorizationCode)
                .replace("\$pidReadingCode", pidReadingCode)
        )
    }

    private fun getOpenid4Vp(code: String, resp: HttpServletResponse) {
        val id = codeToId(OpaqueIdType.OPENID4VP_CODE, code)
        val stateRef = idToCode(OpaqueIdType.OPENID4VP_STATE, id, 5.minutes)
        val responseUri = "$baseUrl/openid4vp-response"
        val jwt = runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            val state = IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
            val session = initiateOpenid4Vp(state.clientId, responseUri, stateRef)
            state.pidReadingKey = session.privateKey
            state.pidNonce = session.nonce
            storage.update(key = id, data = ByteString(state.toCbor()))
            session.jwt
        }
        resp.contentType = "application/oauth-authz-req+jwt"
        resp.writer.write(jwt)
    }

    /**
     * Handle user's authorization and redirect to [FinishAuthorizationServlet].
     */
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val code = req.getParameter("authorizationCode")
        val pidData = req.getParameter("pidData")
        val id = codeToId(OpaqueIdType.AUTHORIZATION_STATE, code)
        val baseUri = URI(this.baseUrl)

        val tokenData = Json.parseToJsonElement(pidData).jsonObject["token"]!!
            .jsonPrimitive.content.fromBase64Url()

        val (cipherText, encapsulatedPublicKey) = parseCredentialDocument(tokenData)

        runBlocking {
            val origin = baseUri.scheme + "://" + baseUri.authority
            val storage = environment.getTable(IssuanceState.tableSpec)
            val state = IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
            val encodedKey = (state.pidReadingKey!!.publicKey as EcPublicKeyDoubleCoordinate).asUncompressedPointEncoding
            val sessionTranscript = generateBrowserSessionTranscript(
                Crypto.digest(Algorithm.SHA256, id.toByteArray()),
                origin,
                Crypto.digest(Algorithm.SHA256, encodedKey)
            )
            val deviceResponseRaw = Crypto.hpkeDecrypt(
                Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
                state.pidReadingKey!!,
                cipherText,
                sessionTranscript,
                encapsulatedPublicKey)
            val parser = DeviceResponseParser(deviceResponseRaw, sessionTranscript)
            val deviceResponse = parser.parse()
            val data = NameSpacedData.Builder()
            for (document in deviceResponse.documents) {
                for (namespaceName in document.issuerNamespaces) {
                    for (dataElementName in document.getIssuerEntryNames(namespaceName)) {
                        val value = document.getIssuerEntryData(namespaceName, dataElementName)
                        data.putEntry(namespaceName, dataElementName, value)
                    }
                }
            }

            state.credentialData = data.build()
            storage.update(key = id, data = ByteString(state.toCbor()))
        }
        val issuerState = idToCode(OpaqueIdType.ISSUER_STATE, id, 5.minutes)
        resp.sendRedirect("finish_authorization?issuer_state=$issuerState")
    }
}

// Copied from VerifierServlet.kt as is
// TODO: this code should be removed here and in VerifierServlet.kt and the functionality
// factored into a reusable library.

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