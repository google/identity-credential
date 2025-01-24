package com.android.identity.server.openid4vci

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.time.Duration.Companion.seconds

/**
 * PAR stands for Pushed Authorization Request, which is the first request to be sent to our
 * OpenID4VCI server. In theory, other, simpler (and less secure) forms of client authorization are
 * possible, but Pushed Authorization Request is required in our implementation.
 *
 * The purpose of this request is for the Wallet App (or Wallet Server serving as a proxy)
 * to establish authorization session on the issuance server. This session is then referenced when
 * performing browser-based proofing/authorization, using requestUri issued in the response from
 * this request. Once web-based authorization is complete, Wallet App re-establishes control over
 * the session in [TokenServlet] by (1) proving that hash of code_verifier matches
 * code_challenge supplied to this service, (2) using DPoP authorization using the key
 * supplied in client_assertion to this service.
 *
 * One of the parameters of this servlet is redirect_uri. When the URL supplied using this
 * parameter is resolved, it signals the end of the web-based user authorization session.
 */
class ParServlet : BaseServlet() {
    companion object {
        const val ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
    }

    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val id = runBlocking {
            createSession(environment, req)
        }

        // Format the result (session identifying information).
        val expirationSeconds = 600
        val code = idToCode(OpaqueIdType.PAR_CODE, id, expirationSeconds.seconds)
        resp.status = 201  // Created
        resp.outputStream.write(
            Json.encodeToString(
                ParResponse.serializer(),
                ParResponse(
                    requestUri = "urn:ietf:params:oauth:request_uri:$code",
                    expiresIn = expirationSeconds
                )
            ).toByteArray())
    }
}
