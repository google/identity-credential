package com.android.identity.server.openid4vci

import com.android.identity.flow.server.getTable
import com.android.identity.util.toBase64Url
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URLEncoder
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class AuthorizeChallengeServlet : BaseServlet() {
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val authSession = req.getParameter("auth_session")
        val id = if (authSession == null) {
            // Initial call, authSession was not yet established
            runBlocking {
                createSession(environment, req)
            }
        } else {
            codeToId(OpaqueIdType.AUTH_SESSION, authSession)
        }
        val presentation = req.getParameter("presentation_during_issuance_session")
        val state = runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
        }
        if (authSession != null) {
            authorizeWithDpop(
                state.dpopKey,
                req,
                state.dpopNonce?.toByteArray()?.toBase64Url(),
                null
            )
        }
        if (presentation == null) {
            val expirationSeconds = 600
            val code = idToCode(OpaqueIdType.PAR_CODE, id, expirationSeconds.seconds)
            val openid4VpCode = idToCode(OpaqueIdType.OPENID4VP_CODE, id, 5.minutes)
            val requestUri = URLEncoder.encode(
                AuthorizeServlet.OPENID4VP_REQUEST_URI_PREFIX + openid4VpCode,
                "UTF-8"
            )
            resp.status = 400
            resp.writer.write(buildJsonObject {
                put("error", "insufficient_authorization")
                put("presentation", "$baseUrl/authorize?request_uri=$requestUri")
                put("auth_session", idToCode(OpaqueIdType.AUTH_SESSION, id, 5.minutes))
                put("request_uri", "urn:ietf:params:oauth:request_uri:$code")
                put("expires_in", expirationSeconds)

            }.toString())
        } else {
            if (codeToId(OpaqueIdType.OPENID4VP_PRESENTATION, presentation) != id) {
                throw IllegalStateException("Bad presentation code")
            }
            resp.writer.write(buildJsonObject {
                put("authorization_code", idToCode(OpaqueIdType.REDIRECT, id, 2.minutes))
            }.toString())
        }
    }
}