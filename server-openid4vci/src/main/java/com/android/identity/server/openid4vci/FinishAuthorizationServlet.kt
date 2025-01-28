package com.android.identity.server.openid4vci

import com.android.identity.flow.handler.InvalidRequestException
import com.android.identity.flow.server.getTable
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlin.time.Duration.Companion.minutes

/**
 * Finish web-based authorization and hand off the session back to the Wallet App (or
 * Wallet Server).
 */
class FinishAuthorizationServlet : BaseServlet() {
    override val outputFormat: String
        get() = "text/html"

    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val issuerState = req.getParameter("issuer_state")
            ?: throw InvalidRequestException("missing parameter 'issuer_state'")
        val id = codeToId(OpaqueIdType.ISSUER_STATE, issuerState)
        runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            val state = IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
            val redirectUri = state.redirectUri ?: throw IllegalStateException("No redirect url")
            if (!redirectUri.startsWith("http://") && !redirectUri.startsWith("https://")) {
                resp.writer.write(
                    """
                            <!DOCTYPE html>
                            <html>
                            <head>
                            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                            </head>
                            <body>
                            <a href="$redirectUri?issuer_state=$issuerState">Continue</a>
                            </body>
                            </html>
                        """.trimIndent()
                )
            } else {
                val redirectUrl =
                    redirectUri + "?code=" + idToCode(OpaqueIdType.REDIRECT, id, 2.minutes)
                resp.sendRedirect(redirectUrl)
            }
        }
    }
}