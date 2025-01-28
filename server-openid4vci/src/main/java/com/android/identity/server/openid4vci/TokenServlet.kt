package com.android.identity.server.openid4vci

import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.flow.handler.InvalidRequestException
import com.android.identity.flow.server.getTable
import com.android.identity.util.toBase64Url
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Takes control over authentication session after web-based user authentication. This is a
 * counterpart of the [ParServlet]. It checks that (1) hash of code_verifier supplied here matches
 * code_challenge supplied to [ParServlet], (2) performs DPoP authorization using the key
 * in client_assertion to [ParServlet]. Once all the checks are done it issues access token that
 * can be used to request a credential and possibly a refresh token that can be used to request
 * more access tokens.
 */
class TokenServlet : BaseServlet() {
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val digest: ByteString?
        val id = when (req.getParameter("grant_type")) {
            "authorization_code" -> {
                val code = req.getParameter("code")
                    ?: throw InvalidRequestException("'code' parameter missing")
                val codeVerifier = req.getParameter("code_verifier")
                    ?: throw InvalidRequestException("'code_verifier' parameter missing")
                digest = ByteString(Crypto.digest(Algorithm.SHA256, codeVerifier.toByteArray()))
                codeToId(OpaqueIdType.REDIRECT, code)
            }
            "refresh_token" -> {
                val refreshToken = req.getParameter("refresh_token")
                    ?: throw InvalidRequestException("'refresh_token' parameter missing")
                digest = null
                codeToId(OpaqueIdType.REFRESH_TOKEN, refreshToken)
            }
            else -> throw InvalidRequestException("invalid parameter 'grant_type'")

        }
        val state = runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
        }
        if (digest != null) {
            if (state.codeChallenge == digest) {
                state.codeChallenge = null  // challenge met
            } else {
                throw InvalidRequestException("authorization: bad code_verifier")
            }
        }
        authorizeWithDpop(state.dpopKey, req, state.dpopNonce?.toByteArray()?.toBase64Url(), null)
        val dpopNonce = Random.nextBytes(15)
        state.dpopNonce = ByteString(dpopNonce)
        resp.setHeader("DPoP-Nonce", dpopNonce.toBase64Url())
        val cNonce = Random.nextBytes(15)
        state.redirectUri = null
        state.cNonce = ByteString(cNonce)
        runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            storage.update(id, ByteString(state.toCbor()))
        }
        val expiresIn = 60.minutes
        val accessToken = idToCode(OpaqueIdType.ACCESS_TOKEN, id, expiresIn)
        val refreshToken = idToCode(OpaqueIdType.REFRESH_TOKEN, id, Duration.INFINITE)
        resp.contentType = "application/json"
        val accessTokenJson = Json.encodeToString(
            TokenResponse.serializer(), TokenResponse(
                accessToken = accessToken,
                refreshToken = refreshToken,
                cNonce = cNonce.toBase64Url(),
                expiresIn = expiresIn.inWholeSeconds.toInt(),
                cNonceExpiresIn = expiresIn.inWholeSeconds.toInt(),
                tokenType = "DPoP"
            )
        )
        resp.writer.write(accessTokenJson)
    }
}