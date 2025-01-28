package com.android.identity.issuance.funke

import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.issuance.IssuingAuthorityException
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyInfo
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.util.Logger
import com.android.identity.util.toBase64Url
import io.ktor.client.HttpClient
import io.ktor.client.request.headers
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.readBytes
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.random.Random

internal object FunkeUtil {
    const val TAG = "FunkeUtil"

    private val keyCreationMutex = Mutex()

    suspend fun communicationKey(env: FlowEnvironment, clientId: String): KeyInfo {
        val secureArea = env.getInterface(SecureAreaProvider::class)!!.get()
        val alias = "FunkeComm_" + clientId
        return try {
            secureArea.getKeyInfo(alias)
        } catch (_: Exception) {
            keyCreationMutex.withLock {
                try {
                    secureArea.getKeyInfo(alias)
                } catch (_: Exception) {
                    secureArea.createKey(alias, CreateKeySettings())
                    secureArea.getKeyInfo(alias)
                }
            }
        }
    }

    suspend fun communicationSign(env: FlowEnvironment, clientId: String, message: ByteArray): ByteArray {
        val secureArea = env.getInterface(SecureAreaProvider::class)!!.get()
        val alias = "FunkeComm_" + clientId
        val sig = secureArea.sign(alias, Algorithm.ES256, message, null)
        return sig.toCoseEncoded()
    }

    suspend fun generateDPoP(
        env: FlowEnvironment,
        clientId: String,
        requestUrl: String,
        dpopNonce: String?,
        accessToken: String? = null
    ): String {
        val keyInfo = communicationKey(env, clientId)
        val header = buildJsonObject {
            put("typ", JsonPrimitive("dpop+jwt"))
            put("alg", JsonPrimitive(keyInfo.publicKey.curve.defaultSigningAlgorithm.jwseAlgorithmIdentifier))
            put("jwk", keyInfo.publicKey.toJson(clientId))
        }.toString().toByteArray().toBase64Url()
        val bodyObj = buildJsonObject {
            put("htm", JsonPrimitive("POST"))
            put("htu", JsonPrimitive(requestUrl))
            put("iat", JsonPrimitive(Clock.System.now().epochSeconds))
            if (dpopNonce != null) {
                put("nonce", JsonPrimitive(dpopNonce))
            }
            put("jti", JsonPrimitive(Random.Default.nextBytes(15).toBase64Url()))
            if (accessToken != null) {
                put("ath", JsonPrimitive(Crypto.digest(Algorithm.SHA256, accessToken.toByteArray()).toBase64Url()))
            }
        }
        val body = bodyObj.toString().toByteArray().toBase64Url()
        val message = "$header.$body"
        val signature = communicationSign(env, clientId, message.toByteArray()).toBase64Url()
        return "$message.$signature"
    }

    suspend fun obtainToken(
        env: FlowEnvironment,
        tokenUrl: String,
        clientId: String,
        issuanceClientId: String,
        refreshToken: String? = null,
        accessToken: String? = null,
        authorizationCode: String? = null,
        preauthorizedCode: String? = null,
        txCode: String? = null,  // pin or other transaction code
        codeVerifier: String? = null,
        dpopNonce: String? = null
    ): FunkeAccess {
        if (refreshToken == null && authorizationCode == null && preauthorizedCode == null) {
            throw IllegalArgumentException("No authorizations provided")
        }
        val httpClient = env.getInterface(HttpClient::class)!!
        var currentDpopNonce = dpopNonce
        // When dpop nonce is null, this loop will run twice, first request will return with error,
        // but will provide fresh, dpop nonce and the second request will get fresh access data.
        while (true) {
            val dpop = generateDPoP(env, clientId, tokenUrl, currentDpopNonce, null)
            val tokenRequest = FormUrlEncoder {
                if (refreshToken != null) {
                    add("grant_type", "refresh_token")
                    add("refresh_token", refreshToken)
                }
                if (authorizationCode != null) {
                    add("grant_type", "authorization_code")
                    add("code", authorizationCode)
                } else if (preauthorizedCode != null) {
                    add("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                    add("pre-authorized_code", preauthorizedCode)
                    if (txCode != null) {
                        add("tx_code", txCode)
                    }
                }
                if (codeVerifier != null) {
                    add("code_verifier", codeVerifier)
                }
                add("client_id", issuanceClientId)
                // TODO: It's arbitrary in our case, right?
                add("redirect_uri", "https://secure.redirect.com")
            }
            val tokenResponse = httpClient.post(tokenUrl) {
                headers {
                    if (currentDpopNonce != null && accessToken != null) {
                        append("Authorization", "DPoP $accessToken")
                    }
                    append("DPoP", dpop)
                    append("Content-Type", "application/x-www-form-urlencoded")
                }
                setBody(tokenRequest.toString())
            }
            if (tokenResponse.status != HttpStatusCode.OK) {
                val errResponseText = String(tokenResponse.readBytes())
                if (currentDpopNonce == null && tokenResponse.headers.contains("DPoP-Nonce")) {
                    Logger.e(TAG, "DPoP nonce refreshed: $errResponseText")
                    currentDpopNonce = tokenResponse.headers["DPoP-Nonce"]!!
                    continue
                }
                Logger.e(TAG, "Token request error: ${tokenResponse.status} $errResponseText")
                throw IssuingAuthorityException(
                    if (authorizationCode != null) {
                        "Authorization code rejected by the issuer"
                    } else {
                        "Refresh token (seed credential) rejected by the issuer"
                    }
                )
            }
            return try {
                FunkeAccess.parseResponse(tokenUrl, tokenResponse)
            } catch (err: IllegalArgumentException) {
                val tokenString = String(tokenResponse.readBytes())
                Logger.e(TAG, "Invalid token response: ${err.message}: $tokenString")
                throw IssuingAuthorityException("Invalid response from the issuer")
            }
        }
    }
}