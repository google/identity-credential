package com.android.identity.server.openid4vci

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.Uint
import com.android.identity.crypto.EcPublicKey
import com.android.identity.flow.handler.AesGcmCipher
import com.android.identity.flow.handler.FlowNotifications
import com.android.identity.flow.handler.InvalidRequestException
import com.android.identity.flow.handler.SimpleCipher
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.getTable
import com.android.identity.server.BaseHttpServlet
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.fromBase64Url
import com.android.identity.util.toBase64Url
import jakarta.servlet.http.HttpServletRequest
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.ByteStringBuilder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Duration

abstract class BaseServlet: BaseHttpServlet() {

    companion object {
        lateinit var cipher: SimpleCipher

        private val rootTableSpec = StorageTableSpec(
            name = "Openid4VciServerRootState",
            supportExpiration = false,
            supportPartitions = false
        )
    }

    override fun initializeEnvironment(env: FlowEnvironment): FlowNotifications? {
        val encryptionKey = runBlocking {
            val storage = env.getTable(rootTableSpec)
            val key = storage.get("issuanceStateEncryptionKey")
            if (key != null) {
                key.toByteArray()
            } else {
                val newKey = Random.nextBytes(16)
                storage.insert(
                    data = ByteString(newKey),
                    key = "issuanceStateEncryptionKey"
                )
                newKey
            }
        }
        cipher = AesGcmCipher(encryptionKey)
        return null
    }

    protected val baseUrl: String
        get() = environment.getInterface(Configuration::class)!!
                    .getValue("base_url") + "/openid4vci"

    /**
     * Creates an opaque session id ("code") that can be safely given to the client. On the server
     * the session is just identified by its id, which stays the same. When referencing the session
     * from the client, we do not want the client to be able to play any games, thus the actual
     * server-side id and a small amount of metadata is encrypted using server secret key.
     *
     * We use these codes for many purposes (identified by [OpaqueIdType]) and always validate
     * that the code we get is actually created for its intended purpose. Also a code contains
     * expiration time, a code can only be used until it expires.
     */
    protected fun idToCode(type: OpaqueIdType, id: String, expiresIn: Duration): String {
        val buf = ByteStringBuilder()
        buf.append(type.ordinal.toByte())
        val idBytes = id.toByteArray()
        check(idBytes.size <= 255)
        buf.append(idBytes.size.toByte())
        buf.append(idBytes)
        val expiration = Clock.System.now() + expiresIn
        buf.append(Cbor.encode(Uint(expiration.epochSeconds.toULong())))
        return cipher.encrypt(buf.toByteString().toByteArray()).toBase64Url()
    }

    /**
     * Decodes opaque session id ("code") into server-side id, validating code purpose (type)
     * and expiration time.
     */
    protected fun codeToId(type: OpaqueIdType, code: String): String {
        val buf = cipher.decrypt(code.fromBase64Url())
        if (buf[0].toInt() != type.ordinal) {
            throw IllegalArgumentException(
                "Not required code/token type, need ${type.ordinal}, got ${buf[0].toInt()}")
        }
        val len = buf[1].toInt()
        val offsetAndExpirationTimeEpochSeconds = Cbor.decode(buf, 2 + len)
        // returned offset should be at the end of the string
        if (offsetAndExpirationTimeEpochSeconds.first != buf.size) {
            throw IllegalArgumentException("Decoding error")
        }
        // expiration time should not be in the past
        if (offsetAndExpirationTimeEpochSeconds.second.asNumber < Clock.System.now().epochSeconds) {
            throw IllegalArgumentException("Code/token expired")
        }
        return String(buf, 2, len)
    }

    /**
     * DPoP Authorization validation.
     */
    protected fun authorizeWithDpop(
        publicKey: EcPublicKey,
        req: HttpServletRequest,
        dpopNonce: String?,
        accessToken: String? = null
    ) {
        val auth = req.getHeader("Authorization")
        if (accessToken == null) {
            if (auth != null) {
                throw InvalidRequestException("Unexpected authorization header")
            }
        } else {
            if (auth == null) {
                throw InvalidRequestException("Authorization header required")
            }
            if (auth.substring(0, 5).lowercase() != "dpop ") {
                throw InvalidRequestException("DPoP authorization required")
            }
            if (auth.substring(5) != accessToken) {
                throw InvalidRequestException("Stale or invalid access token")
            }
        }
        val dpop = req.getHeader("DPoP")
            ?: throw InvalidRequestException("DPoP header required")
        val parts = dpop.split('.')
        if (parts.size != 3) {
            throw InvalidRequestException("DPoP invalid")
        }
        checkJwtSignature(publicKey, dpop)
        val json = Json.parseToJsonElement(String(parts[1].fromBase64Url())) as JsonObject
        if (json["nonce"]?.jsonPrimitive?.content != dpopNonce) {
            throw InvalidRequestException("Stale or invalid DPoP nonce")
        }
        val serverUrl = environment.getInterface(Configuration::class)!!.getValue("base_url")
        // NB: cannot use req.requestURL, as it does not take into account potential frontends.
        val expectedUrl = "$serverUrl${req.servletPath}"
        val actualUrl = json["htu"]?.jsonPrimitive?.content
        if (actualUrl != expectedUrl) {
            throw InvalidRequestException("Incorrect request URI: $expectedUrl vs $actualUrl")
        }
    }
}