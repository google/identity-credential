package com.android.identity.server

import com.android.identity.flow.handler.AesGcmCipher
import com.android.identity.flow.handler.FlowDispatcherLocal
import com.android.identity.flow.handler.FlowExceptionMap
import com.android.identity.flow.handler.FlowNotifications
import com.android.identity.flow.handler.FlowNotificationsLocalPoll
import com.android.identity.flow.handler.HttpHandler
import com.android.identity.flow.handler.SimpleCipher
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.getTable
import com.android.identity.flow.transport.HttpTransport
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.Logger
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import java.lang.UnsupportedOperationException
import kotlin.random.Random

/**
 * Servlet to handle flow RPC requests.
 *
 * Subclass this servlet registering all flow method handlers and exceptions by overriding
 * buildExceptionMap and buildDispatcher. Typically a single subclass should handle all
 * flow RPC requests on a given server.
 */
abstract class BaseFlowHttpServlet : BaseHttpServlet() {
    companion object {
        const val TAG = "BaseFlowHttpServlet"

        private val flowRootStateTableSpec = StorageTableSpec(
            name = "FlowRootState",
            supportPartitions = false,
            supportExpiration = false
        )
    }

    private lateinit var httpHandler: HttpHandler

    override fun initializeEnvironment(env: FlowEnvironment): FlowNotifications? {
        val exceptionMapBuilder = FlowExceptionMap.Builder()
        buildExceptionMap(exceptionMapBuilder)
        val dispatcherBuilder = FlowDispatcherLocal.Builder()
        buildDispatcher(dispatcherBuilder)
        val messageEncryptionKey = runBlocking {
            val storage = env.getTable(flowRootStateTableSpec)
            val key = storage.get("messageEncryptionKey")
            if (key != null) {
                key.toByteArray()
            } else {
                val newKey = Random.nextBytes(16)
                storage.insert(
                    key = "messageEncryptionKey",
                    data = ByteString(newKey),
                )
                newKey
            }
        }
        val cipher = AesGcmCipher(messageEncryptionKey)
        val localPoll = FlowNotificationsLocalPoll(cipher)
        val localDispatcher = dispatcherBuilder.build(
            env,
            cipher,
            exceptionMapBuilder.build()
        )

        httpHandler = HttpHandler(localDispatcher, localPoll)
        return localPoll
    }

    abstract fun buildExceptionMap(exceptionMapBuilder: FlowExceptionMap.Builder)
    abstract fun buildDispatcher(dispatcherBuilder: FlowDispatcherLocal.Builder)

    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val path = req.pathInfo.substring(1)
        val threadId = Thread.currentThread().id
        val remoteHost = getRemoteHost(req)
        val prefix = "tid=$threadId host=$remoteHost"
        val requestLength = req.contentLength
        Logger.i(TAG, "$prefix: POST $path ($requestLength bytes)")
        val parts = path.split("/")
        if (parts.size != 2) {
            Logger.i(TAG, "$prefix: malformed request")
            throw Exception("Illegal request!")
        }
        val target = parts[0]
        val action = parts[1]
        val requestData = req.inputStream.readNBytes(requestLength)
        try {
            val bytes = runBlocking {
                httpHandler.post(
                    url = "$target/$action",
                    data = ByteString(requestData)
                )
            }
            Logger.i(TAG, "$prefix: POST response status 200 (${bytes.size} bytes)")
            resp.outputStream.write(bytes.toByteArray())
        } catch (e: UnsupportedOperationException) {
            Logger.e(TAG, "$prefix: POST response status 404", e)
            resp.sendError(404, e.message)
        } catch (e: SimpleCipher.DataTamperedException) {
            Logger.e(TAG, "$prefix: POST response status 405", e)
            resp.sendError(405, "State tampered")
        } catch (e: IllegalStateException) {
            Logger.e(TAG, "$prefix: POST response status 405", e)
            resp.sendError(405, "IllegalStateException")
        } catch (e: Throwable) {
            // NotificationTimeoutError happens frequently, don't need a stack trace for this...
            if (e is HttpTransport.TimeoutException) {
                Logger.e(TAG, "$prefix: POST response status 500 (TimeoutException)")
            } else {
                Logger.e(TAG, "$prefix: POST response status 500", e)
            }
            resp.sendError(500, e.message)
        }
    }

    override val outputFormat: String
        get() = "application/cbor"
}