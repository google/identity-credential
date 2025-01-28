package com.android.identity.wallet.server

import com.android.identity.flow.handler.FlowNotifications
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.Resources
import com.android.identity.flow.server.getTable
import com.android.identity.issuance.LandingUrlNotification
import com.android.identity.issuance.wallet.ApplicationSupportState
import com.android.identity.issuance.wallet.LandingRecord
import com.android.identity.issuance.wallet.emit
import com.android.identity.issuance.wallet.fromCbor
import com.android.identity.issuance.wallet.toCbor
import com.android.identity.server.BaseHttpServlet
import com.android.identity.util.Logger
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString

/**
 * Servlet to handle landing for a redirect url that happens as a final step in the OpenID-based
 * workflows, when user is authorizing in the browser.
 *
 * A specific landing URL is created using [ApplicationSupport.createLandingUrl] method.
 */
class LandingServlet: BaseHttpServlet() {
    companion object {
        private const val TAG = "LandingServlet"
    }

    override fun initializeEnvironment(env: FlowEnvironment): FlowNotifications? {
        // Use notifications from FlowServlet (it must be initialized before LandingServlet)
        return environmentFor(FlowServlet::class)!!.getInterface(FlowNotifications::class)
    }

    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val threadId = Thread.currentThread().id
        val remoteHost = getRemoteHost(req)
        val prefix = "tid=$threadId host=$remoteHost"
        val rawPath = req.pathInfo
        Logger.i(TAG, "$prefix: GET $rawPath")
        if (rawPath == null) {
            resp.sendError(404)
            return
        }
        val id = rawPath.substring(1)
        runBlocking {
            val storage = environment.getTable(ApplicationSupportState.landingTableSpec)
            val recordData = storage.get(id)
            if (recordData == null) {
                resp.sendError(404)
            } else {
                val record = LandingRecord.fromCbor(recordData.toByteArray())
                record.resolved = req.queryString ?: ""
                storage.update(id, ByteString(record.toCbor()))
                val configuration = environment.getInterface(Configuration::class)!!
                val baseUrl = configuration.getValue("base_url")
                val landingUrl = "$baseUrl/${ApplicationSupportState.URL_PREFIX}$id"
                ApplicationSupportState(record.clientId).emit(environment,
                    LandingUrlNotification(landingUrl))
                resp.contentType = "text/html"
                val resources = environment.getInterface(Resources::class)!!
                resp.outputStream.write(
                    resources.getRawResource("landing/index.html")!!.toByteArray())
            }
        }
    }
}