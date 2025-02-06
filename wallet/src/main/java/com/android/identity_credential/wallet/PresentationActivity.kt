/*
 * Copyright (C) 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity_credential.wallet

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Text
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.lifecycleScope
import com.android.identity.android.mdoc.deviceretrieval.DeviceRetrievalHelper
import com.android.identity.android.mdoc.transport.DataTransport
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.request.Requester
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.document.Document
import com.android.identity.document.DocumentRequest
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.logging.EventLogger
import com.android.identity_credential.wallet.presentation.UserCanceledPromptException
import com.android.identity_credential.wallet.presentation.showMdocPresentmentFlow
import com.android.identity.request.MdocClaim
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.mdoc.util.toMdocRequest
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class NoMatchingDocumentException(message: String): Exception(message) {}

// using FragmentActivity in order to support androidx.biometric.BiometricPrompt
class PresentationActivity : FragmentActivity() {
    companion object {
        private const val TAG = "PresentationActivity"
        private var transport: DataTransport?
        private var handover: ByteArray?
        private var eDeviceKey: EcPrivateKey?
        private var deviceEngagement: ByteArray?
        private var resultStringId: Int = 0
        private var resultDrawableId: Int = 0
        private var phase = MutableLiveData<Phase>()
        private var resultDelay: Long = 1500

        init {
            phase.value = Phase.NOT_CONNECTED
            transport = null
            handover = null
            eDeviceKey = null
            deviceEngagement = null
        }

        fun engagementDetected(context: Context) {
            if (phase.value != Phase.NOT_CONNECTED) {
                Logger.w(TAG, "engagementDetected: expected NOT_CONNECTED, is in " + phase.value)
                return
            }
            launchPresentationActivity(context)
            phase.value = Phase.ENGAGING
        }

        fun startPresentation(
            context: Context, transport: DataTransport, handover: ByteArray,
            eDeviceKey: EcPrivateKey, deviceEngagement: ByteArray
        ) {
            this.transport = transport
            this.handover = handover
            this.eDeviceKey = eDeviceKey
            this.deviceEngagement = deviceEngagement
            Logger.i(TAG, "engagement info set")

            if (phase.value != Phase.ENGAGING) {
                launchPresentationActivity(context)
            }
            phase.value = Phase.CONNECTED
        }

        private fun launchPresentationActivity(context: Context) {
            val launchAppIntent = Intent(context, PresentationActivity::class.java)
            launchAppIntent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_NO_HISTORY or
                        Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                        Intent.FLAG_ACTIVITY_NO_ANIMATION
            )
            context.startActivity(launchAppIntent)
        }

        fun isPresentationActive(): Boolean {
            return phase.value != Phase.NOT_CONNECTED
        }

        fun stopPresentationReaderTimeout(context: Context) {
            showResult(
                R.string.presentation_result_error_message_reader_timeout,
                R.drawable.presentment_result_status_error)
        }

        fun stopPresentation(context: Context) {
            phase.value = Phase.NOT_CONNECTED
        }

        private fun showResult(stringId: Int, drawableId: Int, delay: Long = 1500) {
            resultStringId = stringId
            resultDrawableId = drawableId
            resultDelay = delay
            phase.value = Phase.SHOW_RESULT
        }
    }

    enum class Phase {
        NOT_CONNECTED,
        ENGAGING,
        CONNECTED,
        REQUEST_AVAILABLE,
        SHOW_RESULT,
        POST_RESULT,
        CANCELED,
    }

    // reference WalletApplication for obtaining dependencies
    private val walletApp: WalletApplication by lazy {
        application as WalletApplication
    }

    // device request bytes
    private var deviceRequestByteArray: ByteArray? = null
    private var deviceRetrievalHelper: DeviceRetrievalHelper? = null

    // Listener for obtaining request bytes from NFC/QR presentation engagements
    val deviceRetrievalHelperListener = object : DeviceRetrievalHelper.Listener {

        override fun onEReaderKeyReceived(eReaderKey: EcPublicKey) {
            Logger.i(TAG, "onEReaderKeyReceived")
        }

        override fun onDeviceRequest(deviceRequestBytes: ByteArray) {
            Logger.i(TAG, "onDeviceRequest")

            deviceRequestByteArray = deviceRequestBytes
            phase.value = Phase.REQUEST_AVAILABLE
        }

        override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
            Logger.i(TAG, "onDeviceDisconnected $transportSpecificTermination")
            disconnect()
        }

        override fun onError(error: Throwable) {
            Logger.e(TAG, "onError", error)
            disconnect()
        }
    }


    @Composable
    fun Result(phase: Phase) {
        AnimatedVisibility(
            visible = phase == Phase.SHOW_RESULT,
            enter = fadeIn(),
            exit = fadeOut(),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxHeight()
                    .padding(horizontal = 32.dp),
                verticalArrangement = Arrangement.Center
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(elevation = 8.dp, shape = RoundedCornerShape(28.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (resultDrawableId != 0) {
                        Image(
                            modifier = Modifier.padding(top = 30.dp),
                            painter = painterResource(resultDrawableId),
                            contentDescription = null,
                            contentScale = ContentScale.None,
                        )
                    }
                    if (resultStringId != 0) {
                        Text(
                            text = stringResource(resultStringId),
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 20.dp, bottom = 40.dp),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }
    }

    @Composable
    fun ConnectingToReader(phase: Phase) {
        AnimatedVisibility(
            visible = phase == Phase.ENGAGING,
            enter = fadeIn(),
            exit = fadeOut(),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxHeight()
                    .padding(horizontal = 32.dp),
                verticalArrangement = Arrangement.Center
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(elevation = 8.dp, shape = RoundedCornerShape(28.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = stringResource(id = R.string.app_name),
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 20.dp),
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Image(
                        modifier = Modifier.padding(top = 20.dp),
                        painter = painterResource(id = R.drawable.waiting_for_reader),
                        contentDescription = null,
                        contentScale = ContentScale.None,
                    )
                    Text(
                        text = stringResource(id = R.string.presentation_waiting_for_reader),
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 20.dp, bottom = 40.dp),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        Logger.i(TAG, "onCreate")
        super.onCreate(savedInstanceState)
        // ensure no external apps can take a peek of Presentment Prompts while viewing recent apps
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContent {
            val phaseState: Phase by phase.observeAsState(Phase.NOT_CONNECTED)
            ConnectingToReader(phaseState)
            Result(phaseState)
        }


        phase.observe(this as LifecycleOwner) {
            when (it!!) {
                Phase.NOT_CONNECTED -> {
                    Logger.i(TAG, "Phase: Not Connected")
                    finish()
                }

                Phase.ENGAGING -> {
                    Logger.i(TAG, "Phase: Engaging")
                }

                Phase.CONNECTED -> {
                    Logger.i(TAG, "Phase: Connected")
                    // on a new connected client, create a new DeviceRetrievalHelper
                    deviceRetrievalHelper = DeviceRetrievalHelper
                        .Builder(
                            applicationContext,
                            deviceRetrievalHelperListener,
                            ContextCompat.getMainExecutor(applicationContext),
                            eDeviceKey!!
                        )
                        .useForwardEngagement(transport!!, deviceEngagement!!, handover!!)
                        .build()
                }

                Phase.REQUEST_AVAILABLE -> {
                    Logger.i(TAG, "Phase: Request Available")
                    /**
                     * Device request bytes have been transmitted via device retrieval helper listener,
                     * Start the Presentment Flow where a Presentment is shown for every
                     * [DocumentRequest] that has a suitable [Document].
                     */
                    lifecycleScope.launch {
                        try {
                            val deviceRequest = DeviceRequestParser(
                                deviceRequestByteArray!!,
                                deviceRetrievalHelper!!.sessionTranscript
                            ).parse()

                            // generates the DeviceResponse from all the [Document] CBOR bytes of docRequests
                            val deviceResponseGenerator =
                                DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)

                            // Inside Phase.REQUEST_AVAILABLE
                            var requester: EventLogger.Requester? = null
                            deviceRequest.docRequests.forEach { docRequest ->
                                // find an MdocCredential for the docRequest or skip to next docRequest
                                val mdocCredential =
                                    findMdocCredentialForRequest(docRequest) ?: return@forEach

                                // See if we recognize the reader/verifier
                                var trustPoint: TrustPoint? = null
                                if (docRequest.readerAuthenticated) {
                                    val result = walletApp.readerTrustManager.verify(
                                        docRequest.readerCertificateChain!!.certificates,
                                    )
                                    if (result.isTrusted && result.trustPoints.isNotEmpty()) {
                                        trustPoint = result.trustPoints.first()
                                        val requesterName = trustPoint.certificate.javaX509Certificate.subjectX500Principal.name
                                        requester = EventLogger.Requester.Named(requesterName)
                                    } else if (result.error != null) {
                                        Logger.w(
                                            TAG,
                                            "Error finding TrustPoint for reader auth",
                                            result.error!!
                                        )
                                    }
                                } else {
                                    requester = EventLogger.Requester.Anonymous()
                                }

                                val request = docRequest.toMdocRequest(
                                    documentTypeRepository = walletApp.documentTypeRepository,
                                    mdocCredential = mdocCredential
                                )

                                // show the Presentation Flow for and get the response bytes for
                                // the generated Document
                                val documentCborBytes = showMdocPresentmentFlow(
                                    activity = this@PresentationActivity,
                                    request = request,
                                    trustPoint = trustPoint,
                                    document = ConsentDocument(
                                        name = mdocCredential.document.documentConfiguration.displayName,
                                        description = mdocCredential.document.documentConfiguration.typeDisplayName,
                                        cardArt = mdocCredential.document.documentConfiguration.cardArt,
                                    ),
                                    credential = mdocCredential,
                                    encodedSessionTranscript = deviceRetrievalHelper!!.sessionTranscript
                                )
                                deviceResponseGenerator.addDocument(documentCborBytes)
                            }
                            if (deviceResponseGenerator.isEmpty()) {
                                throw NoMatchingDocumentException("No documents found.")
                            }
                            val deviceResponse = deviceResponseGenerator.generate()
                            deviceRetrievalHelper?.sendDeviceResponse(
                                deviceResponse,
                                Constants.SESSION_DATA_STATUS_SESSION_TERMINATION
                            )
                            showResult(
                                R.string.presentation_result_success_message,
                                R.drawable.presentment_result_status_success)
                            resultStringId = R.string.presentation_result_success_message
                            resultDrawableId = R.drawable.presentment_result_status_success
                            phase.value = Phase.SHOW_RESULT

                            // Add the PresentationActivity entry
                            walletApp.eventLogger.addMDocPresentationEntry(
                                walletApp.settingsModel.focusedCardId.value.toString(),
                                deviceRetrievalHelper!!.sessionTranscript,
                                deviceRequestByteArray!!,
                                deviceResponse,
                                requester ?: EventLogger.Requester.Anonymous(),
                                EventLogger.ShareType.SHARED_WITH_APPLICATION,
                            )
                        } catch (e: Throwable) {
                            if (e is UserCanceledPromptException) {
                                phase.value = Phase.CANCELED
                            } else if (e is NoMatchingDocumentException) {
                                Logger.e(TAG, "No matching document while running the Presentment Flow", e)
                                showResult(
                                    R.string.presentation_result_no_matching_document_message,
                                    R.drawable.presentment_result_status_error,
                                    3000)
                            } else {
                                Logger.e(TAG, "Error while running the Presentment Flow", e)
                                showResult(
                                    R.string.presentation_result_error_message,
                                    R.drawable.presentment_result_status_error)
                            }
                        }
                    }
                }

                Phase.SHOW_RESULT -> {
                    Logger.i(TAG, "Phase: Showing result")
                    lifecycleScope.launch {
                        // the amount of time to show the result for
                        delay(resultDelay)
                        phase.value = Phase.POST_RESULT
                    }
                }

                Phase.POST_RESULT -> {
                    Logger.i(TAG, "Phase: Post showing result")
                    lifecycleScope.launch {
                        // delay before finishing activity, to ensure the result is fading out
                        delay(500)
                        phase.value = Phase.NOT_CONNECTED
                    }
                }

                Phase.CANCELED -> {
                    Logger.i(TAG, "Phase: Canceled")
                    phase.value = Phase.NOT_CONNECTED
                }
            }
        }
    }


    override fun onDestroy() {
        Logger.i(TAG, "onDestroy")
        disconnect()
        super.onDestroy()
    }

    private suspend fun documentGetValidMdocCredentialIfAvailable(
        document: Document,
        docType: String,
        now: Instant,
    ): MdocCredential?  =
        if (document.documentConfiguration.mdocConfiguration?.docType == docType) {
            document.findCredential(
                WalletApplication.CREDENTIAL_DOMAIN_MDOC,
                now,
            ) as MdocCredential
        } else {
            null
        }

    /**
     * Find a suitable Document for the given [docRequest] else throw [IllegalStateException].
     * @param docRequest parsed from DeviceRequest CBOR.
     * @return a matching [MdocCredential] from either on-screen Document or [DocumentStore]
     *      or null if there are no matching MdocCredential
     */
    private suspend fun findMdocCredentialForRequest(
        docRequest: DeviceRequestParser.DocRequest
    ): MdocCredential? {
        val now = Clock.System.now()

        // prefer the document that is on-screen if possible
        walletApp.settingsModel.focusedCardId.value?.let { documentIdFromPager ->
            val pagerDocument = walletApp.documentStore.lookupDocument(documentIdFromPager)
            if (pagerDocument != null) {
                val mdocCredential = documentGetValidMdocCredentialIfAvailable(
                    pagerDocument,
                    docRequest.docType,
                    now)
                if (mdocCredential != null) {
                    return mdocCredential
                }
            }
        }

        // no matches from above, check suitability with all Documents added to DocumentStore
        walletApp.documentStore.listDocuments().forEach storeloop@{ documentIdFromStore ->
            val storeDocument = walletApp.documentStore.lookupDocument(documentIdFromStore)!!
            val mdocCredential = documentGetValidMdocCredentialIfAvailable(
                storeDocument,
                docRequest.docType,
                now)
            if (mdocCredential != null) {
                return mdocCredential
            }
        }

        return null
    }

    private fun disconnect() {
        Logger.i(TAG, "disconnect")
        if (deviceRetrievalHelper == null) {
            Logger.i(TAG, "already closed")
            return
        }
        // If the connection to the reader is still open, let them know we're shutting down
        // as required by ISO 18013-5.
        if (phase.value == Phase.REQUEST_AVAILABLE) {
            deviceRetrievalHelper?.sendDeviceResponse(
                DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_GENERAL_ERROR).generate(),
                Constants.SESSION_DATA_STATUS_SESSION_TERMINATION
            )
        }
        deviceRetrievalHelper?.disconnect()
        deviceRetrievalHelper = null
        transport = null
        handover = null
    }
}