/*
 * Copyright (C) 2023 Google LLC
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

package com.android.identity.preconsent_mdl

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.LifecycleOwner
import com.android.identity.document.NameSpacedData
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.preconsent_mdl.ui.theme.IdentityCredentialTheme
import com.android.identity.crypto.Algorithm
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock

class PresentationActivity : ComponentActivity() {
    companion object {
        private val TAG = "PresentationActivity"
    }

    private lateinit var transferHelper: TransferHelper

    override fun onDestroy() {
        Logger.i(TAG, "onDestroy")
        transferHelper.disconnect()
        super.onDestroy()
    }

    private var connectionMethodString: String = ""
    private var durationMillisTapToEngagement: Long = 0
    private var durationMillisEngagementToRequest: Long = 0
    private var durationMillisScanning: Long = 0
    private var durationMillisRequestToResponse: Long = 0
    private var durationMillisTotal: Long = 0

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        Logger.i(TAG, "onCreate")
        super.onCreate(savedInstanceState)


        transferHelper = TransferHelper.getInstance(applicationContext)

        setContent {
            IdentityCredentialTheme {

                var stateDisplay = remember { mutableStateOf("Idle") }
                val coroutineScope = rememberCoroutineScope()

                transferHelper.getState().observe(this as LifecycleOwner) { state ->
                    when (state) {
                        TransferHelper.State.NOT_CONNECTED -> {
                            stateDisplay.value = "Not Connected"
                            Logger.i(TAG, "State: Not Connected")
                        }
                        TransferHelper.State.ENGAGING -> {
                            stateDisplay.value = "Engaging"
                            Logger.i(TAG, "State: Engaging")
                        }
                        TransferHelper.State.ENGAGEMENT_SENT -> {
                            stateDisplay.value = "Engagement Sent"
                            Logger.i(TAG, "State: Engagement sent")
                        }
                        TransferHelper.State.CONNECTED -> {
                            stateDisplay.value = "Connected"
                            Logger.i(TAG, "State: Connected")
                            connectionMethodString = transferHelper.getConnectionMethod().toString()
                        }
                        TransferHelper.State.REQUEST_AVAILABLE -> {
                            stateDisplay.value = "Request Available"
                            Logger.i(TAG, "State: Request Available")
                            coroutineScope.launch {
                                processRequest()
                            }
                        }
                        TransferHelper.State.RESPONSE_SENT -> {
                            stateDisplay.value = "Response Sent"
                            Logger.i(TAG, "State: Response Sent")
                            durationMillisTapToEngagement = transferHelper.getTapToEngagementSentDurationMillis()
                            durationMillisEngagementToRequest = transferHelper.getEngagementSentToRequestAvailableDurationMillis()
                            durationMillisScanning = transferHelper.getScanningDurationMillis()
                            durationMillisRequestToResponse = transferHelper.getRequestToResponseDurationMillis()
                            durationMillisTotal = transferHelper.getTotalDurationMillis()
                        }
                        else -> {}
                    }
                }

                val engagementString =
                    if (transferHelper.getNfcStaticHandoverEnabled()) {
                        "NFC Static Handover"
                    } else {
                        "NFC Negotiated Handover"
                    }

                val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
                Scaffold(
                    modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),

                    topBar = {
                        CenterAlignedTopAppBar(
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer,
                                titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            ),
                            title = {
                                Text(
                                    "mDL Preconsent Presentation",
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            },
                            scrollBehavior = scrollBehavior,
                        )
                    },
                ) { innerPadding ->
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        color = MaterialTheme.colorScheme.background,
                    ) {
                        Column() {
                            val scrollState = rememberScrollState()
                            Column(
                                modifier = Modifier
                                    .padding(16.dp)
                                    .verticalScroll(scrollState),
                                verticalArrangement = Arrangement.spacedBy(16.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Column() {
                                    Text(
                                        text = "Sending mDL to reader.",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                Column() {
                                    Text(
                                        text = "Engagement: $engagementString",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                Column() {
                                    Text(
                                        text = "Connection: $connectionMethodString",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                Divider()
                                Column() {
                                    Text(
                                        text = "State: ${stateDisplay.value}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                Divider()
                                Column {
                                    Text(
                                        text = "Tap to Engagement Sent: $durationMillisTapToEngagement ms",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                Column {
                                    Text(
                                        text = "Engagement Sent to Request Received: $durationMillisEngagementToRequest ms",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                val scanningText = if (durationMillisScanning > 0) {
                                    "$durationMillisScanning ms"
                                } else {
                                    "N/A"
                                }
                                Column {
                                    Text(
                                        text = "BLE Scanning: $scanningText",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                Column {
                                    Text(
                                        text = "Request Received to Response Sent: $durationMillisRequestToResponse ms",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                Column {
                                    Text(
                                        text = "Total transaction time: $durationMillisTotal ms",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                Divider()
                                Column {
                                    Button(onClick = { finish() }) {
                                        Text("Close")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    private suspend fun processRequest() {
        val request = DeviceRequestParser(
            transferHelper.getDeviceRequest(),
            transferHelper.getSessionTranscript()
        ).parse()
        val docRequest = request.docRequests[0]
        val documentRequest = MdocUtil.generateDocumentRequest(docRequest)
        val now = Clock.System.now()

        val documentIds = transferHelper.documentStore.listDocuments()
        // Must have one at this point
        val document = transferHelper.documentStore.lookupDocument(documentIds[0])!!
        val credential =
            document.findCredential(MainActivity.AUTH_KEY_DOMAIN, now) as MdocCredential

        val staticAuthData = StaticAuthDataParser(credential.issuerProvidedData).parse()
        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            documentRequest,
            document.preconsentMetadata.namespacedData,
            staticAuthData
        )

        val deviceResponseGenerator =
            DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
        deviceResponseGenerator.addDocument(
            DocumentGenerator(
                MainActivity.MDL_DOCTYPE,
                staticAuthData.issuerAuth,
                transferHelper.getSessionTranscript()
            )
                .setIssuerNamespaces(mergedIssuerNamespaces)
                .setDeviceNamespacesSignature(
                    NameSpacedData.Builder().build(),
                    credential.secureArea,
                    credential.alias,
                    null,
                    Algorithm.ES256
                )
                .generate()
        )
        val encodedDeviceResponse = deviceResponseGenerator.generate()
        transferHelper.sendResponse(encodedDeviceResponse)
    }
}
