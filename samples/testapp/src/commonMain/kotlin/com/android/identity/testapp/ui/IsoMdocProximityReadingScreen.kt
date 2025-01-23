package com.android.identity.testapp.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.android.identity.appsupport.ui.decodeImage
import com.android.identity.appsupport.ui.permissions.rememberBluetoothPermissionState
import com.android.identity.appsupport.ui.qrcode.ScanQrCodeDialog
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.DiagnosticOption
import com.android.identity.cbor.Simple
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.documenttype.DocumentAttributeType
import com.android.identity.documenttype.DocumentType
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.DocumentCannedRequest
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.engagement.EngagementParser
import com.android.identity.mdoc.nfc.scanNfcMdocReader
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.mdoc.sessionencryption.SessionEncryption
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.mdoc.transport.MdocTransportClosedException
import com.android.identity.mdoc.transport.MdocTransportFactory
import com.android.identity.mdoc.transport.MdocTransportOptions
import com.android.identity.testapp.TestAppSettingsModel
import com.android.identity.testapp.TestAppUtils
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import com.android.identity.util.fromBase64Url
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.bytestring.ByteString

private const val TAG = "IsoMdocProximityReadingScreen"

private data class ConnectionMethodPickerData(
    val showPicker: Boolean,
    val connectionMethods: List<ConnectionMethod>,
    val continuation:  CancellableContinuation<ConnectionMethod?>,
)

private suspend fun selectConnectionMethod(
    connectionMethods: List<ConnectionMethod>,
    connectionMethodPickerData: MutableState<ConnectionMethodPickerData?>
): ConnectionMethod? {
    return suspendCancellableCoroutine { continuation ->
        connectionMethodPickerData.value = ConnectionMethodPickerData(
            showPicker = true,
            connectionMethods = connectionMethods,
            continuation = continuation
        )
    }
}

private data class RequestPickerEntry(
    val displayName: String,
    val documentType: DocumentType,
    val sampleRequest: DocumentCannedRequest
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalCoroutinesApi::class)
@Composable
fun IsoMdocProximityReadingScreen(
    settingsModel: TestAppSettingsModel,
    showToast: (message: String) -> Unit,
) {
    val availableRequests = mutableListOf<RequestPickerEntry>()
    for (documentType in TestAppUtils.provisionedDocumentTypes) {
        for (sampleRequest in documentType.cannedRequests) {
            availableRequests.add(RequestPickerEntry(
                displayName = "${documentType.displayName}: ${sampleRequest.displayName}",
                documentType = documentType,
                sampleRequest = sampleRequest
            ))
        }
    }
    var dropdownExpanded = remember { mutableStateOf(false) }
    var selectedRequest = remember { mutableStateOf(availableRequests[0]) }

    val blePermissionState = rememberBluetoothPermissionState()

    val coroutineScope = rememberCoroutineScope()

    val readerShowQrScanner = remember { mutableStateOf(false) }
    var readerJob by remember { mutableStateOf<Job?>(null) }
    var readerTransport = remember { mutableStateOf<MdocTransport?>(null) }
    var readerSessionEncryption = remember { mutableStateOf<SessionEncryption?>(null) }
    var readerSessionTranscript = remember { mutableStateOf<ByteArray?>(null) }
    var readerMostRecentDeviceResponse = remember { mutableStateOf<ByteArray?>(null) }

    val connectionMethodPickerData = remember { mutableStateOf<ConnectionMethodPickerData?>(null) }

    if (connectionMethodPickerData.value != null) {
        val radioOptions = connectionMethodPickerData.value!!.connectionMethods
        val (selectedOption, onOptionSelected) = remember { mutableStateOf(radioOptions[0]) }
        AlertDialog(
            title = @Composable { Text(text = "Select Connection Method") },
            text = @Composable {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Column(
                        modifier = Modifier.selectableGroup(),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        radioOptions.forEach { connectionMethod ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .selectable(
                                        selected = (connectionMethod == selectedOption),
                                        onClick = { onOptionSelected(connectionMethod) },
                                        role = Role.RadioButton
                                    )
                                    .padding(horizontal = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                RadioButton(
                                    selected = (connectionMethod == selectedOption),
                                    onClick = null
                                )
                                Text(
                                    text = connectionMethod.toString(),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }

                }
            },
            dismissButton = @Composable {
                TextButton(
                    onClick = {
                        connectionMethodPickerData.value!!.continuation.resume(null, null)
                        connectionMethodPickerData.value = null
                    }
                ) {
                    Text("Cancel")
                }
            },
            onDismissRequest = {
                connectionMethodPickerData.value!!.continuation.resume(null, null)
                connectionMethodPickerData.value = null
            },
            confirmButton = @Composable {
                TextButton(
                    onClick = {
                        connectionMethodPickerData.value!!.continuation.resume(selectedOption, null)
                        connectionMethodPickerData.value = null
                    }
                ) {
                    Text("Connect")
                }
            }
        )
    }

    if (readerShowQrScanner.value) {
        ScanQrCodeDialog(
            title = { Text(text = "Scan QR code") },
            text = { Text(text = "Scan this QR code on another device") },
            dismissButton = "Close",
            onCodeScanned = { data ->
                if (data.startsWith("mdoc:")) {
                    readerShowQrScanner.value = false
                    readerJob = coroutineScope.launch() {
                        doReaderFlow(
                            encodedDeviceEngagement = ByteString(data.substring(5).fromBase64Url()),
                            existingTransport = null,
                            handover = Simple.NULL,
                            allowMultipleRequests = settingsModel.readerAllowMultipleRequests.value,
                            bleUseL2CAP = settingsModel.readerBleL2CapEnabled.value,
                            showToast = showToast,
                            readerTransport = readerTransport,
                            readerSessionEncryption = readerSessionEncryption,
                            readerSessionTranscript = readerSessionTranscript,
                            readerMostRecentDeviceResponse = readerMostRecentDeviceResponse,
                            selectedRequest = selectedRequest,
                            selectConnectionMethod = { connectionMethods ->
                                if (settingsModel.readerAutomaticallySelectTransport.value) {
                                    showToast("Auto-selected first from $connectionMethods")
                                    connectionMethods[0]
                                } else {
                                    selectConnectionMethod(
                                        connectionMethods,
                                        connectionMethodPickerData
                                    )
                                }
                            }
                        )
                        readerJob = null
                    }
                    true
                } else {
                    false
                }
            },
            onDismiss = { readerShowQrScanner.value = false }
        )
    }

    val readerTransportState = readerTransport.value?.state?.collectAsState()

    if (!blePermissionState.isGranted) {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(
                onClick = { blePermissionState.launchPermissionRequest() }
            ) {
                Text("Request BLE permissions")
            }
        }
    } else {
        if (readerJob != null) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Column(
                    modifier = Modifier.weight(1.0f),
                    verticalArrangement = Arrangement.SpaceEvenly,
                ) {
                    ShowReaderResults(readerMostRecentDeviceResponse, readerSessionTranscript)
                }
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Connection State: ${readerTransportState?.value}",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(modifier = Modifier.height(10.dp))
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.SpaceEvenly,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                try {
                                    val encodedDeviceRequest =
                                        TestAppUtils.generateEncodedDeviceRequest(
                                            selectedRequest.value.sampleRequest,
                                            readerSessionTranscript.value!!
                                        )
                                    readerMostRecentDeviceResponse.value = byteArrayOf()
                                    readerTransport.value!!.sendMessage(
                                        readerSessionEncryption.value!!.encryptMessage(
                                            messagePlaintext = encodedDeviceRequest,
                                            statusCode = null
                                        )
                                    )
                                } catch (error: Throwable) {
                                    Logger.e(TAG, "Caught exception", error)
                                    error.printStackTrace()
                                    showToast("Error: ${error.message}")
                                }
                            }
                        }
                    ) {
                        Text("Send Another Request")
                    }
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                try {
                                    readerTransport.value!!.sendMessage(
                                        SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION)
                                    )
                                    readerTransport.value!!.close()
                                } catch (error: Throwable) {
                                    Logger.e(TAG, "Caught exception", error)
                                    error.printStackTrace()
                                    showToast("Error: ${error.message}")
                                }
                            }
                        }
                    ) {
                        Text("Close (Message)")
                    }
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                try {
                                    readerTransport.value!!.sendMessage(byteArrayOf())
                                    readerTransport.value!!.close()
                                } catch (error: Throwable) {
                                    Logger.e(TAG, "Caught exception", error)
                                    error.printStackTrace()
                                    showToast("Error: ${error.message}")
                                }
                            }
                        }
                    ) {
                        Text("Close (Transport-Specific)")
                    }
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                try {
                                    readerTransport.value!!.close()
                                } catch (error: Throwable) {
                                    Logger.e(TAG, "Caught exception", error)
                                    error.printStackTrace()
                                    showToast("Error: ${error.message}")
                                }
                            }
                        }
                    ) {
                        Text("Close (None)")
                    }
                }
            }
        } else if (readerMostRecentDeviceResponse.value != null) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Column(
                    modifier = Modifier.weight(1.0f),
                    verticalArrangement = Arrangement.SpaceEvenly,
                ) {
                    ShowReaderResults(readerMostRecentDeviceResponse, readerSessionTranscript)
                }
                Spacer(modifier = Modifier.height(10.dp))
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.SpaceEvenly,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Button(
                        onClick = { readerMostRecentDeviceResponse.value = null }
                    ) {
                        Text("Close")
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.padding(8.dp)
            ) {
                item {
                    SettingHeadline("Transports (NFC Negotiated Handover)")
                }
                item {
                    SettingToggle(
                        title = "BLE (mdoc central client mode)",
                        isChecked = settingsModel.readerBleCentralClientModeEnabled.collectAsState().value,
                        onCheckedChange = { settingsModel.readerBleCentralClientModeEnabled.value = it },
                    )
                }
                item {
                    SettingToggle(
                        title = "BLE (mdoc peripheral server mode)",
                        isChecked = settingsModel.readerBlePeripheralServerModeEnabled.collectAsState().value,
                        onCheckedChange = { settingsModel.readerBlePeripheralServerModeEnabled.value = it },
                    )
                }
                item {
                    SettingToggle(
                        title = "Automatically select transport",
                        isChecked = settingsModel.readerAutomaticallySelectTransport.collectAsState().value,
                        onCheckedChange = { settingsModel.readerAutomaticallySelectTransport.value = it },
                    )
                }
                item {
                    SettingHeadline("Transport Options")
                }
                item {
                    SettingToggle(
                        title = "Use L2CAP if available",
                        isChecked = settingsModel.readerBleL2CapEnabled.collectAsState().value,
                        onCheckedChange = { settingsModel.readerBleL2CapEnabled.value = it },
                    )
                }
                item {
                    SettingToggle(
                        title = "Keep connection open after first request",
                        isChecked = settingsModel.readerAllowMultipleRequests.collectAsState().value,
                        onCheckedChange = { settingsModel.readerAllowMultipleRequests.value = it },
                    )
                }
                item {
                    HorizontalDivider(
                        modifier = Modifier.padding(8.dp)
                    )
                }
                item {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Button(
                            onClick = {
                                settingsModel.resetReaderSettings()
                            },
                        ) {
                            Text(text = "Reset Settings")
                        }
                    }
                }
                item {
                    HorizontalDivider(
                        modifier = Modifier.padding(8.dp)
                    )
                }
                item {
                    RequestPicker(
                        availableRequests,
                        selectedRequest,
                        dropdownExpanded,
                        onRequestSelected = {}
                    )
                }
                item {
                    TextButton(
                        onClick = {
                            readerShowQrScanner.value = true
                            readerMostRecentDeviceResponse.value = null
                        },
                        content = { Text("Request mdoc via QR Code") }
                    )
                }
                item {
                    TextButton(
                        onClick = {
                            readerMostRecentDeviceResponse.value = null

                            coroutineScope.launch {
                                try {
                                    val negotiatedHandoverConnectionMethods = mutableListOf<ConnectionMethod>()
                                    val bleUuid = UUID.randomUUID()
                                    if (settingsModel.readerBleCentralClientModeEnabled.value) {
                                        negotiatedHandoverConnectionMethods.add(
                                            ConnectionMethodBle(
                                                supportsPeripheralServerMode = false,
                                                supportsCentralClientMode = true,
                                                peripheralServerModeUuid = null,
                                                centralClientModeUuid = bleUuid,
                                            )
                                        )
                                    }
                                    if (settingsModel.readerBlePeripheralServerModeEnabled.value) {
                                        negotiatedHandoverConnectionMethods.add(
                                            ConnectionMethodBle(
                                                supportsPeripheralServerMode = true,
                                                supportsCentralClientMode = false,
                                                peripheralServerModeUuid = bleUuid,
                                                centralClientModeUuid = null,
                                            )
                                        )
                                    }
                                    val result = scanNfcMdocReader(
                                        message = "Hold near credential holder's phone.",
                                        options = MdocTransportOptions(
                                            bleUseL2CAP = settingsModel.readerBleL2CapEnabled.value
                                        ),
                                        selectConnectionMethod = { connectionMethods ->
                                            if (settingsModel.readerAutomaticallySelectTransport.value) {
                                                showToast("Auto-selected first from $connectionMethods")
                                                connectionMethods[0]
                                            } else {
                                                selectConnectionMethod(
                                                    connectionMethods,
                                                    connectionMethodPickerData
                                                )
                                            }
                                        },
                                        negotiatedHandoverConnectionMethods = negotiatedHandoverConnectionMethods
                                    )
                                    if (result != null) {
                                        readerJob = CoroutineScope(Dispatchers.IO).launch {
                                            try {
                                                doReaderFlow(
                                                    encodedDeviceEngagement = result.encodedDeviceEngagement,
                                                    existingTransport = result.transport,
                                                    handover = result.handover,
                                                    allowMultipleRequests = settingsModel.readerAllowMultipleRequests.value,
                                                    bleUseL2CAP = settingsModel.readerBleL2CapEnabled.value,
                                                    showToast = showToast,
                                                    readerTransport = readerTransport,
                                                    readerSessionEncryption = readerSessionEncryption,
                                                    readerSessionTranscript = readerSessionTranscript,
                                                    readerMostRecentDeviceResponse = readerMostRecentDeviceResponse,
                                                    selectedRequest = selectedRequest,
                                                    selectConnectionMethod = { connectionMethods ->
                                                        if (settingsModel.readerAutomaticallySelectTransport.value) {
                                                            showToast("Auto-selected first from $connectionMethods")
                                                            connectionMethods[0]
                                                        } else {
                                                            selectConnectionMethod(
                                                                connectionMethods,
                                                                connectionMethodPickerData
                                                            )
                                                        }
                                                    }
                                                )
                                                readerJob = null
                                            } catch (e: Throwable) {
                                                Logger.e(TAG, "NFC engagement transport failed", e)
                                                e.printStackTrace()
                                                showToast("NFC engagement transport failed with $e")
                                            }
                                        }
                                    }
                                } catch (e: Throwable) {
                                    Logger.e(TAG, "NFC engagement failed", e)
                                    e.printStackTrace()
                                    showToast("NFC engagement failed with $e")
                                }
                            }
                        },
                        content = { Text("Request mdoc via NFC") }
                    )
                }
            }
        }
    }
}

private suspend fun doReaderFlow(
    encodedDeviceEngagement: ByteString,
    existingTransport: MdocTransport?,
    handover: DataItem,
    allowMultipleRequests: Boolean,
    bleUseL2CAP: Boolean,
    showToast: (message: String) -> Unit,
    readerTransport: MutableState<MdocTransport?>,
    readerSessionEncryption: MutableState<SessionEncryption?>,
    readerSessionTranscript: MutableState<ByteArray?>,
    readerMostRecentDeviceResponse: MutableState<ByteArray?>,
    selectedRequest: MutableState<RequestPickerEntry>,
    selectConnectionMethod: suspend (connectionMethods: List<ConnectionMethod>) -> ConnectionMethod?
) {
    val deviceEngagement = EngagementParser(encodedDeviceEngagement.toByteArray()).parse()
    val eDeviceKey = deviceEngagement.eSenderKey
    val eReaderKey = Crypto.createEcPrivateKey(EcCurve.P256)

    val transport = if (existingTransport != null) {
        existingTransport
    } else {
        val connectionMethods = ConnectionMethod.disambiguate(deviceEngagement.connectionMethods)
        val connectionMethod = if (connectionMethods.size == 1) {
            connectionMethods[0]
        } else {
            selectConnectionMethod(connectionMethods)
        }
        if (connectionMethod == null) {
            // If user canceled
            return
        }
        MdocTransportFactory.Default.createTransport(
            connectionMethod,
            MdocTransport.Role.MDOC_READER,
            MdocTransportOptions(bleUseL2CAP = bleUseL2CAP)
        )
    }
    readerTransport.value = transport
    val encodedSessionTranscript = TestAppUtils.generateEncodedSessionTranscript(
        encodedDeviceEngagement.toByteArray(),
        handover,
        eReaderKey.publicKey
    )
    val sessionEncryption = SessionEncryption(
        SessionEncryption.Role.MDOC_READER,
        eReaderKey,
        eDeviceKey,
        encodedSessionTranscript,
    )
    readerSessionEncryption.value = sessionEncryption
    readerSessionTranscript.value = encodedSessionTranscript
    val encodedDeviceRequest = TestAppUtils.generateEncodedDeviceRequest(
        selectedRequest.value.sampleRequest,
        encodedSessionTranscript
    )
    try {
        transport.open(eDeviceKey)
        transport.sendMessage(
            sessionEncryption.encryptMessage(
                messagePlaintext = encodedDeviceRequest,
                statusCode = null
            )
        )
        while (true) {
            val sessionData = transport.waitForMessage()
            if (sessionData.isEmpty()) {
                showToast("Received transport-specific session termination message from holder")
                transport.close()
                break
            }

            val (message, status) = sessionEncryption.decryptMessage(sessionData)
            Logger.i(TAG, "Holder sent ${message?.size} bytes status $status")
            if (message != null) {
                readerMostRecentDeviceResponse.value = message
            }
            if (status == Constants.SESSION_DATA_STATUS_SESSION_TERMINATION) {
                showToast("Received session termination message from holder")
                Logger.i(TAG, "Holder indicated they closed the connection. " +
                        "Closing and ending reader loop")
                transport.close()
                break
            }
            if (!allowMultipleRequests) {
                showToast("Response received, closing connection")
                Logger.i(TAG, "Holder did not indicate they are closing the connection. " +
                        "Auto-close is enabled, so sending termination message, closing, and " +
                        "ending reader loop")
                transport.sendMessage(SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION))
                transport.close()
                break
            }
            showToast("Response received, keeping connection open")
            Logger.i(TAG, "Holder did not indicate they are closing the connection. " +
                    "Auto-close is not enabled so waiting for message from holder")
            // "Send additional request" and close buttons will act further on `transport`
        }
    } catch (_: MdocTransportClosedException) {
        // Nothing to do, this is thrown when transport.close() is called from another coroutine, that
        // is, the onClick handlers for the close buttons.
        Logger.i(TAG, "Ending reader flow due to MdocTransportClosedException")
    } catch (error: Throwable) {
        Logger.e(TAG, "Caught exception", error)
        error.printStackTrace()
        showToast("Error: ${error.message}")
    } finally {
        transport.close()
        readerTransport.value = null
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RequestPicker(
    availableRequests: List<RequestPickerEntry>,
    comboBoxSelected: MutableState<RequestPickerEntry>,
    comboBoxExpanded: MutableState<Boolean>,
    onRequestSelected: (request: RequestPickerEntry) -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                modifier = Modifier.padding(end = 16.dp),
                text = "mDL Data Elements to Request"
            )

            ExposedDropdownMenuBox(
                expanded = comboBoxExpanded.value,
                onExpandedChange = {
                    comboBoxExpanded.value = !comboBoxExpanded.value
                }
            ) {
                TextField(
                    value = comboBoxSelected.value.displayName,
                    onValueChange = {},
                    readOnly = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = comboBoxExpanded.value) },
                    modifier = Modifier.menuAnchor()
                )

                ExposedDropdownMenu(
                    expanded = comboBoxExpanded.value,
                    onDismissRequest = { comboBoxExpanded.value = false }
                ) {
                    availableRequests.forEach { item ->
                        DropdownMenuItem(
                            text = { Text(text = item.displayName) },
                            onClick = {
                                comboBoxSelected.value = item
                                comboBoxExpanded.value = false
                                onRequestSelected(comboBoxSelected.value)
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ShowReaderResults(
    readerMostRecentDeviceResponse: MutableState<ByteArray?>,
    readerSessionTranscript: MutableState<ByteArray?>,
) {
    val deviceResponse = readerMostRecentDeviceResponse.value
    if (deviceResponse == null || deviceResponse.isEmpty()) {
        Text(
            text = "Waiting for data",
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Bold,
        )
    } else {
        val parser = DeviceResponseParser(deviceResponse, readerSessionTranscript.value!!)
        val deviceResponse = parser.parse()
        if (deviceResponse.documents.isEmpty()) {
            Text(
                text = "No documents in response",
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Bold,
            )
        } else {
            // TODO: show multiple documents
            val documentData = DocumentData.fromMdocDeviceResponseDocument(
                deviceResponse.documents[0],
                TestAppUtils.documentTypeRepository,
                TestAppUtils.issuerTrustManager
            )
            ShowDocumentData(documentData, 0, deviceResponse.documents.size)
        }
    }
}

@Composable
private fun ShowKeyValuePair(kvPair: DocumentKeyValuePair) {
    Column(
        Modifier
            .padding(8.dp)
            .fillMaxWidth()) {
        Text(
            text = kvPair.key,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            text = kvPair.textValue,
            style = MaterialTheme.typography.bodyMedium
        )
        if (kvPair.bitmap != null) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Image(
                    bitmap = kvPair.bitmap,
                    modifier = Modifier.size(200.dp),
                    contentDescription = null
                )
            }

        }
    }
}

@Composable
private fun ShowDocumentData(
    documentData: DocumentData,
    documentIndex: Int,
    numDocuments: Int
) {
    Column(
        Modifier
            .padding(8.dp)
            .verticalScroll(rememberScrollState())
    ) {

        for (text in documentData.infoTexts) {
            InfoCard(text)
        }
        for (text in documentData.warningTexts) {
            WarningCard(text)
        }

        if (numDocuments > 1) {
            ShowKeyValuePair(
                DocumentKeyValuePair(
                    "Document Number",
                    "${documentIndex + 1} of $numDocuments"
                )
            )
        }

        for (kvPair in documentData.kvPairs) {
            ShowKeyValuePair(kvPair)
        }

    }
}

// TODO:
//  - add infos/warnings according to TrustManager (need to port TrustManager to KMP), that is
//    add a warning if the issuer isn't well-known.
//  - move to identity-appsupport
//  - add fromSdJwtVcResponse()
private data class DocumentData(
    val infoTexts: List<String>,
    val warningTexts: List<String>,
    val kvPairs: List<DocumentKeyValuePair>
) {
    companion object {

        fun fromMdocDeviceResponseDocument(
            document: DeviceResponseParser.Document,
            documentTypeRepository: DocumentTypeRepository,
            issuerTrustManager: TrustManager
        ): DocumentData {
            val infos = mutableListOf<String>()
            val warnings = mutableListOf<String>()
            val kvPairs = mutableListOf<DocumentKeyValuePair>()

            if (document.issuerSignedAuthenticated) {
                val trustResult = issuerTrustManager.verify(document.issuerCertificateChain.certificates)
                if (trustResult.isTrusted) {
                    infos.add("Issuer '${trustResult.trustPoints[0].displayName}' is in a trust list")
                } else {
                    warnings.add("Issuer is not in trust list")
                }
            }
            if (!document.deviceSignedAuthenticated) {
                warnings.add("Device Authentication failed")
            }
            if (!document.issuerSignedAuthenticated) {
                warnings.add("Issuer Authentication failed")
            }
            if (document.numIssuerEntryDigestMatchFailures > 0) {
                warnings.add("One or more issuer provided data elements failed to authenticate")
            }
            val now = Clock.System.now()
            if (now < document.validityInfoValidFrom || now > document.validityInfoValidUntil) {
                warnings.add("Document information is not valid at this point in time.")
            }

            kvPairs.add(DocumentKeyValuePair("Type", "ISO mdoc (ISO/IEC 18013-5:2021)"))
            kvPairs.add(DocumentKeyValuePair("DocType", document.docType))
            kvPairs.add(DocumentKeyValuePair("Valid From", formatTime(document.validityInfoValidFrom)))
            kvPairs.add(DocumentKeyValuePair("Valid Until", formatTime(document.validityInfoValidUntil)))
            kvPairs.add(DocumentKeyValuePair("Signed At", formatTime(document.validityInfoSigned)))
            kvPairs.add(DocumentKeyValuePair(
                "Expected Update",
                document.validityInfoExpectedUpdate?.let { formatTime(it) } ?: "Not Set"
            ))

            val mdocType = documentTypeRepository.getDocumentTypeForMdoc(document.docType)?.mdocDocumentType

            // TODO: Handle DeviceSigned data
            for (namespaceName in document.issuerNamespaces) {
                val mdocNamespace = if (mdocType !=null) {
                    mdocType.namespaces.get(namespaceName)
                } else {
                    // Some DocTypes not known by [documentTypeRepository] - could be they are
                    // private or was just never added - may use namespaces from existing
                    // DocTypes... support that as well.
                    //
                    documentTypeRepository.getDocumentTypeForMdocNamespace(namespaceName)
                        ?.mdocDocumentType?.namespaces?.get(namespaceName)
                }

                kvPairs.add(DocumentKeyValuePair("Namespace", namespaceName))
                for (dataElementName in document.getIssuerEntryNames(namespaceName)) {
                    val mdocDataElement = mdocNamespace?.dataElements?.get(dataElementName)
                    val encodedDataElementValue = document.getIssuerEntryData(namespaceName, dataElementName)
                    val dataElement = Cbor.decode(encodedDataElementValue)
                    var bitmap: ImageBitmap? = null
                    val (key, value) = if (mdocDataElement != null) {
                        if (dataElement is Bstr &&
                            mdocDataElement.attribute.type == DocumentAttributeType.Picture) {
                            try {
                                bitmap = decodeImage((dataElement as Bstr).value)
                            } catch (e: Throwable) {
                                Logger.w(TAG, "Error decoding image for data element $dataElement in " +
                                        "namespace $namespaceName", e)
                            }
                        }
                        Pair(
                            mdocDataElement.attribute.displayName,
                            mdocDataElement.renderValue(dataElement)
                        )
                    } else {
                        Pair(
                            dataElementName,
                            Cbor.toDiagnostics(
                                dataElement, setOf(
                                    DiagnosticOption.PRETTY_PRINT,
                                    DiagnosticOption.EMBEDDED_CBOR,
                                    DiagnosticOption.BSTR_PRINT_LENGTH,
                                )
                            )
                        )
                    }
                    kvPairs.add(DocumentKeyValuePair(key, value, bitmap = bitmap))
                }
            }
            return DocumentData(infos, warnings, kvPairs)
        }
    }
}

private data class DocumentKeyValuePair(
    val key: String,
    val textValue: String,
    val bitmap: ImageBitmap? = null
)

private fun formatTime(instant: Instant): String {
    val tz = TimeZone.currentSystemDefault()
    val isoStr = instant.toLocalDateTime(tz).format(LocalDateTime.Formats.ISO)
    // Get rid of the middle 'T'
    return isoStr.substring(0, 10) + " " + isoStr.substring(11)
}


