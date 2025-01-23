package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.android.identity.appsupport.ui.permissions.rememberBluetoothPermissionState
import com.android.identity.appsupport.ui.qrcode.ShowQrCodeDialog
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Simple
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.engagement.EngagementGenerator
import com.android.identity.appsupport.ui.presentment.MdocPresentmentMechanism
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.mdoc.transport.MdocTransportFactory
import com.android.identity.mdoc.transport.MdocTransportOptions
import com.android.identity.appsupport.ui.presentment.PresentmentModel
import com.android.identity.mdoc.transport.connectionHelper
import com.android.identity.testapp.Platform
import com.android.identity.testapp.TestAppSettingsModel
import com.android.identity.testapp.platform
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import com.android.identity.util.toBase64Url
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.ByteString

private const val TAG = "IsoMdocProximitySharingScreen"

@OptIn(ExperimentalMaterial3Api::class, ExperimentalCoroutinesApi::class)
@Composable
fun IsoMdocProximitySharingScreen(
    presentmentModel: PresentmentModel,
    settingsModel: TestAppSettingsModel,
    onNavigateToPresentmentScreen: () -> Unit,
    showToast: (message: String) -> Unit,
) {
    val blePermissionState = rememberBluetoothPermissionState()

    val showQrCode = remember { mutableStateOf<ByteString?>(null) }
    if (showQrCode.value != null && presentmentModel.state.collectAsState().value != PresentmentModel.State.PROCESSING) {
        Logger.dCbor(TAG, "DeviceEngagement:", showQrCode.value!!.toByteArray())
        val deviceEngagementQrCode = "mdoc:" + showQrCode.value!!.toByteArray().toBase64Url()
        ShowQrCodeDialog(
            title = { Text(text = "Scan QR code") },
            text = { Text(text = "Scan this QR code on another device") },
            dismissButton = "Close",
            data = deviceEngagementQrCode,
            onDismiss = {
                showQrCode.value = null
                presentmentModel.reset()
            }
        )
    }

    // NFC engagment as an mdoc is only supported on Android.
    //
    val nfcAvailable = (platform == Platform.ANDROID)

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
        val negotiatedHandoverOrder = settingsModel.presentmentNegotiatedHandoverPreferredOrder.collectAsState().value
        LazyColumn(
            modifier = Modifier.padding(8.dp)
        ) {
            item { SettingHeadline("NFC Engagement Settings") }
            item {
                if (!nfcAvailable) {
                    WarningCard("NFC Engagement as an mdoc is not supported on ${platform.displayName}")
                }
            }
            item {
                SettingToggle(
                    title = "Use NFC Static Handover",
                    isChecked = !settingsModel.presentmentUseNegotiatedHandover.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentUseNegotiatedHandover.value = !it },
                    enabled = nfcAvailable
                )
            }
            item {
                SettingToggle(
                    title = "Use NFC Negotiated Handover",
                    isChecked = settingsModel.presentmentUseNegotiatedHandover.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentUseNegotiatedHandover.value = it },
                    enabled = nfcAvailable
                )
            }
            item {
                SettingHeadline("Transports (QR and NFC Static Handover)")
            }
            item {
                SettingToggle(
                    title = "BLE (mdoc central client mode)",
                    isChecked = settingsModel.presentmentBleCentralClientModeEnabled.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentBleCentralClientModeEnabled.value = it },
                )
            }
            item {
                SettingToggle(
                    title = "BLE (mdoc peripheral server mode)",
                    isChecked = settingsModel.presentmentBlePeripheralServerModeEnabled.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentBlePeripheralServerModeEnabled.value = it },
                )
            }
            item {
                SettingHeadline("NFC Negotiated Handover Preferred Order")
            }
            for (n in negotiatedHandoverOrder.indices) {
                val prefix = negotiatedHandoverOrder[n]
                val isFirst = (n == 0)
                val isLast = (n == negotiatedHandoverOrder.size - 1)
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = prefixToDisplayNameMap[prefix] ?: prefix,
                                fontWeight = FontWeight.Normal,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                        IconButton(
                            onClick = { settingsModel.swapNegotiatedHandoverOrder(n, n - 1) },
                            enabled = !isFirst
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ArrowUpward,
                                contentDescription = null,
                            )
                        }
                        IconButton(
                            onClick = { settingsModel.swapNegotiatedHandoverOrder(n, n + 1) },
                            enabled = !isLast
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ArrowDownward,
                                contentDescription = null,
                            )
                        }
                    }
                }
            }
            item {
                SettingHeadline("Transport Options")
            }
            item {
                SettingToggle(
                    title = "Use L2CAP if available",
                    isChecked = settingsModel.presentmentBleL2CapEnabled.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentBleL2CapEnabled.value = it },
                )
            }
            item {
                SettingToggle(
                    title = "Keep connection open after first request",
                    isChecked = settingsModel.presentmentAllowMultipleRequests.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentAllowMultipleRequests.value = it },
                )
            }
            item {
                SettingHeadline("General Options")
            }
            item {
                SettingToggle(
                    title = "Skip consent prompt",
                    isChecked = !settingsModel.presentmentShowConsentPrompt.collectAsState().value,
                    onCheckedChange = { settingsModel.presentmentShowConsentPrompt.value = !it },
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
                            settingsModel.resetPresentmentSettings()
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
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(
                        onClick = {
                            presentmentModel.reset()
                            presentmentModel.setConnecting()
                            presentmentModel.presentmentScope.launch() {
                                val connectionMethods = mutableListOf<ConnectionMethod>()
                                val bleUuid = UUID.randomUUID()
                                if (settingsModel.presentmentBleCentralClientModeEnabled.value) {
                                    connectionMethods.add(
                                        ConnectionMethodBle(
                                            supportsPeripheralServerMode = false,
                                            supportsCentralClientMode = true,
                                            peripheralServerModeUuid = null,
                                            centralClientModeUuid = bleUuid,
                                        )
                                    )
                                }
                                if (settingsModel.presentmentBlePeripheralServerModeEnabled.value) {
                                    connectionMethods.add(
                                        ConnectionMethodBle(
                                            supportsPeripheralServerMode = true,
                                            supportsCentralClientMode = false,
                                            peripheralServerModeUuid = bleUuid,
                                            centralClientModeUuid = null,
                                        )
                                    )
                                }
                                val options = MdocTransportOptions(
                                    bleUseL2CAP = settingsModel.presentmentBleL2CapEnabled.value
                                )
                                if (connectionMethods.isEmpty()) {
                                    showToast("No connection methods selected")
                                } else {
                                    doHolderFlow(
                                        connectionMethods = connectionMethods,
                                        handover = Simple.NULL,
                                        options = options,
                                        allowMultipleRequests = settingsModel.presentmentAllowMultipleRequests.value,
                                        showToast = showToast,
                                        presentmentModel = presentmentModel,
                                        showQrCode = showQrCode,
                                        onNavigateToPresentationScreen = onNavigateToPresentmentScreen,
                                    )
                                }
                            }
                        },
                    ) {
                        Text(text = "Share via QR")
                    }
                }
            }
        }
    }
}

private suspend fun doHolderFlow(
    connectionMethods: List<ConnectionMethod>,
    handover: DataItem,
    options: MdocTransportOptions,
    allowMultipleRequests: Boolean,
    showToast: (message: String) -> Unit,
    presentmentModel: PresentmentModel,
    showQrCode: MutableState<ByteString?>,
    onNavigateToPresentationScreen: () -> Unit,
) {
    val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
    lateinit var encodedDeviceEngagement: ByteString
    val transport = connectionMethods.connectionHelper(
        role = MdocTransport.Role.MDOC,
        transportFactory = MdocTransportFactory.Default,
        options = options,
        eDeviceKey = eDeviceKey.publicKey,
        onConnectionMethodsReady = { advertisedConnectionMethods ->
            val engagementGenerator = EngagementGenerator(
                eSenderKey = eDeviceKey.publicKey,
                version = "1.0"
            )
            engagementGenerator.addConnectionMethods(advertisedConnectionMethods)
            encodedDeviceEngagement = ByteString(engagementGenerator.generate())
            showQrCode.value = encodedDeviceEngagement
        }
    )
    presentmentModel.setMechanism(
        MdocPresentmentMechanism(
            transport = transport,
            eDeviceKey = eDeviceKey,
            encodedDeviceEngagement = encodedDeviceEngagement,
            handover = handover,
            engagementDuration = null,
            allowMultipleRequests = allowMultipleRequests
        )
    )
    showQrCode.value = null
    onNavigateToPresentationScreen()
}

private val prefixToDisplayNameMap = mapOf<String, String>(
    "ble:central_client_mode:" to "BLE (mdoc central client mode)",
    "ble:peripheral_server_mode:" to "BLE (mdoc peripheral server mode)",
)

private fun TestAppSettingsModel.swapNegotiatedHandoverOrder(index1: Int, index2: Int) {
    val list = presentmentNegotiatedHandoverPreferredOrder.value.toMutableList()
    val tmp = list[index2]
    list[index2] = list[index1]
    list[index1] = tmp
    presentmentNegotiatedHandoverPreferredOrder.value = list
}
