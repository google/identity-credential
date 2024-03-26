package com.android.identity_credential.wallet.ui.destination.provisioncredential

import android.Manifest
import android.os.Build
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.android.identity.document.DocumentStore
import com.android.identity.issuance.IssuingAuthorityRepository
import com.android.identity.issuance.evidence.EvidenceRequestIcaoNfcTunnel
import com.android.identity.issuance.evidence.EvidenceRequestIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceRequestMessage
import com.android.identity.issuance.evidence.EvidenceRequestNotificationPermission
import com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice
import com.android.identity.issuance.evidence.EvidenceRequestQuestionString
import com.android.identity.issuance.evidence.EvidenceResponseIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceResponseMessage
import com.android.identity.issuance.evidence.EvidenceResponseNotificationPermission
import com.android.identity.util.Logger
import com.android.identity_credential.mrtd.MrtdMrzScanner
import com.android.identity_credential.mrtd.MrtdNfc
import com.android.identity_credential.mrtd.MrtdNfcDataReader
import com.android.identity_credential.mrtd.MrtdNfcReader
import com.android.identity_credential.mrtd.MrtdNfcScanner
import com.android.identity_credential.wallet.NfcTunnelScanner
import com.android.identity_credential.wallet.PermissionTracker
import com.android.identity_credential.wallet.ProvisioningViewModel
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.ui.MarkdownText
import com.android.identity_credential.wallet.util.getActivity
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import kotlinx.coroutines.launch


private const val TAG = "EvidenceRequest"

@Composable
fun EvidenceRequestMessageView(
    evidenceRequest: EvidenceRequestMessage,
    provisioningViewModel: ProvisioningViewModel,
    issuingAuthorityRepository: IssuingAuthorityRepository,
    documentStore: DocumentStore
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        MarkdownText(
                modifier = Modifier.padding(8.dp),
                content = evidenceRequest.message,
                assets = evidenceRequest.assets
            )
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        if (evidenceRequest.rejectButtonText != null) {
            Button(
                modifier = Modifier.padding(8.dp),
                onClick = {
                    provisioningViewModel.provideEvidence(
                        evidence = EvidenceResponseMessage(false),
                        issuingAuthorityRepository = issuingAuthorityRepository,
                        documentStore = documentStore
                    )
            }) {
                Text(evidenceRequest.rejectButtonText)
            }
        }
        Button(
            modifier = Modifier.padding(8.dp),
            onClick = {
                provisioningViewModel.provideEvidence(
                    evidence = EvidenceResponseMessage(true),
                    issuingAuthorityRepository = issuingAuthorityRepository,
                    documentStore = documentStore
                )
        }) {
            Text(evidenceRequest.acceptButtonText)
        }
    }
}

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun EvidenceRequestNotificationPermissionView(
    evidenceRequest: EvidenceRequestNotificationPermission,
    provisioningViewModel: ProvisioningViewModel,
    issuingAuthorityRepository: IssuingAuthorityRepository,
    documentStore: DocumentStore
) {

    // Only need to request POST_NOTIFICATIONS permission if on Android 13 (Tiramisu) or later.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        // TODO: This is a hack, this check should be done in the model instead of here.
        SideEffect {
            provisioningViewModel.provideEvidence(
                evidence = EvidenceResponseNotificationPermission(true),
                issuingAuthorityRepository = issuingAuthorityRepository,
                documentStore = documentStore
            )
        }
        return
    }

    val postNotificationsPermissionState = rememberPermissionState(Manifest.permission.POST_NOTIFICATIONS)
    if (postNotificationsPermissionState.status.isGranted) {
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseNotificationPermission(true),
            issuingAuthorityRepository = issuingAuthorityRepository,
            documentStore = documentStore
        )
    } else {
        Column {
            // We always show the rationale to the user so not need to key off
            // postNotificationsPermissionState.status.shouldShowRationale, just
            // always show it.

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                MarkdownText(
                    modifier = Modifier.padding(8.dp),
                    content = evidenceRequest.permissionNotGrantedMessage,
                    assets = evidenceRequest.assets
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Button(
                    modifier = Modifier.padding(8.dp),
                    onClick = {
                        provisioningViewModel.provideEvidence(
                            evidence = EvidenceResponseNotificationPermission(false),
                            issuingAuthorityRepository = issuingAuthorityRepository,
                            documentStore = documentStore
                        )
                    }) {
                    Text(evidenceRequest.continueWithoutPermissionButtonText)
                }
                Button(
                    modifier = Modifier.padding(8.dp),
                    onClick = {
                        postNotificationsPermissionState.launchPermissionRequest()
                    }) {
                    Text(evidenceRequest.grantPermissionButtonText)
                }
            }
        }
    }

}

@Composable
fun EvidenceRequestQuestionStringView(
    evidenceRequest: EvidenceRequestQuestionString,
    onAccept: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        MarkdownText(
            modifier = Modifier.padding(8.dp),
            content = evidenceRequest.message,
            assets = evidenceRequest.assets
        )
    }

    var inputText by remember { mutableStateOf(evidenceRequest.defaultValue) }
    TextField(
        value = inputText,
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        onValueChange = { inputText = it },
        label = { Text(stringResource(R.string.evidence_question_label_answer)) }
    )

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        Button(onClick = {
            onAccept(inputText)
        }) {
            Text(evidenceRequest.acceptButtonText)
        }
    }

}

@Composable
fun EvidenceRequestQuestionMultipleChoiceView(
    evidenceRequest: EvidenceRequestQuestionMultipleChoice,
    onAccept: (String) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        MarkdownText(
            modifier = Modifier.padding(8.dp),
            content = evidenceRequest.message,
            assets = evidenceRequest.assets
        )
    }

    val radioOptions = evidenceRequest.possibleValues
    val (selectedOption, onOptionSelected) = remember {
        mutableStateOf(radioOptions.keys.iterator().next())
    }
    Column {
        radioOptions.forEach { entry ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = (entry.key == selectedOption),
                        onClick = {
                            onOptionSelected(entry.key)
                        }
                    )
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(
                    selected = (entry.key == selectedOption),
                    onClick = { onOptionSelected(entry.key) }
                )
                Text(
                    text = entry.value,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
        }
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        Button(onClick = {
            onAccept(selectedOption)
        }) {
            Text(evidenceRequest.acceptButtonText)
        }
    }

}

@Composable
fun EvidenceRequestIcaoPassiveAuthenticationView(
    evidenceRequest: EvidenceRequestIcaoPassiveAuthentication,
    provisioningViewModel: ProvisioningViewModel,
    issuingAuthorityRepository: IssuingAuthorityRepository,
    documentStore: DocumentStore,
    permissionTracker: PermissionTracker
) {
    EvidenceRequestIcaoView(
        MrtdNfcDataReader(evidenceRequest.requestedDataGroups),
        permissionTracker
    ) { nfcData ->
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseIcaoPassiveAuthentication(nfcData.dataGroups, nfcData.sod),
            issuingAuthorityRepository = issuingAuthorityRepository,
            documentStore = documentStore
        )
    }
}

@Composable
fun EvidenceRequestIcaoNfcTunnelView(
    evidenceRequest: EvidenceRequestIcaoNfcTunnel,
    provisioningViewModel: ProvisioningViewModel,
    permissionTracker: PermissionTracker
) {
    EvidenceRequestIcaoView(NfcTunnelScanner(provisioningViewModel), permissionTracker) {
        provisioningViewModel.finishTunnel()
    }
}

@Composable
fun <ResultT> EvidenceRequestIcaoView(
    reader: MrtdNfcReader<ResultT>,
    permissionTracker: PermissionTracker,
    onResult: (ResultT) -> Unit
) {
    val requiredPermissions = listOf(Manifest.permission.CAMERA, Manifest.permission.NFC)
    permissionTracker.PermissionCheck(requiredPermissions) {
        var visualScan by remember { mutableStateOf(true) }  // start with visual scan
        var status by remember { mutableStateOf<MrtdNfc.Status>(MrtdNfc.Initial) }
        val scope = rememberCoroutineScope()
        if (visualScan) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = stringResource(R.string.evidence_camera_scan_mrz_title),
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.titleLarge)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                    text = stringResource(R.string.evidence_camera_scan_mrz_instruction),
                    style = MaterialTheme.typography.bodyLarge)
            }
            Row(
                modifier = Modifier.fillMaxWidth().fillMaxHeight(),
                horizontalArrangement = Arrangement.Center
            ) {
                AndroidView(
                    modifier = Modifier.padding(16.dp),
                    factory = { context ->
                        PreviewView(context).apply {
                            layoutParams = LinearLayout.LayoutParams(
                                ViewGroup.LayoutParams.MATCH_PARENT,
                                ViewGroup.LayoutParams.MATCH_PARENT
                            )
                            scaleType = PreviewView.ScaleType.FILL_START
                            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                            post {
                                scope.launch {
                                    val activity = context.getActivity()!!
                                    val passportCapture = MrtdMrzScanner(activity)
                                    val passportNfcScanner = MrtdNfcScanner(activity)
                                    try {
                                        val mrzInfo =
                                            passportCapture.readFromCamera(surfaceProvider)
                                        status = MrtdNfc.Initial
                                        visualScan = false
                                        val result =
                                            passportNfcScanner.scanCard(mrzInfo, reader) { st ->
                                                status = st
                                            }
                                        onResult(result)
                                    } catch (err: Exception) {
                                        Logger.e(TAG, "Error scanning MRTD: $err")
                                    }
                                }
                            }
                        }
                    }
                )
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = stringResource(R.string.evidence_nfc_scan_title),
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(8.dp),
                    style = MaterialTheme.typography.titleLarge)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    style = MaterialTheme.typography.bodyLarge,
                    text = when(status) {
                        is MrtdNfc.Initial -> stringResource(R.string.nfc_status_initial)
                        is MrtdNfc.Connected -> stringResource(R.string.nfc_status_connected)
                        is MrtdNfc.AttemptingPACE -> stringResource(R.string.nfc_status_attempting_pace)
                        is MrtdNfc.PACESucceeded -> stringResource(R.string.nfc_status_pace_succeeded)
                        is MrtdNfc.PACENotSupported -> stringResource(R.string.nfc_status_pace_not_supported)
                        is MrtdNfc.PACEFailed -> stringResource(R.string.nfc_status_pace_failed)
                        is MrtdNfc.AttemptingBAC -> stringResource(R.string.nfc_status_attempting_bac)
                        is MrtdNfc.BACSucceeded -> stringResource(R.string.nfc_status_bac_succeeded)
                        is MrtdNfc.ReadingData -> {
                            val s = status as MrtdNfc.ReadingData
                            stringResource(R.string.nfc_status_reading_data, s.progressPercent)
                        }
                        is MrtdNfc.TunnelAuthenticating -> {
                            val s = status as MrtdNfc.TunnelAuthenticating
                            stringResource(R.string.nfc_status_tunnel_authenticating, s.progressPercent)
                        }
                        is MrtdNfc.TunnelReading -> {
                            val s = status as MrtdNfc.TunnelReading
                            stringResource(R.string.nfc_status_tunnel_reading_data, s.progressPercent)
                        }
                        is MrtdNfc.Finished -> stringResource(R.string.nfc_status_finished)
                    })
            }
        }
    }
}