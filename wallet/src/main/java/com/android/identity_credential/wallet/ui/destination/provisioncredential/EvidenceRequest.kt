package com.android.identity_credential.wallet.ui.destination.provisioncredential

import android.Manifest
import android.content.Context
import android.os.Build
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.android.identity.document.DocumentStore
import com.android.identity.issuance.evidence.EvidenceRequestCreatePassphrase
import com.android.identity.issuance.evidence.EvidenceRequestGermanEid
import com.android.identity.issuance.evidence.EvidenceRequestIcaoNfcTunnel
import com.android.identity.issuance.evidence.EvidenceRequestIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceRequestMessage
import com.android.identity.issuance.evidence.EvidenceRequestNotificationPermission
import com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice
import com.android.identity.issuance.evidence.EvidenceRequestQuestionString
import com.android.identity.issuance.evidence.EvidenceResponseGermanEid
import com.android.identity.issuance.evidence.EvidenceResponseIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceResponseMessage
import com.android.identity.issuance.evidence.EvidenceResponseNotificationPermission
import com.android.identity.issuance.remote.WalletServerProvider
import com.android.identity.mrtd.MrtdNfc
import com.android.identity.mrtd.MrtdNfcDataReader
import com.android.identity.mrtd.MrtdNfcReader
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity_credential.wallet.NfcTunnelScanner
import com.android.identity_credential.wallet.PermissionTracker
import com.android.identity_credential.wallet.ProvisioningViewModel
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.ui.RichTextSnippet
import com.android.identity_credential.wallet.ui.prompt.passphrase.PassphraseEntryField
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch


private const val TAG = "EvidenceRequest"

@Composable
fun EvidenceRequestMessageView(
    evidenceRequest: EvidenceRequestMessage,
    provisioningViewModel: ProvisioningViewModel,
    walletServerProvider: WalletServerProvider,
    documentStore: DocumentStore
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        RichTextSnippet(
                modifier = Modifier.padding(8.dp),
                content = evidenceRequest.message,
                assets = evidenceRequest.assets
            )
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        val rejectButtonText = evidenceRequest.rejectButtonText
        if (rejectButtonText != null) {
            Button(
                modifier = Modifier.padding(8.dp),
                onClick = {
                    provisioningViewModel.provideEvidence(
                        evidence = EvidenceResponseMessage(false),
                        walletServerProvider = walletServerProvider,
                        documentStore = documentStore
                    )
            }) {
                Text(rejectButtonText)
            }
        }
        Button(
            modifier = Modifier.padding(8.dp),
            onClick = {
                provisioningViewModel.provideEvidence(
                    evidence = EvidenceResponseMessage(true),
                    walletServerProvider = walletServerProvider,
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
    walletServerProvider: WalletServerProvider,
    documentStore: DocumentStore
) {

    // Only need to request POST_NOTIFICATIONS permission if on Android 13 (Tiramisu) or later.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        // TODO: This is a hack, this check should be done in the model instead of here.
        SideEffect {
            provisioningViewModel.provideEvidence(
                evidence = EvidenceResponseNotificationPermission(true),
                walletServerProvider = walletServerProvider,
                documentStore = documentStore
            )
        }
        return
    }

    val postNotificationsPermissionState = rememberPermissionState(Manifest.permission.POST_NOTIFICATIONS)
    if (postNotificationsPermissionState.status.isGranted) {
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseNotificationPermission(true),
            walletServerProvider = walletServerProvider,
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
                RichTextSnippet(
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
                            walletServerProvider = walletServerProvider,
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
        RichTextSnippet(
            modifier = Modifier.padding(8.dp),
            content = evidenceRequest.message,
            assets = evidenceRequest.assets
        )
    }

    var inputText by remember { mutableStateOf(evidenceRequest.defaultValue) }
    TextField(
        value = inputText,
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp),
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
fun EvidenceRequestCreatePassphraseView(
    context: Context,
    evidenceRequest: EvidenceRequestCreatePassphrase,
    onAccept: (String) -> Unit
) {
    val scope = rememberCoroutineScope()
    var chosenPassphrase by remember { mutableStateOf("") }
    var verifiedPassphrase by remember { mutableStateOf("") }
    var showMatchErrorText by remember { mutableStateOf(false) }

    val constraints = evidenceRequest.passphraseConstraints

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        if (chosenPassphrase.isEmpty()) {
            RichTextSnippet(
                modifier = Modifier.padding(8.dp),
                content = evidenceRequest.message,
                assets = evidenceRequest.assets
            )
        } else {
            RichTextSnippet(
                modifier = Modifier.padding(8.dp),
                content = evidenceRequest.verifyMessage,
                assets = evidenceRequest.assets
            )
        }
    }

    if (chosenPassphrase.isEmpty()) {
        // Choose PIN
        var currentPassphraseMeetsRequirements by remember { mutableStateOf(false) }
        var currentPassphrase by remember { mutableStateOf("") }
        PassphraseEntryField(
            constraints = constraints,
            checkWeakPassphrase = true,
            onChanged = { passphrase, passphraseMeetsRequirements, donePressed ->
                currentPassphrase = passphrase
                currentPassphraseMeetsRequirements = passphraseMeetsRequirements
                val isFixedLength = (constraints.minLength == constraints.maxLength)
                if (isFixedLength && currentPassphraseMeetsRequirements) {
                    chosenPassphrase = passphrase
                } else if (donePressed) {
                    chosenPassphrase = passphrase
                }
            }
        )

        if (constraints.minLength != constraints.maxLength) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                Button(
                    enabled = currentPassphraseMeetsRequirements,
                    onClick = { chosenPassphrase = currentPassphrase }
                ) {
                    Text(stringResource(id = R.string.evidence_create_passphrase_next))
                }
            }
        }
    } else if (verifiedPassphrase.isEmpty()) {
        // Verify PIN
        var currentPassphrase by remember { mutableStateOf("") }
        PassphraseEntryField(
            constraints = constraints,
            checkWeakPassphrase = false,
            onChanged = { passphrase, passphraseMeetsRequirements, donePressed ->
                currentPassphrase = passphrase
                val isFixedLength = (constraints.minLength == constraints.maxLength)
                if (isFixedLength && currentPassphrase.length == constraints.minLength) {
                    verifiedPassphrase = passphrase
                } else if (donePressed) {
                    verifiedPassphrase = passphrase
                }
            }
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            Spacer(modifier = Modifier.weight(1.0f))
            if (constraints.minLength != constraints.maxLength) {
                Button(
                    onClick = { verifiedPassphrase = currentPassphrase },
                ) {
                    Text(stringResource(id = R.string.evidence_create_passphrase_confirm))
                }
            }
        }
    } else {
        if (chosenPassphrase == verifiedPassphrase) {
            onAccept(chosenPassphrase)
            return
        } else {
            showMatchErrorText = true
            PassphraseEntryField(
                constraints = constraints,
                checkWeakPassphrase = false,
                onChanged = { passphrase, passphraseMeetsRequirements, donePressed ->
                }
            )
            SideEffect {
                scope.launch {
                    delay(2000)
                    verifiedPassphrase = ""
                    showMatchErrorText = false
                }
            }
        }
    }

    val matchErrorText = if (showMatchErrorText) {
        if (constraints.requireNumerical) {
             context.getString(R.string.evidence_create_passphrase_no_match_pin)
        } else {
            context.getString(R.string.evidence_create_passphrase_no_match)
        }
    } else ""
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp),
        horizontalArrangement = Arrangement.Center,
    ) {
        Text(
            text = matchErrorText,
            color = Color.Red
        )
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
        RichTextSnippet(
            modifier = Modifier.padding(8.dp),
            content = evidenceRequest.message,
            assets = evidenceRequest.assets
        )
    }

    val radioOptions = evidenceRequest.possibleValues
    val radioOptionsKeys = radioOptions.keys.toList()
    val (selectedOption, onOptionSelected) = remember { mutableStateOf(0) }
    Column {
        radioOptions.forEach { entry ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = (entry.key == radioOptionsKeys[selectedOption]),
                        onClick = {
                            onOptionSelected(radioOptionsKeys.indexOf(entry.key))
                        }
                    )
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(
                    selected = (entry.key == radioOptionsKeys[selectedOption]),
                    onClick = { onOptionSelected(radioOptionsKeys.indexOf(entry.key)) }
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
            onAccept(radioOptionsKeys[selectedOption])
            // Reset to first choice, for the next time this is used
            onOptionSelected(0)
        }) {
            Text(evidenceRequest.acceptButtonText)
        }
    }

}

@Composable
fun EvidenceRequestIcaoPassiveAuthenticationView(
    evidenceRequest: EvidenceRequestIcaoPassiveAuthentication,
    provisioningViewModel: ProvisioningViewModel,
    walletServerProvider: WalletServerProvider,
    documentStore: DocumentStore,
    permissionTracker: PermissionTracker
) {
    EvidenceRequestIcaoView(
        MrtdNfcDataReader(evidenceRequest.requestedDataGroups),
        permissionTracker,
        IcaoMrtdCommunicationModel.Route.CAMERA_SCAN
    ) { nfcData ->
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseIcaoPassiveAuthentication(nfcData.dataGroups, nfcData.sod),
            walletServerProvider = walletServerProvider,
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
    val tunnelScanner = NfcTunnelScanner(provisioningViewModel)
    // Start with the camera scan only if it was requested
    val initialRoute =
        if (evidenceRequest.passThrough) {
            // Issuing server requested pass-through, it will handle encryption itself.
            IcaoMrtdCommunicationModel.Route.NFC_SCAN
        } else {
            // Need to establish initial secure channel on the client by BAC or PACE using
            // data scanned from passport MRZ strip.
            IcaoMrtdCommunicationModel.Route.CAMERA_SCAN
        }
    EvidenceRequestIcaoView(tunnelScanner, permissionTracker, initialRoute) {
        provisioningViewModel.finishTunnel()
    }
}

@Composable
fun <ResultT> EvidenceRequestIcaoView(
    reader: MrtdNfcReader<ResultT>,
    permissionTracker: PermissionTracker,
    initialRoute: IcaoMrtdCommunicationModel.Route,
    onResult: (ResultT) -> Unit
) {
    val requiredPermissions = if (initialRoute == IcaoMrtdCommunicationModel.Route.CAMERA_SCAN) {
        listOf(Manifest.permission.CAMERA, Manifest.permission.NFC)
    } else {
        listOf(Manifest.permission.NFC)
    }
    permissionTracker.PermissionCheck(requiredPermissions) {
        val navController = rememberNavController()
        val icaoCommunication = rememberIcaoMrtdCommunicationModel(reader, navController, onResult)
        NavHost(navController = navController, startDestination = initialRoute.route ) {
            composable(IcaoMrtdCommunicationModel.Route.CAMERA_SCAN.route) {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = stringResource(R.string.evidence_camera_scan_mrz_title),
                            modifier = Modifier.padding(16.dp),
                            textAlign = TextAlign.Center,
                            style = MaterialTheme.typography.titleLarge
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                            text = stringResource(R.string.evidence_camera_scan_mrz_instruction),
                            style = MaterialTheme.typography.bodyLarge
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .fillMaxHeight(),
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
                                        icaoCommunication.launchCameraScan(surfaceProvider)
                                    }
                                }
                            }
                        )
                    }
                }
            }

            composable(IcaoMrtdCommunicationModel.Route.NFC_SCAN.route) {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = stringResource(R.string.evidence_nfc_scan_title),
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(8.dp),
                            style = MaterialTheme.typography.titleLarge
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            style = MaterialTheme.typography.bodyLarge,
                            text = when (icaoCommunication.status.value) {
                                is MrtdNfc.Initial -> stringResource(R.string.nfc_status_initial)
                                is MrtdNfc.Connected -> stringResource(R.string.nfc_status_connected)
                                is MrtdNfc.AttemptingPACE -> stringResource(R.string.nfc_status_attempting_pace)
                                is MrtdNfc.PACESucceeded -> stringResource(R.string.nfc_status_pace_succeeded)
                                is MrtdNfc.PACENotSupported -> stringResource(R.string.nfc_status_pace_not_supported)
                                is MrtdNfc.PACEFailed -> stringResource(R.string.nfc_status_pace_failed)
                                is MrtdNfc.AttemptingBAC -> stringResource(R.string.nfc_status_attempting_bac)
                                is MrtdNfc.BACSucceeded -> stringResource(R.string.nfc_status_bac_succeeded)
                                is MrtdNfc.ReadingData -> {
                                    val s = icaoCommunication.status.value as MrtdNfc.ReadingData
                                    stringResource(
                                        R.string.nfc_status_reading_data,
                                        s.progressPercent
                                    )
                                }

                                is MrtdNfc.TunnelAuthenticating -> {
                                    val s =
                                        icaoCommunication.status.value as MrtdNfc.TunnelAuthenticating
                                    stringResource(
                                        R.string.nfc_status_tunnel_authenticating,
                                        s.progressPercent
                                    )
                                }

                                is MrtdNfc.TunnelReading -> {
                                    val s = icaoCommunication.status.value as MrtdNfc.TunnelReading
                                    stringResource(
                                        R.string.nfc_status_tunnel_reading_data,
                                        s.progressPercent
                                    )
                                }

                                is MrtdNfc.Finished -> stringResource(R.string.nfc_status_finished)
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun EvidenceRequestEIdView(
    evidenceRequest: EvidenceRequestGermanEid,
    provisioningViewModel: ProvisioningViewModel,
    walletServerProvider: WalletServerProvider,
    documentStore: DocumentStore,
    permissionTracker: PermissionTracker
) {
    AusweisView(
        evidenceRequest.optionalComponents,
        permissionTracker
    ) { evidence ->
        provisioningViewModel.provideEvidence(
            evidence = evidence,
            walletServerProvider = walletServerProvider,
            documentStore = documentStore
        )
    }
}

@Composable
fun AusweisView(
    requiredComponents: List<String>,
    permissionTracker: PermissionTracker,
    onResult: (evidence: EvidenceResponseGermanEid) -> Unit
) {
    val navController = rememberNavController()
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val status = remember { mutableStateOf<AusweisModel.Status?>(null) }
    val model = remember {
        AusweisModel(
            context,
            status,
            navController,
            requiredComponents,
            coroutineScope,
            onResult
        )
    }
    NavHost(navController = navController, startDestination = AusweisModel.Route.INITIAL.route) {
        composable(AusweisModel.Route.INITIAL.route) {
            Column {
                val ready = status.value != null
                val started = ready && status.value !is AusweisModel.Ready
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = stringResource(
                            if (started) {
                                R.string.eid_status_started
                            } else if (ready) {
                                R.string.eid_status_ready
                            } else {
                                R.string.eid_status_preparing
                            }
                        ),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(
                        enabled = ready && !started,
                        onClick = { model.startWorkflow(false) }
                    ) {
                        Text(stringResource(R.string.eid_start_workflow))
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(
                        enabled = ready && !started,
                        onClick = { model.startWorkflow(true) }
                    ) {
                        Text(stringResource(R.string.eid_start_workflow_with_simulator))
                    }
                }
            }
        }
        composable(AusweisModel.Route.ACCESS_RIGHTS.route) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = stringResource(R.string.eid_access_rights_title),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge
                    )
                }
                val statusValue = status.value
                if (statusValue is AusweisModel.AccessRights) {
                    for (component in statusValue.components) {
                        Text(
                            when (component) {
                                "GivenNames" -> stringResource(R.string.eid_access_right_first_name)
                                "FamilyName" -> stringResource(R.string.eid_access_right_last_name)
                                "BirthName" -> stringResource(R.string.eid_access_right_maiden_name)
                                "DateOfBirth" -> stringResource(R.string.eid_access_right_date_of_birth)
                                // TODO: all others
                                else -> "Item [$component]"
                            },
                            modifier = Modifier.padding(8.dp, 0.dp)
                        )
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(onClick = { model.acceptAccess() }) {
                        Text(stringResource(R.string.eid_access_right_allow))
                    }
                }
            }
        }
        composable(AusweisModel.Route.CARD_SCAN.route) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = stringResource(R.string.eid_nfc_scanning),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge
                    )
                }
                val statusValue = status.value
                if (statusValue is AusweisModel.Auth) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Progress: ${statusValue.progress}%",
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(8.dp),
                            style = MaterialTheme.typography.bodyLarge
                        )
                    }
                }
            }
        }
        composable(AusweisModel.Route.PIN_ENTRY.route) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = stringResource(R.string.eid_enter_pin),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    PassphraseEntryField(
                        constraints = PassphraseConstraints.PIN_SIX_DIGITS,
                        checkWeakPassphrase = false
                    ) { passphrase, meetsRequirements, _ ->
                        if (meetsRequirements) {
                            model.providePin(passphrase)
                        }
                    }
                }
            }
        }
        composable(AusweisModel.Route.ERROR.route) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = stringResource(
                            if (status.value == AusweisModel.NetworkError) {
                                R.string.eid_network_error
                            } else {
                                R.string.eid_generic_error
                            }),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(onClick = { model.tryAgain() }) {
                        Text(stringResource(R.string.eid_try_again))
                    }
                }
            }
        }
    }
}
