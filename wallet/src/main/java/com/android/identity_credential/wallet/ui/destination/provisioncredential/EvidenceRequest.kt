package com.android.identity_credential.wallet.ui.destination.provisioncredential

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.camera.view.PreviewView
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
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
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.colorResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.android.identity.android.securearea.cloud.CloudSecureArea
import com.android.identity.appsupport.ui.PassphraseEntryField
import com.android.identity.appsupport.ui.getDefaultImageVector
import com.android.identity.documenttype.Icon
import com.android.identity.issuance.ApplicationSupport
import com.android.identity.issuance.LandingUrlUnknownException
import com.android.identity.issuance.evidence.EvidenceRequestCompletionMessage
import com.android.identity.issuance.evidence.EvidenceRequestCreatePassphrase
import com.android.identity.issuance.evidence.EvidenceRequestGermanEid
import com.android.identity.issuance.evidence.EvidenceRequestIcaoNfcTunnel
import com.android.identity.issuance.evidence.EvidenceRequestIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceRequestMessage
import com.android.identity.issuance.evidence.EvidenceRequestNotificationPermission
import com.android.identity.issuance.evidence.EvidenceRequestOpenid4Vp
import com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice
import com.android.identity.issuance.evidence.EvidenceRequestQuestionString
import com.android.identity.issuance.evidence.EvidenceRequestSelfieVideo
import com.android.identity.issuance.evidence.EvidenceRequestSetupCloudSecureArea
import com.android.identity.issuance.evidence.EvidenceRequestWeb
import com.android.identity.issuance.evidence.EvidenceResponseGermanEid
import com.android.identity.issuance.evidence.EvidenceResponseIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceResponseMessage
import com.android.identity.issuance.evidence.EvidenceResponseNotificationPermission
import com.android.identity.issuance.evidence.EvidenceResponseOpenid4Vp
import com.android.identity.issuance.evidence.EvidenceResponseSelfieVideo
import com.android.identity.issuance.evidence.EvidenceResponseWeb
import com.android.identity.issuance.remote.WalletServerProvider
import com.android.identity.mrtd.MrtdNfc
import com.android.identity.mrtd.MrtdNfcDataReader
import com.android.identity.mrtd.MrtdNfcReader
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.FaceImageClassifier
import com.android.identity_credential.wallet.NfcTunnelScanner
import com.android.identity_credential.wallet.PermissionTracker
import com.android.identity_credential.wallet.ProvisioningViewModel
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.WalletApplication
import com.android.identity_credential.wallet.presentation.UserCanceledPromptException
import com.android.identity_credential.wallet.ui.RichTextSnippet
import com.android.identity_credential.wallet.ui.SelfieRecorder
import com.android.identity_credential.wallet.util.inverse
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlin.time.Duration.Companion.seconds

private const val TAG = "EvidenceRequest"

@Composable
fun EvidenceRequestMessageView(
    evidenceRequest: EvidenceRequestMessage,
    provisioningViewModel: ProvisioningViewModel
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
                        evidence = EvidenceResponseMessage(false)
                    )
            }) {
                Text(rejectButtonText)
            }
        }
        Button(
            modifier = Modifier.padding(8.dp),
            onClick = {
                provisioningViewModel.provideEvidence(
                    evidence = EvidenceResponseMessage(true)
                )
        }) {
            Text(evidenceRequest.acceptButtonText)
        }
    }

}

/**
 * Show the "Document Scanning Complete" screen after completing all steps of for evidence gathering.
 * Since it occupies the entire visible screen real estate, this function can be appropriately
 * classified as a "Screen" (rather than a generic "View").
 */
@Composable
fun EvidenceRequestCompletedScreen(
    evidenceRequest: EvidenceRequestCompletionMessage,
    provisioningViewModel: ProvisioningViewModel
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 10.dp)
    ) {
        Icon(
            painter = painterResource(id = R.drawable.id_card),
            tint = MaterialTheme.colorScheme.background.inverse(),
            contentDescription = stringResource(
                R.string.accessibility_artwork_for,
                evidenceRequest.messageTitle
            ),
            modifier = Modifier
                .size(48.dp)
                .padding(start = 16.dp)
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(
                text = evidenceRequest.messageTitle,
                modifier = Modifier.padding(16.dp),
                textAlign = TextAlign.Left,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.headlineLarge
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Absolute.Left
        ) {
            Text(
                modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                text = evidenceRequest.message,
                style = MaterialTheme.typography.bodyLarge
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 200.dp, bottom = 150.dp),
            horizontalArrangement = Arrangement.Center
        ) {
            Icon(
                painter = painterResource(id = R.drawable.check_circled),
                tint = colorResource(id = R.color.success_green),
                modifier = Modifier.size(100.dp),
                contentDescription = stringResource(
                    R.string.accessibility_artwork_for,
                    evidenceRequest.messageTitle
                )
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End
        ) {
            Button(
                modifier = Modifier.padding(8.dp),
                onClick = {
                    provisioningViewModel.provideEvidence(
                        evidence = EvidenceResponseMessage(true)
                    )
                }) {
                Text(evidenceRequest.acceptButtonText)
            }
        }
    }
}

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun EvidenceRequestNotificationPermissionView(
    evidenceRequest: EvidenceRequestNotificationPermission,
    provisioningViewModel: ProvisioningViewModel
) {

    // Only need to request POST_NOTIFICATIONS permission if on Android 13 (Tiramisu) or later.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        // TODO: This is a hack, this check should be done in the model instead of here.
        SideEffect {
            provisioningViewModel.provideEvidence(
                evidence = EvidenceResponseNotificationPermission(true)
            )
        }
        return
    }

    val postNotificationsPermissionState = rememberPermissionState(Manifest.permission.POST_NOTIFICATIONS)
    if (postNotificationsPermissionState.status.isGranted) {
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseNotificationPermission(true)
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
                            evidence = EvidenceResponseNotificationPermission(false)
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
                if (constraints.isFixedLength() && currentPassphraseMeetsRequirements) {
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
            onChanged = { passphrase, passphraseMeetsRequirements, donePressed ->
                currentPassphrase = passphrase
                if (constraints.isFixedLength() && currentPassphrase.length == constraints.minLength) {
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
fun EvidenceRequestSetupCloudSecureAreaView(
    context: Context,
    secureAreaRepository: SecureAreaRepository,
    evidenceRequest: EvidenceRequestSetupCloudSecureArea,
    onAccept: () -> Unit,
    onError: (error: Throwable) -> Unit
) {
    val cloudSecureAreaState = remember { mutableStateOf<CloudSecureArea?>(null) }
    println("secureAreaRepository: $secureAreaRepository")
    val scope = rememberCoroutineScope()
    SideEffect {
        scope.launch {
            val cloudSecureArea = secureAreaRepository.getImplementation(
                evidenceRequest.cloudSecureAreaIdentifier
            )
            if (cloudSecureArea == null) {
                throw IllegalStateException("Cannot create Secure Area with id ${evidenceRequest.cloudSecureAreaIdentifier}")
            }
            if (cloudSecureArea !is CloudSecureArea) {
                throw IllegalStateException("Expected type CloudSecureArea, got $cloudSecureArea")
            }
            if (cloudSecureArea.isRegistered) {
                println("CSA already registered")
                onAccept()
            } else {
                cloudSecureAreaState.value = cloudSecureArea
            }
        }
    }

    if (cloudSecureAreaState.value == null) {
        Text("TODO: Waiting....")
        return
    }

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
            SideEffect {
                scope.launch {
                    try {
                        cloudSecureAreaState.value!!.register(
                            chosenPassphrase,
                            evidenceRequest.passphraseConstraints,
                        ) { true }
                        onAccept()
                    } catch (e: Throwable) {
                        Logger.e(TAG, "Error registering with Cloud Secure Area", e)
                        onError(e)
                    }
                }
            }
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
    permissionTracker: PermissionTracker
) {
    EvidenceRequestIcaoView(
        MrtdNfcDataReader(evidenceRequest.requestedDataGroups),
        permissionTracker,
        IcaoMrtdCommunicationModel.Route.CAMERA_SCAN
    ) { nfcData ->
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseIcaoPassiveAuthentication(nfcData.dataGroups, nfcData.sod)
        )
    }
}

@Composable
fun EvidenceRequestIcaoNfcTunnelView(
    evidenceRequest: EvidenceRequestIcaoNfcTunnel,
    provisioningViewModel: ProvisioningViewModel,
    permissionTracker: PermissionTracker,
    developerMode: Boolean = false
) {
    var showSuccessfulScanningScreen by remember { mutableStateOf(false) }
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

    // If developer mode not enabled, simply show the MRZ or NFC screen without briefly showing
    // transitional success screen after successfully scanning an NFC document.
    if (!developerMode){
        EvidenceRequestIcaoView(tunnelScanner, permissionTracker, initialRoute) {
            // upon completion of nfc scanning, finish the tunneling process
            provisioningViewModel.finishTunnel()
        }
    } else { // developer mode is enabled
        // if user has not successfully scanned an NFC document, show the MRZ or NFC screen
        if (!showSuccessfulScanningScreen) {
            EvidenceRequestIcaoView(tunnelScanner, permissionTracker, initialRoute) {
                // upon completion of nfc scanning, show a transitional "Success" screen
                showSuccessfulScanningScreen = true
            }
        } else { // user successfully scanned an NFC document
            // briefly (1 sec) show a transitional success screen then finish the tunneling process
            DocumentSuccessfullyScannedScreen(pauseDurationMs = 1000L) {
                provisioningViewModel.finishTunnel()
            }
        }
    }
}

/**
 * Briefly show the "Document Scanning Successful" screen before moving to the next screen/step
 * of evidence request (automatically after waiting for [pauseDurationMs]).
 */
@Composable
fun DocumentSuccessfullyScannedScreen(pauseDurationMs: Long, onFinishedShowingScreen: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 10.dp)
    ) {
        Icon(
            painter = painterResource(id = R.drawable.id_card),
            tint = MaterialTheme.colorScheme.background.inverse(),
            contentDescription = stringResource(
                R.string.accessibility_artwork_for,
                stringResource(id = R.string.evidence_nfc_scan_successful_title)
            ),
            modifier = Modifier
                .size(48.dp)
                .padding(start = 16.dp)
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(
                text = stringResource(R.string.evidence_nfc_scan_successful_title),
                modifier = Modifier.padding(16.dp),
                textAlign = TextAlign.Left,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.headlineLarge
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 100.dp, bottom = 200.dp),
            horizontalArrangement = Arrangement.Center
        ) {
            Column(
                modifier = Modifier.padding(top = 80.dp, bottom = 50.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.check_circled),
                    tint = colorResource(id = R.color.success_green),
                    modifier = Modifier.size(100.dp),
                    contentDescription = stringResource(
                        R.string.accessibility_artwork_for,
                        stringResource(id = R.string.evidence_nfc_scan_successful_title)
                    )
                )
            }
        }
    }
    LaunchedEffect(key1 = true) {
        delay(pauseDurationMs)
        onFinishedShowingScreen.invoke()
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
        NavHost(navController = navController, startDestination = initialRoute.route) {
            composable(IcaoMrtdCommunicationModel.Route.CAMERA_SCAN.route) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 10.dp)
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.id_card),
                        tint = MaterialTheme.colorScheme.background.inverse(),
                        contentDescription = stringResource(
                            R.string.accessibility_artwork_for,
                            stringResource(id = R.string.evidence_camera_scan_mrz_title)
                        ),
                        modifier = Modifier
                            .size(48.dp)
                            .padding(start = 16.dp)
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = stringResource(R.string.evidence_camera_scan_mrz_title),
                            modifier = Modifier.padding(16.dp),
                            textAlign = TextAlign.Left,
                            style = MaterialTheme.typography.headlineLarge
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 5.dp),
                        horizontalArrangement = Arrangement.Absolute.Left
                    ) {
                        Text(
                            modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                            text = stringResource(R.string.evidence_camera_scan_mrz_instruction),
                            style = MaterialTheme.typography.bodyLarge
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(vertical = 10.dp),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Column {
                            AndroidView(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .padding(top = 16.dp)
                                    .clip(RoundedCornerShape(32.dp))
                                    .background(
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f)
                                    ),
                                factory = { context ->
                                    PreviewView(context).apply {
                                        layoutParams = LinearLayout.LayoutParams(
                                            ViewGroup.LayoutParams.MATCH_PARENT,
                                            ViewGroup.LayoutParams.MATCH_PARENT
                                        )
                                        scaleType = PreviewView.ScaleType.FILL_CENTER
                                        implementationMode =
                                            PreviewView.ImplementationMode.COMPATIBLE
                                        post {
                                            icaoCommunication.launchCameraScan(surfaceProvider)
                                        }
                                    }
                                }
                            )
                        }
                    }
                }
            }

            composable(IcaoMrtdCommunicationModel.Route.NFC_SCAN.route) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 10.dp)
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.id_card),
                        tint = MaterialTheme.colorScheme.background.inverse(),
                        contentDescription = stringResource(
                            R.string.accessibility_artwork_for,
                            stringResource(id = R.string.evidence_camera_scan_mrz_title)
                        ),
                        modifier = Modifier
                            .size(48.dp)
                            .padding(start = 16.dp)
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = stringResource(R.string.evidence_nfc_scan_title),
                            modifier = Modifier.padding(16.dp),
                            textAlign = TextAlign.Left,
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.headlineLarge
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Absolute.Left
                    ) {
                        Text(
                            modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                            text = stringResource(R.string.evidence_nfc_scan_info),
                            style = MaterialTheme.typography.bodyLarge
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 30.dp),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Column(
                            modifier = Modifier.padding(top = 80.dp, bottom = 50.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            val icaoStatusValue = icaoCommunication.status.value
                            NfcHeartbeatAnimation(
                                NfcAnimationStatus.getAnimationStatus(icaoStatusValue)
                            )
                            Text(
                                modifier = Modifier.padding(top = 45.dp),
                                style = MaterialTheme.typography.bodyLarge,
                                fontFamily = FontFamily.SansSerif,
                                text = when (icaoStatusValue) {
                                    // don't show a message while waiting to detect an NFC document,
                                    is MrtdNfc.Initial -> ""
                                    // once an NFC document is detected show "initializing" until
                                    // reading of data from document begins
                                    is MrtdNfc.Connected,
                                    is MrtdNfc.AttemptingPACE,
                                    is MrtdNfc.PACESucceeded,
                                    is MrtdNfc.AttemptingBAC,
                                    is MrtdNfc.BACSucceeded,
                                    is MrtdNfc.TunnelAuthenticating -> stringResource(R.string.nfc_status_initializing)
                                    // if PACE is unsupported or fails, show "unable to initialize"
                                    is MrtdNfc.PACENotSupported,
                                    is MrtdNfc.PACEFailed -> stringResource(R.string.nfc_status_pace_unable_to_initialize)
                                    // when reading data (in/out of a tunnel) show "reading... %"
                                    is MrtdNfc.ReadingData,
                                    is MrtdNfc.TunnelReading -> {
                                        val progressPercent =
                                            (icaoStatusValue as? MrtdNfc.ReadingData)?.progressPercent
                                                ?: (icaoStatusValue as MrtdNfc.TunnelReading).progressPercent
                                        stringResource(
                                            R.string.nfc_status_reading_data,
                                            progressPercent
                                        )
                                    }
                                    // this is here for completeness sake and is not really visible
                                    // due to the screen changing before this view is composed.
                                    is MrtdNfc.Finished -> stringResource(R.string.nfc_status_finished)
                                }
                            )
                        }
                    }
                    Column(
                        modifier = Modifier
                            .padding(top = 60.dp)
                            .fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            painter = painterResource(id = R.drawable.passport_biometric_icon),
                            tint = Color.LightGray,
                            contentDescription = stringResource(
                                R.string.accessibility_artwork_for,
                                stringResource(id = R.string.evidence_nfc_scan_passport_symbol_accesibility_description)
                            ),
                            modifier = Modifier
                                .size(48.dp)
                                .padding(start = 16.dp)
                        )
                        Text(
                            modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                            text = stringResource(R.string.evidence_nfc_scan_passport_symbol_check),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                }
            }
        }
    }
}

/**
 * Nfc Animation Status - used to update the NFC "contactless" icon colors and animation according
 * to the value of [MrtdNfc.Status]
 */
enum class NfcAnimationStatus {
    // Waiting to detect an NFC card
    Initial,
    // Any state that's not Initial, Error, or Finished
    Connected,
    // Some error occurred
    Error,
    // Finished scanning NFC document
    Finished
    ;
    companion object {
        /**
         * Return an [NfcAnimationStatus] from an MrtdNfc.Status
         */
        fun getAnimationStatus(nfcStatus: MrtdNfc.Status): NfcAnimationStatus = when (nfcStatus) {
            MrtdNfc.Initial -> Initial
            MrtdNfc.PACENotSupported, MrtdNfc.PACEFailed -> Error
            MrtdNfc.Finished -> Finished
            else -> Connected
        }
    }
}

/**
 * Compose the NFC "Heartbeat" animation according to the passed-in [nfcAnimationStatus] while
 * following the device's Light/Dark theme colors, where the color scheme for Dark theme is the
 * inverse of Light.
 */
@Composable
fun NfcHeartbeatAnimation(nfcAnimationStatus: NfcAnimationStatus) {
    val infiniteTransition = rememberInfiniteTransition(label = "repeating transition")
    // Duration of all animation transitions.
    val transitionDurationMs = 1500
    // Adjust size of contactless icon here.
    val iconSize = 80.dp
    // Define the starting alpha of background color of radius animation.
    val animationBgAlpha = 0.1F
    // Transition animation that grows the radius around the contactless icon.
    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 2f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = transitionDurationMs,
                easing = LinearOutSlowInEasing
            ),
            repeatMode = RepeatMode.Restart
        ), label = "scaling animation"
    )
    // Transition animation for changing alpha of background color of radius animation.
    val alpha by infiniteTransition.animateFloat(
        initialValue = animationBgAlpha,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = transitionDurationMs, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ), label = "alpha animation"
    )
    val tintColorThemed = if (!isSystemInDarkTheme()) {
        colorResource(id = R.color.contactless_blue)
    } else {
        colorResource(id = R.color.contactless_blue).inverse()
    }
    // Start composing the "NFC heartbeat" animation.
    Box(
        contentAlignment = Alignment.Center,
    ) {
        // Don't show the radius animation when encountering an error.
        if (nfcAnimationStatus != NfcAnimationStatus.Error) {
            Box(
                modifier = Modifier
                    .size(iconSize) // heartbeat size
                    .graphicsLayer(scaleX = scale, scaleY = scale)
                    .alpha(alpha)
                    .background(tintColorThemed, CircleShape)
            )
        }
        Box(
            modifier = Modifier.clip(CircleShape)
        ) {
            // get the main and background colors of the "contactless" icon
            val (tintColor, bgColor) = when (nfcAnimationStatus) {
                // Idling/waiting to begin reading an NFC document.
                NfcAnimationStatus.Initial -> Pair(
                    tintColorThemed,
                    tintColorThemed.copy(alpha = animationBgAlpha)
                )
                // Once an NFC document is detected, inverse colors of "Initial" status.
                NfcAnimationStatus.Connected -> Pair(
                    MaterialTheme.colorScheme.background,
                    tintColorThemed
                )
                // Error while initializing/reading NFC card.
                NfcAnimationStatus.Error -> Pair(
                    MaterialTheme.colorScheme.background,
                    Color.Red.copy(
                        alpha =
                        if (isSystemInDarkTheme()) {
                            1F
                        } else {
                            0.3F
                        }
                    )
                )
                // NFC scan complete -- colors are not used b/c icon is changed entirely.
                else -> Pair(Color.Transparent, Color.Transparent)
            }
            Icon(
                painter = painterResource(id = R.drawable.contactless),
                contentDescription = stringResource(
                    R.string.accessibility_artwork_for,
                    stringResource(id = R.string.evidence_nfc_scan_title)
                ),
                tint = tintColor,
                modifier = Modifier
                    .size(iconSize)
                    .background(bgColor)
            )
        }
    }
}

@Composable
fun EvidenceRequestSelfieVideoView(
    evidenceRequest: EvidenceRequestSelfieVideo,
    provisioningViewModel: ProvisioningViewModel,
    permissionTracker: PermissionTracker
) {
    if (evidenceRequest.poseSequence.isEmpty()) {
        throw IllegalArgumentException("Pose sequence must not be empty.")
    }

    var stage by remember { mutableIntStateOf(-1) }
    var buttonEnabled by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf("") }
    var enablePoseRecognition by remember { mutableStateOf(false) }
    var overrideMessage: String? by remember { mutableStateOf(null) }
    // Using the local lifecycle owner (rather than the Activity) ensures that the camera will be
    // released when this screen is finished.
    val lifecycleOwner = LocalLifecycleOwner.current
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // We want a slight delay from the time the screen provides instructions for a pose to the time
    // we tell the face recognizer to look for that pose. This handles that transition.
    fun moveToNextPose() {
        enablePoseRecognition = false
        stage += 1
        val cachedStage = stage
        if (cachedStage < evidenceRequest.poseSequence.size) {
            coroutineScope.launch {
                delay(1000)
                if (stage == cachedStage) {
                    enablePoseRecognition = true
                }
            }
        }
    }
    val selfieRecorder: SelfieRecorder = remember {
        SelfieRecorder(
            lifecycleOwner,
            context,
            onRecordingStarted = {
                buttonEnabled = true
            },
            onFinished = { selfieResult: ByteArray ->
                Logger.i(TAG, "Selfie video finished.")
                if (selfieResult.isEmpty()) {
                    // There was an error recording the video. Show an error message.
                    // TODO: Depending on what caused the error, we may be able to provide more
                    //  actionable information. Update this so we have more information about what
                    //  caused the failure.
                    errorMessage = context.getString(R.string.selfie_video_failed)
                    return@SelfieRecorder
                } else {
                    provisioningViewModel.provideEvidence(
                        evidence = EvidenceResponseSelfieVideo(selfieResult)
                    )
                }
            },
            onStateChange = { recognitionState, pose ->
                overrideMessage = null
                when (recognitionState) {
                    FaceImageClassifier.RecognitionState.TOO_MANY_FACES -> {
                        overrideMessage =
                            context.getString(R.string.selfie_instructions_too_many_faces)
                    }
                    FaceImageClassifier.RecognitionState.POSE_RECOGNIZED -> {
                        val cachedStage = stage
                        if (cachedStage < 0 || cachedStage >= evidenceRequest.poseSequence.size) {
                            // Face recognition happens in another thread, so we may receive results
                            // after we've finished recording the video.
                            return@SelfieRecorder
                        }

                        // Since recognition happens in another thread, ensure that the pose that
                        // was recognized is the pose we're currently looking for, not a pose that
                        // we were looking for in a past stage.
                        val expectedPose = evidenceRequest.poseSequence[cachedStage]
                        if (pose == expectedPose) {
                            moveToNextPose()
                            Logger.i(TAG, "Face pose detected: $pose. Moving to stage $stage.")
                        }
                    }
                    else -> {}
                }
            }
        )
    }
    // Update the expected pose anytime the stage changes. We can't do this in the
    // onFacePoseDetected handler, because it can't reference selfieRecorder (there's a circular
    // reference, and the variable hasn't been created yet). This ends up setting the value any time
    // the composable is recomposed, but it's just setting a single variable, so it should be quick.
    if (!enablePoseRecognition) {
        selfieRecorder.faceClassifier?.setExpectedPose(null)
    } else if (stage >= 0 && stage < evidenceRequest.poseSequence.size) {
        val expectedPose = evidenceRequest.poseSequence[stage]
        selfieRecorder.faceClassifier?.setExpectedPose(expectedPose)
    }

    var finishing by remember { mutableStateOf(false) }
    SideEffect {
        if (stage >= evidenceRequest.poseSequence.size && !finishing) {
            finishing = true
            coroutineScope.launch {
                selfieRecorder.finish()
            }
        }
    }

    val requiredPermissions =
        mutableListOf (Manifest.permission.CAMERA).apply {
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
                // Needed in older OS versions so we can save the video file to external storage.
                add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        }.toList()
    permissionTracker.PermissionCheck(requiredPermissions) {
        if (errorMessage.isNotEmpty()) {
            Text(
                text = errorMessage,
                modifier = Modifier.padding(16.dp),
                textAlign = TextAlign.Center
            )
            return@PermissionCheck
        }

        Column {
            // We want a fixed height for the instructions and for the video, so when the
            // instructions get longer or shorter, the screen layout doesn't jump around.
            // These won't take up 100% of the screen height, since there are other screen
            // elements above and below them.
            val displayMetrics = context.resources.displayMetrics
            val videoHeightPx = displayMetrics.heightPixels * 7 / 10
            val instructionsHeightPx = displayMetrics.heightPixels  * 2 / 10
            Column(modifier = Modifier
                .fillMaxWidth()
                .height(with(LocalDensity.current) { instructionsHeightPx.toDp() })) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = stringResource(R.string.record_selfie_title),
                        modifier = Modifier.padding(16.dp),
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.titleLarge
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    AnimatedContent(
                        targetState = stage,
                        label = "SelfieInstructions"
                    ) { cachedStage ->
                        val cachedOverrideMessage = overrideMessage
                        Text(
                            modifier = Modifier.padding(start = 16.dp, end = 16.dp),
                            text = when {
                                cachedStage == -1 -> stringResource(R.string.initial_selfie_video_instructions)
                                cachedOverrideMessage != null -> cachedOverrideMessage
                                cachedStage < evidenceRequest.poseSequence.size -> {
                                    when (evidenceRequest.poseSequence[cachedStage]) {
                                        EvidenceRequestSelfieVideo.Poses.FRONT -> stringResource(R.string.selfie_instructions_face_front)
                                        EvidenceRequestSelfieVideo.Poses.SMILE -> stringResource(R.string.selfie_instructions_smile)
                                        EvidenceRequestSelfieVideo.Poses.TILT_HEAD_UP -> stringResource(R.string.selfie_instructions_tilt_head_up)
                                        EvidenceRequestSelfieVideo.Poses.TILT_HEAD_DOWN -> stringResource(R.string.selfie_instructions_tilt_head_down)
                                    }
                                }

                                else -> {
                                    stringResource(R.string.selfie_instructions_finishing_video)
                                }
                            },
                            style = MaterialTheme.typography.bodyLarge
                        )
                    }
                }
            }
            Box(modifier = Modifier
                .fillMaxWidth()
                .height(with(LocalDensity.current) { videoHeightPx.toDp() })) {
                AndroidView(
                    modifier = Modifier.padding(16.dp),
                    factory = { context ->
                        PreviewView(context).apply {
                            layoutParams = LinearLayout.LayoutParams(
                                ViewGroup.LayoutParams.MATCH_PARENT,
                                videoHeightPx
                            )
                            scaleType = PreviewView.ScaleType.FILL_START
                            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                            coroutineScope.launch {
                                async { selfieRecorder.launchCamera(surfaceProvider) }.await()
                                buttonEnabled = true
                            }
                        }
                    }
                )
                if (stage == -1) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .align(Alignment.BottomCenter),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Button(
                            modifier = Modifier.padding(8.dp),
                            enabled = buttonEnabled,
                            onClick = {
                                buttonEnabled = false
                                moveToNextPose()
                                coroutineScope.launch {
                                    selfieRecorder.startRecording()
                                }
                            }
                        ) {
                            Text(stringResource(R.string.selfie_video_start_recording_button))
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun EvidenceRequestEIdView(
    evidenceRequest: EvidenceRequestGermanEid,
    provisioningViewModel: ProvisioningViewModel
) {
    AusweisView(
        evidenceRequest.tcTokenUrl,
        evidenceRequest.optionalComponents
    ) { evidence ->
        provisioningViewModel.provideEvidence(
            evidence = evidence
        )
    }
}

@Composable
fun AusweisView(
    tcTokenUrl: String,
    requiredComponents: List<String>,
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
            tcTokenUrl,
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
                        when (component) {
                            "GivenNames" ->
                                AccessRightsIconAndText(Icon.PERSON, stringResource(R.string.eid_access_right_first_name))
                            "FamilyName" ->
                                AccessRightsIconAndText(Icon.PERSON, stringResource(R.string.eid_access_right_last_name))
                            "BirthName" ->
                                AccessRightsIconAndText(Icon.PERSON, stringResource(R.string.eid_access_right_maiden_name))
                            "DateOfBirth" ->
                                AccessRightsIconAndText(Icon.TODAY, stringResource(R.string.eid_access_right_date_of_birth))
                            "Address" ->
                                AccessRightsIconAndText(Icon.PLACE, stringResource(R.string.eid_access_right_address))
                            "Nationality" ->
                                AccessRightsIconAndText(Icon.LANGUAGE, stringResource(R.string.eid_access_right_nationality))
                            "PlaceOfBirth" ->
                                AccessRightsIconAndText(Icon.PLACE, stringResource(R.string.eid_access_right_place_of_birth))
                            "Pseudonym" ->
                                AccessRightsIconAndText(Icon.PERSON, stringResource(R.string.eid_access_right_pseudonym))
                            "AgeVerification" ->
                                AccessRightsIconAndText(Icon.TODAY, stringResource(R.string.eid_access_right_age_verification))
                            // TODO: all others
                            else -> AccessRightsIconAndText(Icon.STARS, component)
                        }
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
                            } else if (status.value == AusweisModel.PinError) {
                                R.string.eid_pin_error
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

@Composable
fun AccessRightsIconAndText(
    icon: Icon,
    text: String
) {
    Row(modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp), horizontalArrangement = Arrangement.Start) {
        Image(
            painter = rememberVectorPainter(icon.getDefaultImageVector()),
            contentDescription = "Person Icon",
            modifier = Modifier.padding(start = 16.dp))
        Text(
            text = text,
            modifier = Modifier.padding(8.dp, 0.dp))
    }
}

@Composable
fun EvidenceRequestWebView(
    evidenceRequest: EvidenceRequestWeb,
    provisioningViewModel: ProvisioningViewModel,
    walletServerProvider: WalletServerProvider
) {
    val context = LocalContext.current
    val url = Uri.parse(evidenceRequest.url)
    val redirectUri = evidenceRequest.redirectUri
    val scope = rememberCoroutineScope()
    LaunchedEffect(url, redirectUri) {
        // NB: these scopes will be cancelled when navigating outside of this screen.
        val appSupport = walletServerProvider.getApplicationSupportConnection().applicationSupport
        scope.launch {
            // Wait for notifications
            appSupport.notifications.collectLatest { notification ->
                if (notification.baseUrl == redirectUri) {
                    handleLanding(appSupport, redirectUri, provisioningViewModel)
                }
            }
        }

        // Launch the browser
        // TODO: use Chrome Custom Tabs instead?
        val browserIntent = Intent(Intent.ACTION_VIEW, url)
        context.startActivity(browserIntent)

        // Poll as a fallback
        do {
            delay(10.seconds)
        } while(handleLanding(appSupport, redirectUri, provisioningViewModel))
    }
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(
                text = stringResource(
                        R.string.browser_continue
                    ),
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(8.dp),
                style = MaterialTheme.typography.bodyLarge
            )
        }
    }
}

@Composable
fun EvidenceRequestOpenid4Vp(
    evidenceRequest: EvidenceRequestOpenid4Vp,
    provisioningViewModel: ProvisioningViewModel,
    application: WalletApplication
) {
    val cx = LocalContext.current
    val credential = provisioningViewModel.selectedOpenid4VpCredential.value!!
    val coroutineScope = rememberCoroutineScope()
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(
                text = stringResource(
                    R.string.presentation_evidence_message
                ),
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(8.dp),
                style = MaterialTheme.typography.bodyLarge
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        )  {
            Button(
                modifier = Modifier.padding(8.dp),
                onClick = {
                val activity = getFragmentActivity(cx)
                CoroutineScope(Dispatchers.Main).launch {
                    try {
                        val response = openid4VpPresentation(
                            credential,
                            application,
                            activity,
                            evidenceRequest.originUri,
                            evidenceRequest.request
                        )
                        provisioningViewModel.provideEvidence(
                            evidence = EvidenceResponseOpenid4Vp(response)
                        )
                    } catch (cancelled: UserCanceledPromptException) {
                        provisioningViewModel.evidenceCollectionFailed(
                            error = cancelled
                        )
                    }
                }
            }) {
                Text(text = stringResource(id = R.string.presentation_evidence_ok))
            }
            Button(
                modifier = Modifier.padding(8.dp),
                onClick = {
                    coroutineScope.launch {
                        provisioningViewModel.moveToNextEvidenceRequest()
                    }
                }
            ) {
                Text(text = evidenceRequest.cancelText ?:
                    stringResource(id = R.string.presentation_evidence_cancel)
                )
            }
        }
    }
}

private suspend fun handleLanding(
    appSupport: ApplicationSupport,
    redirectUri: String,
    provisioningViewModel: ProvisioningViewModel
): Boolean {
    val resp = try {
        appSupport.getLandingUrlStatus(redirectUri)
    } catch (err: LandingUrlUnknownException) {
        Logger.e(
            "EvidenceRequestWebView",
            "landing: $redirectUri unknown: $err"
        )
        provisioningViewModel.provideEvidence(
            evidence = EvidenceResponseWeb("")
        )
        return false
    }
    Logger.e(
        "EvidenceRequestWebView",
        "landing: $redirectUri status: $resp"
    )
    if (resp == null) {
        // Landing url not navigated to yet.
        return true
    }
    provisioningViewModel.provideEvidence(
        evidence = EvidenceResponseWeb(resp)
    )
    return false
}
