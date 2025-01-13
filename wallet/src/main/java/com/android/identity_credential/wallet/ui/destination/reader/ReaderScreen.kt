package com.android.identity_credential.wallet.ui.destination.reader

import android.app.Activity
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.android.identity.appsupport.ui.qrcode.ScanQrCodeDialog
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.DiagnosticOption
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.DocumentCannedRequest
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.trustmanagement.TrustManager
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.ReaderDocument
import com.android.identity_credential.wallet.ReaderModel
import com.android.identity_credential.wallet.SettingsModel
import com.android.identity_credential.wallet.WalletApplication
import com.android.identity_credential.wallet.createDrivingPrivilegesHtml
import com.android.identity_credential.wallet.navigation.WalletDestination
import com.android.identity_credential.wallet.ui.KeyValuePairHtml
import com.android.identity_credential.wallet.ui.KeyValuePairText
import com.android.identity_credential.wallet.ui.ScreenWithAppBarAndBackButton
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.rememberMultiplePermissionsState
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format
import kotlinx.datetime.toLocalDateTime

private const val TAG = "ReaderScreen"

@Composable
fun ReaderScreen(
    model: ReaderModel,
    docTypeRepo: DocumentTypeRepository,
    settingsModel: SettingsModel,
    issuerTrustManager: TrustManager,
    onNavigate: (String) -> Unit,
) {
    val availableRequests = mutableListOf<Pair<String, DocumentCannedRequest>>()
    for (req in docTypeRepo.getDocumentTypeForMdoc(DrivingLicense.MDL_DOCTYPE)?.cannedRequests!!) {
        availableRequests.add(Pair("mDL: ${req.displayName}", req))
    }
    for (req in docTypeRepo.getDocumentTypeForMdoc(EUPersonalID.EUPID_DOCTYPE)?.cannedRequests!!) {
        availableRequests.add(Pair("EU PID: ${req.displayName}", req))
    }
    for (req in docTypeRepo.getDocumentTypeForMdoc(PhotoID.PHOTO_ID_DOCTYPE)?.cannedRequests!!) {
        availableRequests.add(Pair("Photo ID: ${req.displayName}", req))
    }

    // Make sure we start scanning when entering this screen and stop scanning when
    // we leave the screen...
    //
    val activity = LocalContext.current as Activity
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                model.startRequest(
                    activity,
                    availableRequests[0].second,
                    issuerTrustManager,
                )
            } else if (event == Lifecycle.Event.ON_STOP) {
                model.cancel()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    when (model.phase.value) {
        ReaderModel.Phase.IDLE,
        ReaderModel.Phase.WAITING_FOR_ENGAGEMENT -> {
            WaitForEngagement(
                model,
                settingsModel,
                availableRequests,
                onNavigate
            )
        }
        ReaderModel.Phase.WAITING_FOR_CONNECTION -> {
            WaitingForConnection(model)
        }
        ReaderModel.Phase.WAITING_FOR_RESPONSE -> {
            WaitingForResponse(model)
        }
        ReaderModel.Phase.COMPLETE -> {
            if (model.response != null) {
                ShowResponse(model)
            } else {
                ShowError(model)
            }
        }
    }
}

@OptIn(ExperimentalPermissionsApi::class)
@Composable
private fun WaitForEngagement(
    model: ReaderModel,
    settingsModel: SettingsModel,
    availableRequests: List<Pair<String, DocumentCannedRequest>>,
    onNavigate: (String) -> Unit,
) {
    val showQrScannerDialog = remember { mutableStateOf(false) }
    var dropdownExpanded = remember { mutableStateOf(false) }
    var dropdownSelected = remember { mutableStateOf(availableRequests[0]) }

    if (showQrScannerDialog.value) {
        ScanQrCodeDialog(
            title = @Composable { Text(text = stringResource(R.string.reader_screen_scan_qr_dialog_title)) },
            text = @Composable { Text(text = stringResource(R.string.reader_screen_scan_qr_dialog_text)) },
            onCodeScanned = { qrCodeText ->
                model.setQrCode(qrCodeText)
                true
            },
            dismissButton = stringResource(R.string.reader_screen_scan_qr_dialog_dismiss_button),
            onDismiss = { showQrScannerDialog.value = false },
        )
    }

    val hasProximityPresentationPermissions = rememberMultiplePermissionsState(
        WalletApplication.MDOC_PROXIMITY_PERMISSIONS
    )

    val snackbarHostState = remember { SnackbarHostState() }
    ScreenWithAppBarAndBackButton(
        title = stringResource(R.string.reader_screen_title),
        onBackButtonClick = {
            onNavigate(WalletDestination.PopBackStack.route)
        },
        scrollable = true,
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
    ) {
        if (!hasProximityPresentationPermissions.allPermissionsGranted &&
            !settingsModel.hideMissingProximityPermissionsWarning.value!!
        ) {
            LaunchedEffect(snackbarHostState) {
                when (snackbarHostState.showSnackbar(
                    message = model.context.getString(R.string.proximity_permissions_snackbar_text),
                    actionLabel = model.context.getString(R.string.proximity_permissions_snackbar_action_label),
                    duration = SnackbarDuration.Indefinite,
                    withDismissAction = true
                )) {
                    SnackbarResult.Dismissed -> {
                        settingsModel.hideMissingProximityPermissionsWarning.value = true
                    }

                    SnackbarResult.ActionPerformed -> {
                        hasProximityPresentationPermissions.launchMultiplePermissionRequest()
                    }
                }
            }
        }

        Row(
            modifier = Modifier.weight(1.0f),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Spacer(modifier = Modifier.weight(0.1f))
                    RequestPicker(
                        availableRequests,
                        dropdownSelected,
                        dropdownExpanded,
                        onRequestSelected = { request ->
                            model.updateRequest(request)
                        }
                    )
                    Spacer(modifier = Modifier.weight(0.2f))
                    NfcIconAndText()
                    Spacer(modifier = Modifier.weight(0.5f))
                    QrScannerButton(showQrScannerDialog)
                    Spacer(modifier = Modifier.weight(0.1f))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RequestPicker(
    availableRequests: List<Pair<String, DocumentCannedRequest>>,
    comboBoxSelected: MutableState<Pair<String, DocumentCannedRequest>>,
    comboBoxExpanded: MutableState<Boolean>,
    onRequestSelected: (request: DocumentCannedRequest) -> Unit
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
                text = stringResource(R.string.reader_screen_identity_data_to_request)
            )

            ExposedDropdownMenuBox(
                expanded = comboBoxExpanded.value,
                onExpandedChange = {
                    comboBoxExpanded.value = !comboBoxExpanded.value
                }
            ) {
                TextField(
                    value = comboBoxSelected.value.first,
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
                            text = { Text(text = item.first) },
                            onClick = {
                                comboBoxSelected.value = item
                                comboBoxExpanded.value = false
                                onRequestSelected(comboBoxSelected.value.second)
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun NfcIconAndText(
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                painter = painterResource(id = R.drawable.nfc_icon),
                contentDescription = stringResource(R.string.reader_screen_nfc_icon_content_description),
                modifier = Modifier.size(96.dp),
            )
            Text(
                modifier = Modifier.padding(8.dp),
                text = stringResource(R.string.reader_screen_nfc_presentation_instructions)
            )
        }
    }
}

@Composable
private fun QrScannerButton(
    showQrScannerDialog: MutableState<Boolean>
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 20.dp, top = 8.dp),
        horizontalArrangement = Arrangement.Center
    ) {
        OutlinedButton(onClick = { showQrScannerDialog.value = true }) {
            Icon(
                painter = painterResource(id = R.drawable.qr_icon),
                contentDescription = stringResource(R.string.reader_screen_qr_icon_content_description),
                modifier = Modifier.size(ButtonDefaults.IconSize)
            )
            Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
            Text(
                text = stringResource(R.string.reader_screen_scan_qr_button_text)
            )
        }
    }

}

@Composable
private fun WaitingForConnection(
    model: ReaderModel
) {
    ScreenWithAppBarAndBackButton(
        title = stringResource(R.string.reader_screen_waiting_for_connection_title),
        onBackButtonClick = { model.restart() },
        scrollable = true,
    ) {
        Row(
            modifier = Modifier.weight(1.0f),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(stringResource(R.string.reader_screen_waiting_for_connection_text))
                }
            }
        }
    }
}

@Composable
private fun WaitingForResponse(
    model: ReaderModel
) {
    ScreenWithAppBarAndBackButton(
        title = stringResource(R.string.reader_screen_waiting_for_response_title),
        onBackButtonClick = { model.restart() },
        scrollable = true,
    ) {
        Row(
            modifier = Modifier.weight(1.0f),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(stringResource(R.string.reader_screen_waiting_for_response_text))
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ShowResponse(model: ReaderModel) {
    val response = model.response!!
    val pagerState = rememberPagerState(pageCount = { response.documents.size })

    Box(
        modifier = Modifier.fillMaxHeight()
    ) {
        ScreenWithAppBarAndBackButton(
            title = stringResource(R.string.reader_result_screen_title),
            onBackButtonClick = { model.restart() },
        ) {
            if (response.documents.isEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        modifier = Modifier.padding(8.dp),
                        text = stringResource(R.string.reader_result_screen_no_documents_returned),
                        style = MaterialTheme.typography.titleLarge,
                        textAlign = TextAlign.Center
                    )
                }
            } else {
                Column {
                    HorizontalPager(
                        state = pagerState,
                    ) { page ->
                        ShowResultDocument(
                            response.documents[page],
                            page,
                            response.documents.size
                        )
                    }
                }
            }
        }

        if (pagerState.pageCount > 1) {
            Row(
                horizontalArrangement = Arrangement.Center,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .wrapContentHeight()
                    .fillMaxWidth()
                    .height(30.dp)
                    .padding(8.dp),
            ) {
                repeat(pagerState.pageCount) { iteration ->
                    val color =
                        if (pagerState.currentPage == iteration) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.secondary
                        }
                    Box(
                        modifier = Modifier
                            .padding(2.dp)
                            .clip(CircleShape)
                            .background(color)
                            .size(8.dp)
                    )
                }
            }
        }

        var showWarning = false
        response.documents.forEach {
            if (!it.warningTexts.isEmpty()) {
                showWarning = true
            }
        }
        if (showWarning) {
            Column(
                verticalArrangement = Arrangement.Center,
                modifier = Modifier.align(Alignment.Center)
            ) {
                Text(
                    text = stringResource(id = R.string.reader_result_screen_unverified_data_warning),
                    textAlign = TextAlign.Center,
                    lineHeight = 1.25.em,
                    color = Color(red = 255, green = 128, blue = 128, alpha = 192),
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    style = TextStyle(
                        fontSize = 30.sp,
                        shadow = Shadow(
                            color = Color.Black,
                            offset = Offset(0f, 0f),
                            blurRadius = 2f
                        ),
                    ),
                    modifier = Modifier.rotate(-30f)
                )
            }
        }
    }
}

@Composable
private fun WarningCard(text: String) {
    Column(
        modifier = Modifier
            .padding(8.dp)
            .fillMaxWidth()
            .clip(shape = RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.errorContainer),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
        ) {
            Icon(
                modifier = Modifier.padding(end = 16.dp),
                imageVector = Icons.Filled.Warning,
                contentDescription = "An error icon",
                tint = MaterialTheme.colorScheme.onErrorContainer
            )

            Text(
                text = text,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
        }
    }
}

@Composable
private fun InfoCard(text: String) {
    Column(
        modifier = Modifier
            .padding(8.dp)
            .fillMaxWidth()
            .clip(shape = RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.primaryContainer),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
        ) {
            Icon(
                modifier = Modifier.padding(end = 16.dp),
                imageVector = Icons.Filled.Info,
                contentDescription = "An info icon",
                tint = MaterialTheme.colorScheme.onPrimaryContainer
            )

            Text(
                text = text,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

@Composable
private fun ShowResultDocument(
    document: ReaderDocument,
    documentIndex: Int,
    numDocuments: Int
) {
    Column(Modifier.padding(8.dp)) {

        for (text in document.infoTexts) {
            InfoCard(text)
        }
        for (text in document.warningTexts) {
            WarningCard(text)
        }

        if (numDocuments > 1) {
            KeyValuePairText(
                stringResource(R.string.reader_result_screen_document_number),
                stringResource(R.string.reader_result_screen_document_n_of_m, documentIndex + 1, numDocuments)
            )
        }
        KeyValuePairText(stringResource(R.string.reader_result_screen_doctype), document.docType)
        KeyValuePairText(stringResource(R.string.reader_result_screen_valid_from), formatTime(document.msoValidFrom))
        KeyValuePairText(stringResource(R.string.reader_result_screen_valid_until), formatTime(document.msoValidUntil))
        KeyValuePairText(stringResource(R.string.reader_result_screen_signed_at), formatTime(document.msoSigned))
        KeyValuePairText(
            stringResource(R.string.reader_result_screen_expected_update),
            document.msoExpectedUpdate?.let { formatTime(it) } ?: stringResource(R.string.reader_result_screen_expected_update_not_set)
        )

        for (namespace in document.namespaces) {
            KeyValuePairText(stringResource(R.string.reader_result_screen_namespace), namespace.name)
            for ((dataElementName, dataElement) in namespace.dataElements) {
                val cborValue = Cbor.decode(dataElement.value)
                val (key, value) = if (dataElement.mdocDataElement != null) {
                    Pair(
                        dataElement.mdocDataElement.attribute.displayName,
                        dataElement.mdocDataElement.renderValue(cborValue)
                    )
                } else {
                    Pair(
                        dataElementName,
                        Cbor.toDiagnostics(
                            cborValue, setOf(
                                DiagnosticOption.PRETTY_PRINT,
                                DiagnosticOption.EMBEDDED_CBOR,
                                DiagnosticOption.BSTR_PRINT_LENGTH,
                            )
                        )
                    )
                }
                if (dataElementName == "driving_privileges") {
                    val html = createDrivingPrivilegesHtml(dataElement.value)
                    KeyValuePairHtml(key, html)
                } else {
                    KeyValuePairText(key, value)
                }

                if (dataElement.bitmap != null) {
                    Row(
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Image(
                            bitmap = dataElement.bitmap.asImageBitmap(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(8.dp)
                                .size(200.dp),
                            contentDescription = dataElement.mdocDataElement?.attribute?.description
                                ?: stringResource(R.string.reader_result_screen_bitmap_missing_description)
                        )
                    }
                }
            }
        }
    }
}

private fun formatTime(instant: Instant): String {
    val tz = TimeZone.currentSystemDefault()
    val isoStr = instant.toLocalDateTime(tz).format(LocalDateTime.Formats.ISO)
    // Get rid of the middle 'T'
    return isoStr.substring(0, 10) + " " + isoStr.substring(11)
}

@Composable
private fun ShowError(
    model: ReaderModel
) {
    ScreenWithAppBarAndBackButton(
        title = stringResource(R.string.reader_screen_error_title),
        onBackButtonClick = { model.restart() },
        scrollable = true,
    ) {
        Row(
            modifier = Modifier.weight(1.0f),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(stringResource(
                        R.string.reader_screen_error_prefix,
                        model.error!!.message ?: ""
                    ))
                }
            }
        }
    }
}
