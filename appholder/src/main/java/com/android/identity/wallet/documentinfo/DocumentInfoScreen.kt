package com.android.identity.wallet.documentinfo

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RemoveRedEye
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Alignment.Companion.CenterHorizontally
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.android.identity.crypto.EcCurve
import com.android.identity.securearea.KeyPurpose
import com.android.identity.wallet.R
import com.android.identity.wallet.composables.LoadingIndicator
import com.android.identity.wallet.composables.ShowToast
import com.android.identity.wallet.composables.gradientFor
import com.android.identity.wallet.theme.HolderAppTheme

@Composable
fun DocumentInfoScreen(
    viewModel: DocumentInfoViewModel,
    onNavigateUp: () -> Unit,
    onNavigateToDocumentDetails: () -> Unit
) {
    val state by viewModel.screenState.collectAsState()
    if (state.isDeleted) {
        ShowToast(message = stringResource(id = R.string.delete_document_deleted_message))
        onNavigateUp()
    }

    DocumentInfoScreenContent(
        screenState = state,
        onRefreshCredentials = viewModel::refreshCredentials,
        onShowDocumentElements = { onNavigateToDocumentDetails() },
        onDeleteDocument = { viewModel.promptDocumentDelete() },
        onConfirmDocumentDelete = viewModel::confirmDocumentDelete,
        onCancelDocumentDelete = viewModel::cancelDocumentDelete
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun DocumentInfoScreenContent(
    modifier: Modifier = Modifier,
    screenState: DocumentInfoScreenState,
    onRefreshCredentials: () -> Unit,
    onShowDocumentElements: () -> Unit,
    onDeleteDocument: () -> Unit,
    onConfirmDocumentDelete: () -> Unit,
    onCancelDocumentDelete: () -> Unit,
) {
    Scaffold(
        modifier = modifier
    ) { paddingValues ->
        Column(
            modifier = Modifier.padding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = CenterHorizontally
        ) {
            if (screenState.isLoading) {
                LoadingIndicator(
                    modifier = Modifier.fillMaxSize()
                )
            } else {
                Box(modifier = Modifier.fillMaxSize()) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp)
                                .border(
                                    2.dp,
                                    gradientFor(screenState.documentColor),
                                    RoundedCornerShape(12.dp)
                                )
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                LabeledValue(
                                    label = stringResource(id = R.string.label_document_name),
                                    value = screenState.documentName
                                )
                                LabeledValue(
                                    label = stringResource(id = R.string.label_document_type),
                                    value = screenState.documentType
                                )
                                LabeledValue(
                                    label = stringResource(id = R.string.label_date_provisioned),
                                    value = screenState.provisioningDate
                                )
                                LabeledValue(
                                    label = stringResource(id = R.string.label_last_time_used),
                                    value = screenState.lastTimeUsedDate.ifBlank { "N/A" }
                                )
                                LabeledValue(
                                    label = stringResource(id = R.string.label_issuer),
                                    value = if (screenState.isSelfSigned) "Self-Signed on Device" else "N/A"
                                )
                            }
                        }
                        val pagerState = rememberPagerState(pageCount = { screenState.authKeys.size + screenState.daKeys.size })
                        HorizontalPager(
                            modifier = Modifier
                                .fillMaxWidth(),
                            state = pagerState,
                        ) { page ->
                            if (page < screenState.authKeys.size) {
                                val key = screenState.authKeys[page]
                                AuthenticationKeyInfo(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 16.dp)
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(MaterialTheme.colorScheme.secondaryContainer),
                                    authKeyInfo = key
                                )
                            } else {
                                val key = screenState.daKeys[page - screenState.authKeys.size]
                                DaAuthenticationKeyInfo(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 16.dp)
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(MaterialTheme.colorScheme.secondaryContainer),
                                    authKeyInfo = key
                                )
                            }

                        }
                        PagerIndicators(
                            modifier = Modifier
                                .height(24.dp)
                                .fillMaxWidth()
                                .align(CenterHorizontally),
                            pagerState = pagerState,
                            itemsCount = screenState.authKeys.size + screenState.daKeys.size,
                        )
                        Divider(modifier = Modifier.padding(top = 12.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp),
                            horizontalArrangement = Arrangement.SpaceEvenly,
                        ) {
                            Column(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .weight(1f)
                                    .clickable { onRefreshCredentials() },
                                horizontalAlignment = CenterHorizontally
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    horizontalAlignment = CenterHorizontally
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Refresh,
                                        contentDescription = stringResource(id = R.string.bt_refresh_auth_keys),
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Text(
                                        text = stringResource(id = R.string.bt_refresh_auth_keys),
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                            Column(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .weight(1f)
                                    .clickable { onShowDocumentElements() },
                                horizontalAlignment = CenterHorizontally
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    horizontalAlignment = CenterHorizontally
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.RemoveRedEye,
                                        contentDescription = stringResource(id = R.string.bt_show_data),
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Text(
                                        text = stringResource(id = R.string.bt_show_data),
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                        }
                    }
                    OutlinedButton(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 16.dp, end = 16.dp, bottom = 24.dp)
                            .align(Alignment.BottomCenter),
                        onClick = onDeleteDocument,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.error),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Delete,
                                contentDescription = stringResource(id = R.string.bt_delete),
                            )
                            Text(text = stringResource(id = R.string.bt_delete))
                        }
                    }
                    if (screenState.isDeletingPromptShown) {
                        DeleteDocumentPrompt(
                            onConfirm = onConfirmDocumentDelete,
                            onCancel = onCancelDocumentDelete
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun PagerIndicators(
    modifier: Modifier = Modifier,
    pagerState: PagerState,
    itemsCount: Int,
) {
    Row(
        modifier,
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        repeat(itemsCount) { iteration ->
            val color = if (pagerState.currentPage == iteration) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = .2f)
            }
            Box(
                modifier = Modifier
                    .padding(2.dp)
                    .clip(CircleShape)
                    .background(color)
                    .size(12.dp)
            )
        }
    }
}

@Composable
private fun AuthenticationKeyInfo(
    modifier: Modifier = Modifier,
    authKeyInfo: DocumentInfoScreenState.KeyInformation
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            modifier = Modifier
                .size(48.dp)
                .padding(horizontal = 8.dp),
            imageVector = Icons.Default.Key,
            contentDescription = "${authKeyInfo.counter}",
            tint = MaterialTheme.colorScheme.primary.copy(alpha = .5f)
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LabeledValue(
                label = stringResource(id = R.string.txt_cred_type),
                value = stringResource(id = R.string.txt_cred_mdoc)
            )
            LabeledValue(
                label = stringResource(id = R.string.txt_keystore_implementation),
                value = authKeyInfo.secureAreaDisplayName
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_counter),
                value = "${authKeyInfo.counter}"
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_domain),
                value = authKeyInfo.domain
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_valid_from),
                value = authKeyInfo.validFrom
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_valid_until),
                value = authKeyInfo.validUntil
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_issuer_data),
                value = stringResource(
                    id = R.string.document_info_issuer_data_bytes,
                    authKeyInfo.issuerDataBytesCount
                )
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_usage_count),
                value = "${authKeyInfo.usagesCount}"
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_key_purposes),
                value = authKeyInfo.keyPurposes.toString()
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_ec_curve),
                value = authKeyInfo.ecCurve.toString()
            )
        }
    }
}

@Composable
private fun DaAuthenticationKeyInfo(
    modifier: Modifier = Modifier,
    authKeyInfo: DocumentInfoScreenState.DaKeyInformation
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            modifier = Modifier
                .size(48.dp)
                .padding(horizontal = 8.dp),
            imageVector = Icons.Default.Key,
            contentDescription = "${authKeyInfo.counter}",
            tint = MaterialTheme.colorScheme.primary.copy(alpha = .5f)
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LabeledValue(
                label = stringResource(id = R.string.txt_cred_type),
                value = stringResource(id = R.string.txt_cred_da)
            )
            LabeledValue(
                label = stringResource(id = R.string.txt_keystore_implementation),
                value = authKeyInfo.secureAreaDisplayName
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_counter),
                value = "${authKeyInfo.counter}"
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_domain),
                value = authKeyInfo.domain
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_valid_from),
                value = authKeyInfo.validFrom
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_valid_until),
                value = authKeyInfo.validUntil
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_issuer_data),
                value = stringResource(
                    id = R.string.document_info_issuer_data_bytes,
                    authKeyInfo.issuerDataBytesCount
                )
            )
            LabeledValue(
                label = stringResource(id = R.string.document_info_usage_count),
                value = "${authKeyInfo.usagesCount}"
            )
        }
    }
}

@Composable
private fun DeleteDocumentPrompt(
    onConfirm: () -> Unit,
    onCancel: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = {
            Text(text = stringResource(id = R.string.delete_document_prompt_title))
        },
        text = {
            Text(text = stringResource(id = R.string.delete_document_prompt_message))
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(text = stringResource(id = R.string.bt_delete))
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel) {
                Text(text = stringResource(id = R.string.bt_cancel))
            }
        }
    )
}

@Composable
private fun LabeledValue(
    modifier: Modifier = Modifier,
    label: String,
    value: String
) {
    val textValue = buildAnnotatedString {
        withStyle(style = SpanStyle(fontWeight = FontWeight.Bold)) {
            append(label)
            append(": ")
        }
        append(value)
    }
    Text(
        modifier = modifier,
        text = textValue,
        style = MaterialTheme.typography.titleMedium,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis
    )
}

@Composable
@Preview
private fun PreviewDocumentInfoScreenLoading() {
    HolderAppTheme {
        DocumentInfoScreenContent(
            screenState = DocumentInfoScreenState(
                isLoading = true
            ),
            onRefreshCredentials = {},
            onShowDocumentElements = {},
            onDeleteDocument = {},
            onConfirmDocumentDelete = {}
        ) {}
    }
}

@Composable
@Preview
private fun PreviewDocumentInfoScreen() {
    HolderAppTheme {
        DocumentInfoScreenContent(
            screenState = DocumentInfoScreenState(
                documentName = "Erica's Driving Licence",
                documentType = "org.iso.18013.5.1.mDL",
                provisioningDate = "16-07-2023",
                isSelfSigned = true,
                authKeys = listOf(
                    DocumentInfoScreenState.KeyInformation(
                        counter = 1,
                        validFrom = "16-07-2023",
                        validUntil = "23-07-2023",
                        domain = "Domain",
                        usagesCount = 1,
                        issuerDataBytesCount = "Issuer 1".toByteArray().count(),
                        keyPurposes = KeyPurpose.AGREE_KEY,
                        ecCurve = EcCurve.P256,
                        isHardwareBacked = false,
                        secureAreaDisplayName = "Secure Area Name"
                    ),
                    DocumentInfoScreenState.KeyInformation(
                        counter = 2,
                        validFrom = "16-07-2023",
                        validUntil = "23-07-2023",
                        domain = "Domain",
                        usagesCount = 0,
                        issuerDataBytesCount = "Issuer 2".toByteArray().count(),
                        keyPurposes = KeyPurpose.SIGN,
                        ecCurve = EcCurve.ED25519,
                        isHardwareBacked = true,
                        secureAreaDisplayName = "Secure Area Name"

                    )
                )
            ),
            onRefreshCredentials = {},
            onShowDocumentElements = {},
            onDeleteDocument = {},
            onConfirmDocumentDelete = {}
        ) {}
    }
}