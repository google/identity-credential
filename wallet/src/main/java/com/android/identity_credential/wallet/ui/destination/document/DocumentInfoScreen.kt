package com.android.identity_credential.wallet.ui.destination.document

import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.Image
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ColorMatrix
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.android.identity.android.securearea.ScreenLockRequiredException
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.DocumentModel
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.SettingsModel
import com.android.identity_credential.wallet.navigation.WalletDestination
import com.android.identity_credential.wallet.ui.KeyValuePairText
import com.android.identity_credential.wallet.ui.ScreenWithAppBarAndBackButton
import com.android.identity_credential.wallet.ui.durationFromNowText
import com.android.identity_credential.wallet.util.asFormattedDateTimeInCurrentTimezone
import kotlinx.coroutines.launch
import kotlinx.datetime.Instant
import java.util.*


private const val TAG = "DocumentInfoScreen"

fun formatDate(timestamp: Instant): String {
    return timestamp.asFormattedDateTimeInCurrentTimezone
}

@Composable
fun DocumentInfoScreen(
    context: Context,
    documentId: String,
    documentModel: DocumentModel,
    settingsModel: SettingsModel,
    onNavigate: (String) -> Unit,
) {
    val coroutineScope = rememberCoroutineScope()

    val documentInfo = documentModel.getDocumentInfo(documentId)
    if (documentInfo == null) {
        Logger.w(TAG, "No card with id $documentId")
        onNavigate(WalletDestination.Main.route)
        return
    }

    var showErrorMessage by remember { mutableStateOf<String?>(null) }
    if (showErrorMessage != null) {
        AlertDialog(
            onDismissRequest = { showErrorMessage = null },
            title = { Text(text = stringResource(R.string.document_info_screen_error_dialog_title)) },
            text = {
                Text(showErrorMessage!!)
            },
            confirmButton = {
                Button(
                    onClick = {
                        showErrorMessage = null
                    }) {
                    Text(stringResource(R.string.document_info_screen_error_dialog_confirm_button))
                }
            }
        )
    }

    var showRequestUpdateDialog by remember { mutableStateOf(false) }
    if (showRequestUpdateDialog) {
        val remoteDeletionCheckedState = remember { mutableStateOf(false) }
        val notifyApplicationCheckedState = remember { mutableStateOf(true) }
        AlertDialog(
            onDismissRequest = { showRequestUpdateDialog = false },
            title = { Text(text = stringResource(R.string.document_info_screen_request_update_title)) },
            text = {
                Column() {
                    Text(stringResource(R.string.document_info_screen_request_update_message))
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = remoteDeletionCheckedState.value, onCheckedChange = {
                            remoteDeletionCheckedState.value = it
                        })
                        Text(stringResource(R.string.document_info_screen_request_update_remote_deletion_checkbox_string))
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = notifyApplicationCheckedState.value, onCheckedChange = {
                            notifyApplicationCheckedState.value = it
                        })
                        Text(stringResource(R.string.document_info_screen_request_update_notify_application_checkbox_string))
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showRequestUpdateDialog = false

                        coroutineScope.launch {
                            try {
                                documentModel.developerModeRequestUpdate(
                                    documentInfo,
                                    remoteDeletionCheckedState.value,
                                    notifyApplicationCheckedState.value
                                )
                            } catch (e: Throwable) {
                                showErrorMessage = "Unexpected exception: $e"
                            }

                        }
                    }) {
                    Text(stringResource(R.string.document_info_screen_request_update_confirm_button))
                }
            },
            dismissButton = {
                Button(
                    onClick = { showRequestUpdateDialog = false }) {
                    Text(stringResource(R.string.document_info_screen_request_update_dismiss_button))
                }
            }
        )
    }

    var showDeleteConfirmationDialog by remember { mutableStateOf(false) }
    if (showDeleteConfirmationDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirmationDialog = false },
            title = { Text(text = stringResource(R.string.document_info_screen_confirm_deletion_title)) },
            text = {
                Text(stringResource(R.string.document_info_screen_confirm_deletion_message))
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteConfirmationDialog = false
                        coroutineScope.launch {
                            documentModel.deleteCard(documentInfo)
                            onNavigate(WalletDestination.PopBackStack.route)
                        }
                    }) {
                    Text(stringResource(R.string.document_info_screen_confirm_deletion_confirm_button))
                }
            },
            dismissButton = {
                Button(
                    onClick = { showDeleteConfirmationDialog = false }) {
                    Text(stringResource(R.string.document_info_screen_confirm_deletion_dismiss_button))
                }
            }
        )
    }

    var showMenu by remember { mutableStateOf(false) }
    ScreenWithAppBarAndBackButton(
        title = stringResource(R.string.document_info_screen_title),
        onBackButtonClick = { onNavigate(WalletDestination.PopBackStack.route) },
        actions = {
            IconButton(onClick = { showMenu = true }) { Icon(Icons.Default.Menu, contentDescription = null) }
            DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                DropdownMenuItem(
                    text = { Text(text = stringResource(R.string.document_info_screen_menu_item_check_for_update)) },
                    leadingIcon = { Icon(Icons.Outlined.Refresh, contentDescription = null) },
                    onClick = {
                        coroutineScope.launch {
                            try {
                                documentModel.refreshCard(documentInfo)
                            } catch (e: ScreenLockRequiredException) {
                                showErrorMessage = context.getString(R.string.document_info_screen_refresh_error_missing_screenlock)
                            } catch (e: Throwable) {
                                e.printStackTrace()
                                showErrorMessage = "Unexpected exception while refreshing: $e"
                            }
                        }
                    }
                )
                DropdownMenuItem(
                    text = { Text(text = stringResource(R.string.document_info_screen_menu_item_show_data)) },
                    leadingIcon = { Icon(Icons.Outlined.Info, contentDescription = null) },
                    onClick = {
                        onNavigate(WalletDestination.DocumentInfo.getRouteWithArguments(
                            listOf(
                                Pair(WalletDestination.DocumentInfo.Argument.DOCUMENT_ID, documentInfo.documentId),
                                Pair(WalletDestination.DocumentInfo.Argument.SECTION, "details"),
                                Pair(WalletDestination.DocumentInfo.Argument.AUTH_REQUIRED,
                                    documentInfo.requireUserAuthenticationToViewDocument),
                            )
                        ))
                        showMenu = false
                    }
                )
                DropdownMenuItem(
                    text = { Text(text = stringResource(R.string.document_info_screen_menu_item_show_credentials)) },
                    leadingIcon = {
                        Icon(
                            painter = painterResource(id = R.drawable.certificate_icon),
                            contentDescription = null
                        )
                    },
                    onClick = {
                        onNavigate(
                            WalletDestination.DocumentInfo.getRouteWithArguments(
                                listOf(
                                    Pair(WalletDestination.DocumentInfo.Argument.DOCUMENT_ID, documentInfo.documentId),
                                    Pair(WalletDestination.DocumentInfo.Argument.SECTION, "credentials")
                                )
                            )
                        )
                        showMenu = false
                    }
                )
                DropdownMenuItem(
                    text = { Text(text = stringResource(R.string.document_info_screen_menu_activities_log)) },
                    leadingIcon = { Icon(Icons.Outlined.Info, contentDescription = null) },
                    onClick = {
                        onNavigate(WalletDestination.DocumentInfo.getRouteWithArguments(
                            listOf(
                                Pair(WalletDestination.DocumentInfo.Argument.DOCUMENT_ID, documentInfo.documentId),
                                Pair(WalletDestination.DocumentInfo.Argument.SECTION, "activities")
                            )
                        ))
                        showMenu = false
                    }
                )
                DropdownMenuItem(
                    text = { Text(text = stringResource(R.string.document_info_screen_menu_item_delete)) },
                    leadingIcon = { Icon(Icons.Outlined.Delete, contentDescription = null) },
                    onClick = {
                        showMenu = false;
                        showDeleteConfirmationDialog = true
                    }
                )
                if (settingsModel.developerModeEnabled.value == true) {
                    Divider()
                    DropdownMenuItem(
                        text = { Text(text = stringResource(R.string.document_info_screen_menu_item_request_update)) },
                        leadingIcon = {
                            Icon(
                                painter = painterResource(id = R.drawable.experiment_icon),
                                contentDescription = null
                            )
                        },
                        onClick = {
                            showMenu = false
                            showRequestUpdateDialog = true
                        }
                    )
                }
            }
        }
    ) {

        // Hidden feature to cause a Doc Update: click the artwork five times
        //
        var imageNumClicks by remember { mutableStateOf(0) }
        Column(Modifier.padding(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Image(
                    bitmap = documentInfo.documentArtwork.asImageBitmap(),
                    contentDescription = stringResource(R.string.accessibility_artwork_for, documentInfo.name),
                    colorFilter = if (documentInfo.attentionNeeded) {
                        ColorFilter.colorMatrix(ColorMatrix().apply { setToSaturation(0.1f) })
                    } else {
                        null
                    },
                    modifier = Modifier
                        .height(200.dp).fillMaxSize()
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                            onClick = {
                                imageNumClicks += 1
                                if (imageNumClicks == 5) {
                                    imageNumClicks = 0
                                    Logger.i(TAG, "document art clicked 5 times!")
                                    coroutineScope.launch {
                                        try {
                                            documentModel.developerModeRequestUpdate(
                                                documentInfo,
                                                false,
                                                true
                                            )
                                        } catch (e: Throwable) {
                                            showErrorMessage = "Unexpected exception: $e"
                                        }
                                    }
                                }
                            }
                        )
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = documentInfo.typeName,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.padding(8.dp)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            KeyValuePairText(stringResource(R.string.document_info_screen_data_name), documentInfo.name)
            KeyValuePairText(stringResource(R.string.document_info_screen_data_issuer), documentInfo.issuerName)
            KeyValuePairText(stringResource(R.string.document_info_screen_data_status), documentInfo.status)
            KeyValuePairText(
                stringResource(R.string.document_info_screen_data_last_update_check),
                durationFromNowText(documentInfo.lastRefresh).replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.US) else it.toString() }
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Image(
                    bitmap = documentInfo.issuerLogo.asImageBitmap(),
                    contentDescription = stringResource(R.string.accessibility_artwork_for, documentInfo.issuerName),
                    modifier = Modifier.height(150.dp).fillMaxSize()
                )
            }
        }
    }
}
