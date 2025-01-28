package com.android.identity_credential.wallet.ui.destination.document

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import com.android.identity.util.toBase64Url
import com.android.identity_credential.wallet.DocumentModel
import com.android.identity_credential.wallet.EventInfo
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.logging.EventLogger
import com.android.identity_credential.wallet.navigation.WalletDestination
import com.android.identity_credential.wallet.ui.KeyValuePairText
import com.android.identity_credential.wallet.ui.ScreenWithAppBarAndBackButton
import kotlinx.coroutines.launch
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

private const val TAG = "EventLogScreen"

/**
 * Formats a timestamp string into a human-readable format.
 *
 * This function takes a timestamp string (expected to be in the format "yyyy-MM-dd HH:mm:ss")
 * and converts it into a more readable format like "Wed Oct 02 5:20 PM".
 *
 * @param timestampString The timestamp string to format.
 * @return The formatted timestamp string.
 */
fun formatTimestamp(timestampString: String): String {
    // TODO: Consider using KMM version: https://github.com/Kotlin/kotlinx-datetime.
    // Convert the input timestamp to ISO-8601 format
    val isoTimestamp = timestampString.replace(" ", "T") + "Z"

    // Parse the ISO formatted timestamp as an Instant
    val instant = Instant.parse(isoTimestamp)

    // Convert the instant to LocalDateTime in the system's default timezone
    val localDateTime = instant.toLocalDateTime(TimeZone.currentSystemDefault())

    // Manually format the LocalDateTime to the desired output format
    val dayOfWeek = localDateTime.dayOfWeek.name.take(3).lowercase().replaceFirstChar { it.uppercase() } // e.g., "Wed"
    val month = localDateTime.month.name.take(3).lowercase().replaceFirstChar { it.uppercase() }         // e.g., "Oct"
    val day = localDateTime.dayOfMonth                                // e.g., "02"
    val hour = if (localDateTime.hour > 12) localDateTime.hour - 12 else localDateTime.hour
    val minute = localDateTime.minute.toString().padStart(2, '0')     // e.g., "20"
    val amPm = if (localDateTime.hour >= 12) "PM" else "AM"

    return "$dayOfWeek $month $day $hour:$minute $amPm"
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun EventLogScreen(
    documentId: String,
    documentModel: DocumentModel,
    navController: NavHostController
) {
    val coroutineScope = rememberCoroutineScope()
    // TODO: this needs a ViewModel layer
    val eventInfos = remember {
        mutableStateListOf<EventInfo>().apply {
            coroutineScope.launch {
                addAll(documentModel.getEventInfos(documentId))
            }
        }
    }

    ScreenWithAppBarAndBackButton(
        title = stringResource(R.string.document_info_screen_menu_activities_log),
        onBackButtonClick = { navController.popBackStack() }
    ) {
        if (eventInfos.isEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Text(
                    modifier = Modifier.padding(8.dp),
                    text = stringResource(R.string.document_info_screen_menu_activities_log_screen_empty),
                    style = MaterialTheme.typography.titleLarge,
                    textAlign = TextAlign.Center
                )
            }
        } else {
            Column(
                verticalArrangement = Arrangement.Top,
                modifier = Modifier.weight(1f)
            ) {
                LazyColumn {
                    items(eventInfos) { eventInfo ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(4.dp)
                                .clickable {
                                    // Pass documentId and timestamp as arguments
                                    val encodedDocId = documentId.toByteArray().toBase64Url()
                                    navController.navigate("${WalletDestination.EventDetails.route}/$encodedDocId/${eventInfo.timestamp}")
                                },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            val requesterInfo = eventInfo.requesterInfo ?: EventLogger.RequesterInfo(
                                requester = EventLogger.Requester.Anonymous(),
                                shareType = EventLogger.ShareType.UNKNOWN
                            )

                            val shareTypeText = when (requesterInfo.shareType) {
                                EventLogger.ShareType.SHARED_IN_PERSON -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_shared_in_person)
                                EventLogger.ShareType.SHARED_WITH_APPLICATION -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_shared_with_application)
                                EventLogger.ShareType.SHARED_WITH_WEBSITE -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_shared_with_website)
                                EventLogger.ShareType.UNKNOWN -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_unknown_share)
                            }

                            KeyValuePairText(
                                requesterInfo.requester.toString(), "${formatTimestamp(eventInfo.timestamp)} . $shareTypeText"
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun EventDetailsScreen(
    documentModel: DocumentModel,
    navController: NavHostController,
    documentId: String,
    timestamp: String
) {
    // Retrieve the event based on documentId and timestamp
    val coroutineScope = rememberCoroutineScope()
    // TODO: this needs a ViewModel layer
    val eventInfos = remember {
        mutableStateListOf<EventInfo>().apply {
            coroutineScope.launch {
                addAll(documentModel.getEventInfos(documentId))
            }
        }
    }
    val eventInfo = eventInfos.find { it.timestamp == timestamp }

    ScreenWithAppBarAndBackButton(
        title = "",
        onBackButtonClick = { navController.popBackStack() }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
        ) {
            if (eventInfo == null) {
                Text(text = "Event not found")
            } else {
                Text(
                    text = documentModel.getDocumentInfo(documentId)?.name ?: "Unknown",
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(8.dp))

                val requesterInfo = eventInfo.requesterInfo ?: EventLogger.RequesterInfo(
                    requester = EventLogger.Requester.Anonymous(),
                    shareType = EventLogger.ShareType.UNKNOWN
                )

                val shareTypeText = when (requesterInfo.shareType) {
                    EventLogger.ShareType.SHARED_IN_PERSON -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_shared_in_person)
                    EventLogger.ShareType.SHARED_WITH_APPLICATION -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_shared_with_application)
                    EventLogger.ShareType.SHARED_WITH_WEBSITE -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_shared_with_website)
                    EventLogger.ShareType.UNKNOWN -> stringResource(id = R.string.document_info_screen_menu_activities_log_screen_unknown_share)
                }

                KeyValuePairText(
                    stringResource(id = R.string.document_info_screen_menu_activities_log_screen_share_type),
                    shareTypeText
                )
                Spacer(modifier = Modifier.height(8.dp))
                KeyValuePairText(
                    stringResource(id = R.string.document_info_screen_menu_activities_log_screen_requester),
                    requesterInfo.requester.toString()
                )
                Spacer(modifier = Modifier.height(8.dp))

                val fieldsList = eventInfo.requestedFields.replace("_", " ")
                    .split(",")

                KeyValuePairText(
                    stringResource(id = R.string.document_info_screen_menu_activities_log_screen_data_shared),
                    ""
                )
                Card(
                    modifier = Modifier
                        .padding(16.dp)
                        .fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        fieldsList.chunked(2).forEach { pair ->
                            Row(modifier = Modifier.fillMaxWidth()) {
                                Text(
                                    text = pair.getOrNull(0) ?: "",
                                    modifier = Modifier.weight(1f),
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = pair.getOrNull(1) ?: "",
                                    modifier = Modifier.weight(1f),
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}