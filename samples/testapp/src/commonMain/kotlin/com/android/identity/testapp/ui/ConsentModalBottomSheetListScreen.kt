package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.android.identity.documenttype.knowntypes.DrivingLicense

enum class VerifierType(
    val description: String
) {
    KNOWN_VERIFIER("Known Verifier"),
    UNKNOWN_VERIFIER_PROXIMITY("Unknown Verifier (Proximity)"),
    UNKNOWN_VERIFIER_WEBSITE("Unknown Verifier (Website)"),
}

@Composable
fun ConsentModalBottomSheetListScreen(
    onConsentModalBottomSheetClicked: (mdlSampleRequest: String, verifierType: VerifierType) -> Unit,
) {
    val mdlRequests = remember {
        val documentType = DrivingLicense.getDocumentType()
        documentType.cannedRequests
    }

    LazyColumn(
        modifier = Modifier.padding(8.dp)
    ) {

        for (verifierType in VerifierType.values()) {
            item {
                Text(
                    text = verifierType.description,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            for (request in mdlRequests) {
                item {
                    TextButton(onClick = { onConsentModalBottomSheetClicked(request.id, verifierType) }) {
                        Text("${request.displayName}")
                    }
                }
            }
        }
    }
}
