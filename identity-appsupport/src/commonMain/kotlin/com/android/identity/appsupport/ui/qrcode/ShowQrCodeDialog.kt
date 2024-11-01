package com.android.identity.appsupport.ui.qrcode

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import identitycredential.identity_appsupport.generated.resources.Res
import identitycredential.identity_appsupport.generated.resources.show_qr_code_dialog_qr_content_description
import io.github.alexzhirkevich.qrose.rememberQrCodePainter
import org.jetbrains.compose.resources.stringResource

/**
 * Renders a QR code and shows it in a dialog.
 *
 * @param title The title of the dialog.
 * @param description The description text to include in the dialog.
 * @param dismissButton The text for the dismiss button.
 * @param data the QR code to show, e.g. mdoc:owBjMS4... or https://github.com/....
 * @param onDismiss called when the dismiss button is pressed.
 * @param modifier A [Modifier] or `null`.
 */
@Composable
fun ShowQrCodeDialog(
    title: String,
    description: String,
    dismissButton: String,
    data: String,
    onDismiss: () -> Unit,
    modifier: Modifier? = null
) {
    val painter = rememberQrCodePainter(
        data = data,
    )

    AlertDialog(
        modifier = modifier ?: Modifier,
        title = { Text(text = title) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(text = description)

                Row(
                    modifier = Modifier.align(Alignment.CenterHorizontally)
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(shape = RoundedCornerShape(16.dp))
                            .background(Color.White)
                    ) {
                        Image(
                            painter = painter,
                            contentDescription = stringResource(Res.string.show_qr_code_dialog_qr_content_description),
                            modifier = Modifier
                                .size(300.dp)
                                .padding(16.dp)
                        )
                    }
                }
            }
        },
        onDismissRequest = onDismiss,
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = { onDismiss() }) {
                Text(dismissButton)
            }
        }
    )
}
