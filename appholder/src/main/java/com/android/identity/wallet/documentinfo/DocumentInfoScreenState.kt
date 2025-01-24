package com.android.identity.wallet.documentinfo

import androidx.compose.runtime.Immutable
import com.android.identity.crypto.EcCurve
import com.android.identity.securearea.KeyPurpose
import com.android.identity.wallet.document.DocumentColor

@Immutable
data class DocumentInfoScreenState(
    val isLoading: Boolean = false,
    val documentName: String = "",
    val documentType: String = "",
    val documentColor: DocumentColor = DocumentColor.Green,
    val provisioningDate: String = "",
    val lastTimeUsedDate: String = "",
    val isSelfSigned: Boolean = false,
    val authKeys: List<KeyInformation> = emptyList(),
    val daKeys: List<DaKeyInformation> = emptyList(),
    val isDeletingPromptShown: Boolean = false,
    val isDeleted: Boolean = false
) {

    @Immutable
    data class KeyInformation(
        val counter: Int,
        val validFrom: String,
        val validUntil: String,
        val domain: String,
        val issuerDataBytesCount: Int,
        val usagesCount: Int,
        val keyPurposes: KeyPurpose,
        val ecCurve: EcCurve,
        val isHardwareBacked: Boolean,
        val secureAreaDisplayName: String
    )

    @Immutable
    data class DaKeyInformation(
        val counter: Int,
        val validFrom: String,
        val validUntil: String,
        val domain: String,
        val issuerDataBytesCount: Int,
        val usagesCount: Int,
        val secureAreaDisplayName: String
    )
}