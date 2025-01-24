package com.android.identity.wallet.selfsigned

import android.os.Parcelable
import com.android.identity.wallet.support.CurrentSecureArea
import com.android.identity.wallet.util.Field
import com.android.identity.wallet.support.SecureAreaSupportState
import kotlinx.parcelize.Parcelize

data class SelfSignedDocumentData(
    val provisionInfo: ProvisionInfo,
    val fields: List<Field>
)

@Parcelize
data class ProvisionInfo(
    val docType: String,
    var docName: String,
    var docColor: Int,
    val currentSecureArea: CurrentSecureArea,
    val secureAreaSupportState: SecureAreaSupportState,
    val validityInDays: Int,
    val minValidityInDays: Int,
    val numberMso: Int,
    val maxUseMso: Int,
    val provisionDirectAccess: Boolean,
) : Parcelable