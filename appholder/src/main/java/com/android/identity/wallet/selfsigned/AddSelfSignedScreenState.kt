package com.android.identity.wallet.selfsigned

import android.os.Parcelable
import com.android.identity.wallet.document.DocumentColor
import com.android.identity.wallet.support.CurrentSecureArea
import com.android.identity.wallet.support.SecureAreaSupportState
import com.android.identity.wallet.support.toSecureAreaState
import com.android.identity.wallet.util.DocumentData
import com.android.identity.wallet.util.ProvisioningUtil
import kotlinx.parcelize.Parcelize

@Parcelize
data class AddSelfSignedScreenState(
    val documentType: String = DocumentData.MDL_DOCTYPE,
    val cardArt: DocumentColor = DocumentColor.Green,
    val documentName: String = "Driving License",
    val currentSecureArea: CurrentSecureArea = ProvisioningUtil.defaultSecureArea.toSecureAreaState(),
    val numberOfMso: Int = 3,
    val maxUseOfMso: Int = 1,
    val validityInDays: Int = 30,
    val minValidityInDays: Int = 10,
    val secureAreaSupportState: SecureAreaSupportState? = null,
    val provisionDirectAccessCredential: Boolean = false,
) : Parcelable
