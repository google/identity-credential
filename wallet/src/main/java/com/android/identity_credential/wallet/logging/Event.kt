package com.android.identity_credential.wallet.logging

import com.android.identity.cbor.annotation.CborSerializable
import kotlinx.datetime.Instant

@CborSerializable
sealed class Event(
    open val timestamp: Instant,
    var id: String = ""  // filled by EventLogger
) {
    companion object
}