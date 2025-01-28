package com.android.identity_credential.wallet.logging

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class DocumentUpdateCheckEvent(
    timestamp: Instant = Clock.System.now(),
    var documentId: String = "",
    id: String = ""
) : Event(timestamp, id)