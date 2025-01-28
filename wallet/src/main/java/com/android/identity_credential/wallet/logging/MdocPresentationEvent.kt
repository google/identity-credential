package com.android.identity_credential.wallet.logging

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class MdocPresentationEvent (
    timestamp: Instant = Clock.System.now(),
    var documentId: String = "",
    var sessionTranscript: ByteArray,
    var deviceRequestCbor: ByteArray,
    var deviceResponseCbor: ByteArray,
    val requesterInfo: EventLogger.RequesterInfo = EventLogger.RequesterInfo(
        requester = EventLogger.Requester.Anonymous(),
        shareType = EventLogger.ShareType.UNKNOWN),
    id: String = ""
) : Event(timestamp, id)