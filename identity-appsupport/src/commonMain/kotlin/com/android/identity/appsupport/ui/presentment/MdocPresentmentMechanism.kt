package com.android.identity.appsupport.ui.presentment

import com.android.identity.cbor.DataItem
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.mdoc.transport.MdocTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration

/**
 * A [PresentmentMechanism] to use with [PresentmentModel] for ISO/IEC 18013-5:2021 proximity presentations.
 *
 * @property transport a [MdocTransport] connected to the remote mdoc reader.
 * @property eDeviceKey the ephemeral device key for the session.
 * @property encodedDeviceEngagement the Device Engagement.
 * @property handover the handover.
 * @property engagementDuration the time engagement took if known, `null` otherwise.
 * @property allowMultipleRequests if true, multiple requests are allowed.
 */
class MdocPresentmentMechanism(
    val transport: MdocTransport,
    val eDeviceKey: EcPrivateKey,
    val encodedDeviceEngagement: ByteString,
    val handover: DataItem,
    val engagementDuration: Duration?,
    val allowMultipleRequests: Boolean
): PresentmentMechanism {

    override fun close() {
        CoroutineScope(Dispatchers.IO).launch() { transport.close() }
    }
}