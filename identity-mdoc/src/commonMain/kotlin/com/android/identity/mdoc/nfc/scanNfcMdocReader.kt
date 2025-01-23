package com.android.identity.mdoc.nfc

import com.android.identity.cbor.DataItem
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.mdoc.transport.MdocTransportFactory
import com.android.identity.mdoc.transport.MdocTransportOptions
import com.android.identity.nfc.scanNfcTag
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import kotlinx.coroutines.delay
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.seconds

const private val TAG = "scanNfcMdocReader"

/**
 * The result of performing NFC engagement as a mdoc reader.
 *
 * @property transport the [MdocTransport] connected to the remote mdoc.
 * @property encodedDeviceEngagement the Device Engagement.
 * @property handover the handover.
 */
data class ScanNfcMdocReaderResult(
    val transport: MdocTransport,
    val encodedDeviceEngagement: ByteString,
    val handover: DataItem,
)

/**
 * Performs NFC engagement as a reader.
 *
 * This uses [scanNfcTag] to show a dialog prompting the user to tap the mdoc.
 *
 * @param message the message to display in the NFC tag scanning dialog.
 * @param options the [MdocTransportOptions] used to create new [MdocTransport] instances.
 * @param transportFactory the factory used to create [MdocTransport] instances.
 * @param selectConnectionMethod used to choose a connection method if the remote mdoc is using NFC static handover.
 * @param negotiatedHandoverConnectionMethods the connection methods to offer if the remote mdoc is using NFC
 * Negotiated Handover.
 * @return a [ScanNfcMdocReaderResult], `null` if the dialog was dismissed or [selectConnectionMethod] returned `null`.
 */
suspend fun scanNfcMdocReader(
    message: String,
    options: MdocTransportOptions,
    transportFactory: MdocTransportFactory = MdocTransportFactory.Default,
    selectConnectionMethod: suspend (connectionMethods: List<ConnectionMethod>) -> ConnectionMethod?,
    negotiatedHandoverConnectionMethods: List<ConnectionMethod>,
): ScanNfcMdocReaderResult? {
    // Start creating transports for Negotiated Handover and start advertising these
    // immediately. This helps with connection time because the holder's device will
    // get a chance to opportunistically read the UUIDs which helps reduce scanning
    // time.
    //
    val negotiatedHandoverTransports = negotiatedHandoverConnectionMethods.map {
        val transport = transportFactory.createTransport(
            it,
            MdocTransport.Role.MDOC_READER,
            options
        )
        transport.advertise()
        transport
    }
    // Make sure we don't leak connections...
    val transportsToClose = negotiatedHandoverTransports.toMutableList()

    try {
        val handoverResult = scanNfcTag(
            message = message,
            tagInteractionFunc = { tag, updateMessage ->
                mdocReaderNfcHandover(
                    tag = tag,
                    negotiatedHandoverConnectionMethods = negotiatedHandoverTransports.map { it.connectionMethod },
                )
            }
        )
        if (handoverResult == null) {
            return null
        } else {
            val connectionMethod = if (handoverResult.connectionMethods.size == 1) {
                handoverResult.connectionMethods[0]
            } else {
                selectConnectionMethod(handoverResult.connectionMethods)
            }
            if (connectionMethod == null) {
                return null
            } else {
                // Now that we're connected, close remaining transports and see if one of the warmed-up
                // transports was chosen (can happen for negotiated handover, never for static handover)
                //
                var transport: MdocTransport? = null
                transportsToClose.forEach {
                    if (it.connectionMethod == connectionMethod) {
                        transport = it
                    } else {
                        Logger.i(TAG, "Closing connection with CM ${it.connectionMethod}")
                        it.close()
                    }
                }
                transportsToClose.clear()
                if (transport == null) {
                    transport = transportFactory.createTransport(
                        connectionMethod,
                        MdocTransport.Role.MDOC_READER,
                        options
                    )
                }
                return ScanNfcMdocReaderResult(
                    transport,
                    handoverResult.encodedDeviceEngagement,
                    handoverResult.handover,
                )
            }
        }
    } finally {
        // Close listening transports that went unused.
        transportsToClose.forEach {
            Logger.i(TAG, "Closing connection with CM ${it.connectionMethod}")
            it.close()
        }
    }
}
