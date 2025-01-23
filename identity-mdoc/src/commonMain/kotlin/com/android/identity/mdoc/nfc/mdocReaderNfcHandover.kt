package com.android.identity.mdoc.nfc

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Simple
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.nfc.HandoverRequestRecord
import com.android.identity.nfc.HandoverSelectRecord
import com.android.identity.nfc.NdefMessage
import com.android.identity.nfc.NdefRecord
import com.android.identity.nfc.Nfc
import com.android.identity.nfc.NfcCommandFailedException
import com.android.identity.nfc.NfcIsoTag
import com.android.identity.nfc.ServiceParameterRecord
import com.android.identity.nfc.ServiceSelectRecord
import com.android.identity.nfc.TnepStatusRecord
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString

const private val TAG = "mdocReaderNfcHandover"

/**
 * The result of a successful NFC handover operation
 *
 * @property connectionMethods the possible connection methods for the mdoc reader to connect to.
 * @property encodedDeviceEngagement the bytes of DeviceEngagement.
 * @property handover the handover value.
 */
data class MdocReaderNfcHandoverResult(
    val connectionMethods: List<ConnectionMethod>,
    val encodedDeviceEngagement: ByteString,
    val handover: DataItem,
)

/**
 * Perform NFC Engagement as a mdoc reader.
 *
 * @param tag the [NfcIsoTag] representing a NFC connection to the mdoc.
 * @param negotiatedHandoverConnectionMethods the connection methods to offer if the remote mdoc is using NFC
 * negotiated handover.
 * @return a [MdocReaderNfcHandoverResult] if the handover was successful or `null` if the tag isn't an NDEF tag.
 * @throws Throwable if an error occurs during handover.
 */
suspend fun mdocReaderNfcHandover(
    tag: NfcIsoTag,
    negotiatedHandoverConnectionMethods: List<ConnectionMethod>,
): MdocReaderNfcHandoverResult? {
    try {
        tag.selectApplication(Nfc.NDEF_APPLICATION_ID)
    } catch (e: NfcCommandFailedException) {
        // This is returned by Android when locked phone is being tapped by an mdoc reader. Once unlocked the
        // user will be shown UI to convey another tap should happen. So since we're the mdoc reader, we
        // want to keep scanning...
        //
        if (e.status == Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND) {
            Logger.i(TAG, "NDEF application not found, continuing scanning")
            return null
        }
    }
    tag.selectFile(Nfc.NDEF_CAPABILITY_CONTAINER_FILE_ID)
    // CC file is 15 bytes long
    val ccFile = tag.readBinary(0, 15)
    check(ccFile.size == 15) { "CC file is ${ccFile.size} bytes, expected 15" }

    val ndefFileId = (ccFile[9].toInt() and 0xff) * 256 + (ccFile[10].toInt() and 0xff)

    tag.selectFile(ndefFileId)

    val initialNdefMessage = tag.ndefReadMessage()

    // First see if we should use negotiated handover by looking for the Handover Service parameter record...
    val hspr = initialNdefMessage.records.mapNotNull {
        val parsed = ServiceParameterRecord.fromNdefRecord(it)
        if (parsed?.serviceNameUri == "urn:nfc:sn:handover") parsed else null
    }.firstOrNull()
    if (hspr == null) {
        val (encodedDeviceEngagement, connectionMethods) = parseHandoverSelectMessage(initialNdefMessage, null)
        check(!connectionMethods.isEmpty()) { "No connection methods in Handover Select" }
        val handover = CborArray.builder()
            .add(initialNdefMessage.encode()) // Handover Select message
            .add(Simple.NULL)                 // Handover Request message
            .end()
            .build()

        return MdocReaderNfcHandoverResult(
            connectionMethods = connectionMethods,
            encodedDeviceEngagement = ByteString(encodedDeviceEngagement),
            handover = handover,
        )
    }

    // Select the service, the resulting NDEF message is specified in
    // in Tag NDEF Exchange Protocol Technical Specification Version 1.0
    // section 4.3 TNEP Status Message
    val serviceSelectionResponse = tag.ndefTransact(
        NdefMessage(listOf(
            ServiceSelectRecord(Nfc.SERVICE_NAME_CONNECTION_HANDOVER).toNdefRecord()
        )),
        hspr.wtInt,
        hspr.nWait
    )

    val tnepStatusRecord = serviceSelectionResponse.records.find { TnepStatusRecord.fromNdefRecord(it) != null }
        ?: throw IllegalArgumentException("Service selection: no TNEP status record")
    val tnepStatus = TnepStatusRecord.fromNdefRecord(tnepStatusRecord)!!
    require(tnepStatus.status == 0x00) { "Service selection: Unexpected status ${tnepStatus.status}" }

    // Now send Handover Request message, the resulting NDEF message is Handover Response..
    //
    val hrMessage = generateHandoverRequestMessage(negotiatedHandoverConnectionMethods)
    val hsMessage = tag.ndefTransact(hrMessage, hspr.wtInt, hspr.nWait)

    var bleUuid: UUID? = null
    for (cm in negotiatedHandoverConnectionMethods) {
        if (cm is ConnectionMethodBle) {
            if (cm.peripheralServerModeUuid != null) {
                bleUuid = cm.peripheralServerModeUuid
                break
            }
            if (cm.centralClientModeUuid != null) {
                bleUuid = cm.centralClientModeUuid
                break
            }
        }
    }
    Logger.i(TAG, "Supplementing with UUID $bleUuid")
    val (encodedDeviceEngagement, connectionMethods) = parseHandoverSelectMessage(hsMessage, bleUuid)
    check(connectionMethods.size >= 1) { "No Alternative Carriers in HS message" }

    val handover = CborArray.builder()
        .add(hsMessage.encode()) // Handover Select message
        .add(hrMessage.encode()) // Handover Request message
        .end()
        .build()

    return MdocReaderNfcHandoverResult(
        connectionMethods = connectionMethods,
        encodedDeviceEngagement = ByteString(encodedDeviceEngagement),
        handover = handover,
    )
}

private fun generateHandoverRequestMessage(
    methods: List<ConnectionMethod>,
): NdefMessage {
    val auxiliaryReferences = listOf<String>()
    val carrierConfigurationRecords = mutableListOf<NdefRecord>()
    val alternativeCarrierRecords = mutableListOf<NdefRecord>()
    for (method in methods) {
        val ndefRecordAndAlternativeCarrier = method.toNdefRecord(
            auxiliaryReferences = auxiliaryReferences,
            role = MdocTransport.Role.MDOC_READER,
            skipUuids = false
        )
        if (ndefRecordAndAlternativeCarrier != null) {
            carrierConfigurationRecords.add(ndefRecordAndAlternativeCarrier.first)
            alternativeCarrierRecords.add(ndefRecordAndAlternativeCarrier.second)
        }
    }
    val handoverRequestRecord = HandoverRequestRecord(
        version = 0x15,
        embeddedMessage = NdefMessage(alternativeCarrierRecords)
    )
    // TODO: make it possible for caller to specify readerEngagement
    val encodedReaderEngagement = Cbor.encode(
        CborMap.builder()
            .put(0L, "1.0")
            .end()
            .build()
    )
    return NdefMessage(
        listOf(
            handoverRequestRecord.generateNdefRecord(),
            NdefRecord(
                tnf = NdefRecord.Tnf.EXTERNAL_TYPE,
                type = "iso.org:18013:readerengagement".encodeToByteString(),
                id = "mdocreader".encodeToByteString(),
                payload = ByteString(encodedReaderEngagement)
            )
        ) + carrierConfigurationRecords
    )
}

@OptIn(ExperimentalStdlibApi::class)
private fun parseHandoverSelectMessage(
    message: NdefMessage,
    uuid: UUID?,
): Pair<ByteArray, List<ConnectionMethod>> {
    var hasHandoverSelectRecord = false

    var encodedDeviceEngagement: ByteString? = null
    val connectionMethods = mutableListOf<ConnectionMethod>()
    for (r in message.records) {
        // Handle Handover Select record for NFC Forum Connection Handover specification
        // version 1.5 (encoded as 0x15 below).
        val hsRecord = HandoverSelectRecord.fromNdefRecord(r)
        if (hsRecord != null) {
            check(hsRecord.version == 0x15) { "Only Connection Handover version 1.5 is supported" }
            hasHandoverSelectRecord = true
        }
        if (r.tnf == NdefRecord.Tnf.EXTERNAL_TYPE &&
            r.type.decodeToString() == "iso.org:18013:deviceengagement" &&
            r.id.decodeToString() == "mdoc") {
            encodedDeviceEngagement = r.payload
        }

        if (r.tnf == NdefRecord.Tnf.MIME_MEDIA || r.tnf == NdefRecord.Tnf.EXTERNAL_TYPE) {
            val cm = ConnectionMethod.fromNdefRecord(r, MdocTransport.Role.MDOC, uuid)
            if (cm != null) {
                connectionMethods.add(cm)
            }
        }
    }
    if (!hasHandoverSelectRecord) {
        throw Error("Handover Select record not found")
    }
    if (encodedDeviceEngagement == null) {
        throw Error("DeviceEngagement record not found")
    }
    return Pair(encodedDeviceEngagement.toByteArray(), connectionMethods)
}
