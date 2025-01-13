package com.android.identity.mdoc.nfc

import com.android.identity.cbor.CborArray
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Simple
import com.android.identity.crypto.EcPublicKey
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.engagement.EngagementGenerator
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.nfc.CommandApdu
import com.android.identity.nfc.HandoverRequestRecord
import com.android.identity.nfc.HandoverSelectRecord
import com.android.identity.nfc.NdefMessage
import com.android.identity.nfc.NdefRecord
import com.android.identity.nfc.Nfc
import com.android.identity.nfc.ResponseApdu
import com.android.identity.nfc.ServiceParameterRecord
import com.android.identity.nfc.ServiceSelectRecord
import com.android.identity.nfc.TnepStatusRecord
import com.android.identity.util.Logger
import com.android.identity.util.toHex
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.ByteStringBuilder
import kotlinx.io.bytestring.append
import kotlinx.io.bytestring.encodeToByteString

/**
 * Helper used for NFC engagement on the mdoc side.
 *
 * This implements NFC engagement according to ISO/IEC 18013-5:2021.
 *
 * APDUs received from the NFC tag reader should be passed to the [processApdu] method.
 *
 * @param eDeviceKey EDeviceKey as per ISO/IEC 18013-5:2021.
 * @param onHandoverComplete the function to call when handover is complete.
 * @param onError the function to call if an error occurs.
 * @param staticHandoverMethods list of connection methods to offer the mdoc reader, must contain at least one
 * element, or null to not use NFC static handover.
 * @param negotiatedHandoverPicker a function to choose one of the connection methods from the mdoc reader or
 * null to not use NFC negotiated handover.
 */
class MdocNfcEngagementHelper(
    val eDeviceKey: EcPublicKey,
    val onHandoverComplete: (
        connectionMethods: List<ConnectionMethod>,
        encodedDeviceEngagement: ByteString,
        handover: DataItem) -> Unit,
    val onError: (error: Throwable) -> Unit,
    val staticHandoverMethods: List<ConnectionMethod>? = null,
    val negotiatedHandoverPicker: ((connectionMethods: List<ConnectionMethod>) -> ConnectionMethod)? = null,
) {
    companion object {
        private const val TAG = "MdocNfcEngagementHelper"
    }

    init {
        val static = staticHandoverMethods != null
        val negotiated = negotiatedHandoverPicker != null
        check(static || negotiated) {
            "Must use either static or negotiated handover, none are selected"
        }
        check(!(static && negotiated)) {
            "Can't use both static and negotiated handover at the same time"
        }
        if (static) {
            check(!staticHandoverMethods.isEmpty()) {
                "Must have at least one ConnectionMethod for static handover"
            }
        }
    }

    private enum class NegotiatedHandoverState {
        NOT_STARTED,
        EXPECT_SERVICE_SELECT,
        EXPECT_HANDOVER_REQUEST_MESSAGE,
        EXPECT_HANDOVER_SELECT_MESSAGE,
    }

    private var negotiatedHandoverState = NegotiatedHandoverState.NOT_STARTED

    private var selectedFileId: Int = 0
    private var selectedFilePayload: ByteString = ByteString()
    private var ndefApplicationSelected = false
    private var inError = false

    private fun raiseError(errorMessage: String, cause: Throwable? = null) {
        inError = true
        onError(Error(errorMessage, cause))
    }

    private suspend fun processSelectApplication(command: CommandApdu): ResponseApdu {
        val requestedApplicationId = command.payload
        if (requestedApplicationId != Nfc.NDEF_APPLICATION_ID) {
            raiseError("SelectApplication: Expected NDEF AID but got ${requestedApplicationId.toByteArray().toHex()}")
            return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
        }
        ndefApplicationSelected = true
        return ResponseApdu(Nfc.RESPONSE_STATUS_SUCCESS)
    }

    private suspend fun processSelectFile(command: CommandApdu): ResponseApdu {
        check(ndefApplicationSelected) { "NDEF application not yet selected" }
        selectedFileId = decodeShort(command.payload.toByteArray())
        when (selectedFileId) {
            Nfc.NDEF_CAPABILITY_CONTAINER_FILE_ID -> {
                val fileWriteAccessCondition = if (negotiatedHandoverPicker != null) 0x00 else 0xff.toByte()
                // TODO: Specify CAPABILITIES FILE in a less obscure fashion.
                selectedFilePayload = ByteString(
                    0x00.toByte(),
                    0x0f.toByte(),
                    0x20.toByte(),
                    0x7f.toByte(),
                    0xff.toByte(),
                    0x7f.toByte(),
                    0xff.toByte(),
                    0x04.toByte(),
                    0x06.toByte(),
                    0xe1.toByte(),
                    0x04.toByte(),
                    0x7f.toByte(),
                    0xff.toByte(),
                    0x00.toByte(),           // file read access condition (allow read)
                    fileWriteAccessCondition // file write access condition (allow/disallow write)
                )
            }
            // TODO: This is the fileId in the CAPABILITIES file listed above. Use constant when fixing the above TODO.
            0xe104 -> {
                if (negotiatedHandoverPicker != null) {
                    val initialNdefMessage = NdefMessage(
                        records = listOf(
                            ServiceParameterRecord(
                                tnepVersion = 0x10,
                                serviceNameUri = Nfc.SERVICE_NAME_CONNECTION_HANDOVER,
                                tnepCommunicationMode = 0x00,
                                wtInt = 0,
                                nWait = 15,
                                maxNdefSize = 0xffff
                            ).generateNdefRecord()
                        )
                    )
                    val initialNdefMessagePayload = initialNdefMessage.encode()
                    val bsb = ByteStringBuilder()
                    bsb.append((initialNdefMessagePayload.size/0x100).and(0xff).toByte())
                    bsb.append(initialNdefMessagePayload.size.and(0xff).toByte())
                    bsb.append(initialNdefMessagePayload)
                    selectedFilePayload = bsb.toByteString()
                    negotiatedHandoverState = NegotiatedHandoverState.EXPECT_SERVICE_SELECT
                } else {
                    val encodedDeviceEngagement = EngagementGenerator(
                        eDeviceKey,
                        EngagementGenerator.ENGAGEMENT_VERSION_1_0
                    ).generate()

                    val handoverSelectMessage = generateHandoverSelectMessage(
                        methods = staticHandoverMethods!!,
                        encodedDeviceEngagement = encodedDeviceEngagement,
                        skipUuids = false,
                    )
                    val hsPayload = handoverSelectMessage.encode()

                    val handover = CborArray.builder()
                        .add(hsPayload)                      // Handover Select message
                        .add(Simple.NULL)                    // Handover Request message
                        .end()
                        .build()

                    val bsb = ByteStringBuilder()
                    bsb.append((hsPayload.size/0x100).and(0xff).toByte())
                    bsb.append(hsPayload.size.and(0xff).toByte())
                    bsb.append(hsPayload)

                    onHandoverComplete(
                        staticHandoverMethods!!,
                        ByteString(encodedDeviceEngagement),
                        handover
                    )

                    selectedFilePayload = bsb.toByteString()
                }
            }
            else -> {
                raiseError("SelectFile: Unexpected File ID $selectedFileId")
                return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
            }
        }
        return ResponseApdu(Nfc.RESPONSE_STATUS_SUCCESS)
    }

    private suspend fun processReadBinary(command: CommandApdu): ResponseApdu {
        check(selectedFileId != 0) { "No file selected" }
        val offset = command.p1*0x100 + command.p2
        val length = command.le
        val data = selectedFilePayload.substring(offset, offset + length)
        return ResponseApdu(Nfc.RESPONSE_STATUS_SUCCESS, data)
    }

    private var updateBinaryData: ByteStringBuilder? = null

    private suspend fun ndefTransactHandleServiceSelect(message: NdefMessage): NdefMessage {
        check(message.records.size == 1) { "Expected just a single record for service select" }
        val serviceSelectRecord = ServiceSelectRecord.fromNdefRecord(message.records[0])
            ?: throw Error("Service Select record not found")
        check(serviceSelectRecord.serviceName == Nfc.SERVICE_NAME_CONNECTION_HANDOVER) {
            "Expected service ${Nfc.SERVICE_NAME_CONNECTION_HANDOVER} found ${serviceSelectRecord.serviceName}"
        }

        // From NDEF Exchange Protocol 1.0: 4.3 TNEP Status Message
        // If the NFC Tag Device has received a Service Select Message with a known
        // Service, it will return a TNEP Status Message to confirm a successful
        // Service selection.
        //
        negotiatedHandoverState = NegotiatedHandoverState.EXPECT_HANDOVER_REQUEST_MESSAGE
        return NdefMessage(listOf(TnepStatusRecord(0).toNdefRecord()))
    }

    private suspend fun ndefTransactHandleHandoverRequest(message: NdefMessage): NdefMessage {
        // Handover Request Record must be the first record in Handover Request Message..
        val hrRecord = HandoverRequestRecord.fromNdefRecord(message.records[0])
            ?: throw Error("Handover Request Record not the first in message")
        check(hrRecord.version == 0x15) {
            "Expected Connection Handover version 1.5, got ${byteArrayOf(hrRecord.version.toByte()).toHex()}"
        }

        val availableConnectionMethods = mutableListOf<ConnectionMethod>()
        for (record in message.records.subList(1, message.records.size)) {
            ConnectionMethod.fromNdefRecord(record, MdocTransport.Role.MDOC_READER, null)?.let {
                availableConnectionMethods.add(it)
            }
        }
        if (availableConnectionMethods.isEmpty()) {
            throw Error("No supported connection methods found in Handover Request method")
        }
        val disambiguatedConnectionMethods = ConnectionMethod.disambiguate(availableConnectionMethods)

        val selectedMethod = negotiatedHandoverPicker!!(disambiguatedConnectionMethods)

        // Handover Select message is defined in section 5.2 Handover Select Message
        //
        val encodedDeviceEngagement = EngagementGenerator(
            eDeviceKey,
            EngagementGenerator.ENGAGEMENT_VERSION_1_0
        ).generate()

        // When doing Negotiated Handover, the standard says to don't include the UUIDs in Handover Select
        // message for mdoc central client mode:
        //
        //   The following requirements apply for including the UUID field during NFC device engagement:
        //
        //     — for Negotiated Handover, if the mdoc reader supports mdoc central client mode, it shall include a
        //       UUID in the Handover Request message, to be used for mdoc central client mode;
        //     — for Negotiated Handover, if the mdoc chooses to use mdoc peripheral server mode, it shall include a
        //       UUID in the Handover Select message, to be used for mdoc peripheral server mode;
        //     — for Static Handover, the mdoc shall send one UUID in the handover select message, to be used for
        //       mdoc central client mode, mdoc peripheral server mode or both.
        //
        // Reference: ISO/IEC 18013-5:2021 clause 8.3.3.1.1.2 Device engagement contents
        //
        val skipUuids = selectedMethod is ConnectionMethodBle && selectedMethod.supportsCentralClientMode == true
        val handoverSelectMessage = generateHandoverSelectMessage(
            methods = listOf(selectedMethod),
            encodedDeviceEngagement = encodedDeviceEngagement,
            skipUuids = skipUuids,
        )

        val handover = CborArray.builder()
            .add(handoverSelectMessage.encode())  // Handover Select message
            .add(message.encode())                // Handover Request message
            .end()
            .build()

        negotiatedHandoverState = NegotiatedHandoverState.EXPECT_HANDOVER_SELECT_MESSAGE

        onHandoverComplete(
            listOf(selectedMethod),
            ByteString(encodedDeviceEngagement),
            handover
        )

        return handoverSelectMessage
    }

    private fun generateHandoverSelectMessage(
        methods: List<ConnectionMethod>,
        encodedDeviceEngagement: ByteArray,
        skipUuids: Boolean,
    ): NdefMessage {
        val auxiliaryReferences = mutableListOf<String>("mdoc")
        val carrierConfigurationRecords = mutableListOf<NdefRecord>()
        val alternativeCarrierRecords = mutableListOf<NdefRecord>()
        for (method in methods) {
            val ndefRecordAndAlternativeCarrier = method.toNdefRecord(
                auxiliaryReferences = auxiliaryReferences,
                role = MdocTransport.Role.MDOC,
                skipUuids = skipUuids
            )!!
            carrierConfigurationRecords.add(ndefRecordAndAlternativeCarrier.first)
            alternativeCarrierRecords.add(ndefRecordAndAlternativeCarrier.second)
        }
        val handoverSelectRecord = HandoverSelectRecord(
            version = 0x15,
            embeddedMessage = NdefMessage(alternativeCarrierRecords)
        )
        return NdefMessage(
            listOf(
                handoverSelectRecord.generateNdefRecord(),
                NdefRecord(
                    tnf = NdefRecord.Tnf.EXTERNAL_TYPE,
                    type = "iso.org:18013:deviceengagement".encodeToByteString(),
                    id = "mdoc".encodeToByteString(),
                    payload = ByteString(encodedDeviceEngagement)
                )
            ) + carrierConfigurationRecords
        )
    }

    private suspend fun ndefTransact(message: NdefMessage): NdefMessage {
        return when (negotiatedHandoverState) {
            NegotiatedHandoverState.NOT_STARTED -> throw Error("Unexpected message - Negotiated Handover not started")
            NegotiatedHandoverState.EXPECT_SERVICE_SELECT -> ndefTransactHandleServiceSelect(message)
            NegotiatedHandoverState.EXPECT_HANDOVER_REQUEST_MESSAGE -> ndefTransactHandleHandoverRequest(message)
            NegotiatedHandoverState.EXPECT_HANDOVER_SELECT_MESSAGE -> throw Error("Negotiated Handover is complete")
        }
    }

    private suspend fun processUpdateBinaryNdefMessage(message: NdefMessage): ResponseApdu {
        check(selectedFileId != 0) { "No file selected" }
        try {
            val responseNdefMessage = ndefTransact(message)
            val responseNdefMessagePayload = responseNdefMessage.encode()
            val bsb = ByteStringBuilder()
            bsb.append((responseNdefMessagePayload.size/0x100).and(0xff).toByte())
            bsb.append(responseNdefMessagePayload.size.and(0xff).toByte())
            bsb.append(responseNdefMessagePayload)
            selectedFilePayload = bsb.toByteString()
            return ResponseApdu(Nfc.RESPONSE_STATUS_SUCCESS)
        } catch (error: Throwable) {
            raiseError(error.message!!)
            return ResponseApdu(Nfc.RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS)
        }
    }

    private suspend fun processUpdateBinary(command: CommandApdu): ResponseApdu {
        // This code implements the procedure specified by
        //
        //  Type 4 Tag Technical Specification Version 1.2 section 7.5.5 NDEF Write Procedure
        //
        val offset = command.p1*0x100 + command.p2
        val data = command.payload
        if (offset == 0) {
            if (data.size == 2) {
                val lenInData = decodeShort(data.toByteArray())
                if (lenInData == 0) {
                    if (updateBinaryData != null) {
                        raiseError("Got reset but is already active")
                        return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
                    }
                    updateBinaryData = ByteStringBuilder()
                } else {
                    if (updateBinaryData == null) {
                        raiseError("Got length but we are not active")
                        return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
                    }
                    if (lenInData != updateBinaryData!!.size) {
                        raiseError("Length $lenInData doesn't match received data of ${updateBinaryData!!.size} bytes")
                        return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
                    }

                    // At this point we got the whole NDEF message that the reader wanted to send.
                    val ndefMessage = NdefMessage.fromEncoded(updateBinaryData!!.toByteString().toByteArray())
                    updateBinaryData = null
                    return processUpdateBinaryNdefMessage(ndefMessage)
                }
            } else {
                if (updateBinaryData != null) {
                    raiseError("Got data in single UPDATE_BINARY but we are already active")
                    return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
                }
                val ndefMessage = NdefMessage.fromEncoded(data.toByteArray(2))
                return processUpdateBinaryNdefMessage(ndefMessage)
            }
        } else if (offset == 1) {
            raiseError("Unexpected offset $offset")
            return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
        } else {
            // offset >= 2
            if (updateBinaryData == null) {
                raiseError("Got data but we are not active")
                return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
            }
            // Writes must be sequential
            if (offset - 2 != updateBinaryData!!.size) {
                raiseError("Got data to write at offset $offset but we currently have ${updateBinaryData!!.size}")
                return ResponseApdu(Nfc.RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
            }
            updateBinaryData!!.append(data)
        }
        return ResponseApdu(Nfc.RESPONSE_STATUS_SUCCESS)
    }

    /**
     * Process APDUs received from the remote NFC tag reader.
     *
     * @param command The command received.
     * @return the response.
     */
    suspend fun processApdu(command: CommandApdu): ResponseApdu {
        if (inError) {
            Logger.w(TAG, "processApdu: Already in error state, responding to APDU with status 6f00")
            return ResponseApdu(Nfc.RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS)
        }
        try {
            when (command.ins) {
                Nfc.INS_SELECT -> {
                    when (command.p1) {
                        Nfc.INS_SELECT_P1_FILE -> return processSelectFile(command)
                        Nfc.INS_SELECT_P1_APPLICATION -> return processSelectApplication(command)
                    }
                }
                Nfc.INS_READ_BINARY -> return processReadBinary(command)
                Nfc.INS_UPDATE_BINARY -> return processUpdateBinary(command)
            }
            raiseError("Command APDU $command not supported, returning 6d00")
            return ResponseApdu(Nfc.RESPONSE_STATUS_ERROR_INSTRUCTION_NOT_SUPPORTED_OR_INVALID)
        } catch (error: Throwable) {
            raiseError("Error processing APDU: ${error.message}", error)
            return ResponseApdu(Nfc.RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS)
        }
    }
}

private fun decodeShort(encoded: ByteArray) =
    encoded[0].toInt().and(0xff).shl(8) + encoded[1].toInt().and(0xff)
