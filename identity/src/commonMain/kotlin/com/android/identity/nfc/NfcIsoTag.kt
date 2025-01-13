package com.android.identity.nfc

import kotlinx.coroutines.delay
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration

/**
 * Class representing a ISO/IEC 14443-4 tag.
 *
 * This is an abstract super class intended for OS-specific code to implement the [transceive] method.
 */
abstract class NfcIsoTag {
    /**
     * Sends an APDU to the tag and waits for a response APDU.
     *
     * @param apdu the [CommandApdu] to send.
     * @return the [ResponseApdu] which was received.
     * @throws NfcTagLostException if the tag was lost.
     */
    abstract suspend fun transceive(apdu: CommandApdu): ResponseApdu

    /**
     * Selects an application according to ISO 7816-4 clause 11.2.2.
     *
     * @param applicationId the application to select, e.g. [Nfc.NDEF_APPLICATION_ID].
     * @throws NfcCommandFailedException if the command fails.
     */
    suspend fun selectApplication(applicationId: ByteString) {
        // ISO 7816-4 clause 11.2.2
        val response = transceive(
            CommandApdu(
                cla = 0,
                ins = Nfc.INS_SELECT,
                p1 = Nfc.INS_SELECT_P1_APPLICATION,
                p2 = Nfc.INS_SELECT_P2_APPLICATION,
                payload = applicationId,
                le = 0
            )
        )
        if (response.status != Nfc.RESPONSE_STATUS_SUCCESS) {
            throw NfcCommandFailedException("Error selecting application, status ${response.statusHexString}", response.status)
        }
    }

    /**
     * Selects a file according to ISO 7816-4 clause 11.2.2.
     *
     * @param fileId the identifier for the file to select, e.g. [Nfc.NDEF_CAPABILITY_CONTAINER_FILE_ID].
     * @throws NfcCommandFailedException if the command fails.
     */
    suspend fun selectFile(fileId: Int) {
        //
        val response = transceive(
            CommandApdu(
                cla = 0,
                ins = Nfc.INS_SELECT,
                p1 = Nfc.INS_SELECT_P1_FILE,
                p2 = Nfc.INS_SELECT_P2_FILE,
                payload = ByteString(encodeShort(fileId)),
                le = 0
            )
        )
        if (response.status != Nfc.RESPONSE_STATUS_SUCCESS) {
            throw NfcCommandFailedException("Error selecting file, status ${response.statusHexString}", response.status)
        }
    }

    /**
     * Reads binary data according to ISO 7816-4 clause 11.3.3.
     *
     * @param offset offset of where to read from.
     * @param length amount of data to read, must be positive.
     * @return the data which was read.
     * @throws NfcCommandFailedException if the command fails.
     */
    suspend fun readBinary(offset: Int, length: Int): ByteArray {
        require(length > 0) { "Length must be positive" }
        require(offset >= 0 && offset < 0x10000) { "Offset must be between 0 and 0x10000" }
        val response = transceive(
            CommandApdu(
                cla = 0,
                ins = Nfc.INS_READ_BINARY,
                p1 = offset / 0x100,
                p2 = offset.and(0xff),
                payload = ByteString(),
                le = length
            )
        )
        if (response.status != Nfc.RESPONSE_STATUS_SUCCESS) {
            throw NfcCommandFailedException("Error READ BINARY, status ${response.statusHexString}", response.status)
        }
        return response.payload.toByteArray()
    }

    /**
     * Updates binary data according to ISO 7816-4 clause 11.3.5.
     *
     * @param offset offset of where to update data.
     * @param data the data to write, cannot be larger than 255 bytes.
     * @throws NfcCommandFailedException if the command fails.
     */
    suspend fun updateBinary(offset: Int, data: ByteArray) {
        require(data.size > 0) { "Data to write must be non-empty" }
        require(data.size < 256) { "Data cannot be larger than 255 bytes" }

        //
        val response = transceive(
            CommandApdu(
                cla = 0,
                ins = 0xd6,
                p1 = offset / 0x100,
                p2 = offset.and(0xff),
                payload = ByteString(data),
                le = 0
            )
        )
        if (response.status != Nfc.RESPONSE_STATUS_SUCCESS) {
            throw NfcCommandFailedException("Error UPDATE BINARY, status ${response.statusHexString}", response.status)
        }
    }

    /**
     * Reads NDEF data according to NFC Forum Type 4 Tag section 7.5.4.
     *
     * @param wtInt Minimum waiting time as per NFC Forum Tag NDEF Exchange Protocol section 4.1.6.
     * @param nWait Maximum number of waiting time extensions as per NFC Forum Tag NDEF Exchange Protocol section 4.1.7.
     * @return the message that was read.
     */
    suspend fun ndefReadMessage(
        wtInt: Int = 0,
        nWait: Int = 0
    ): NdefMessage {
        var nWait_ = nWait
        var replyLen: Int
        do {
            replyLen = decodeShort(readBinary(0x0000, 2))
            if (replyLen > 0) {
                break
            }

            // As per [TNEP] 4.1.7 if the tag sends an empty NDEF message it means that
            // it's requesting extra time... honor this if we can.
            if (nWait_ > 0) {
                val tWait = Duration.fromWtInt(wtInt)
                delay(tWait)
                nWait_--
            } else {
                throw IllegalStateException("NDEF message with length 0 but no time extensions left")
            }
        } while (true)
        return NdefMessage.fromEncoded(readBinary(2, replyLen))
    }

    /**
     * Exchanges NDEF messages according to NFC Forum Tag NDEF Exchange Protocol section 5.
     *
     * @param ndefMessage the message to write.
     * @param wtInt Minimum waiting time as per NFC Forum Tag NDEF Exchange Protocol section 4.1.6.
     * @param nWait Maximum number of waiting time extensions as per NFC Forum Tag NDEF Exchange Protocol section 4.1.7.
     * @return the message which was read.
     */
    suspend fun ndefTransact(
        ndefMessage: NdefMessage,
        wtInt: Int,
        nWait: Int
    ): NdefMessage {
        val encodedNdefMessage = ndefMessage.encode()

        // See Type 4 Tag Technical Specification Version 1.2 section 7.5.5 NDEF Write Procedure
        // for how this is done.

        // Check to see if we can merge the three UPDATE_BINARY messages into a single message.
        // This is allowed as per [T4T] 7.5.5 NDEF Write Procedure:
        //
        //   If the entire NDEF Message can be written with a single UPDATE_BINARY
        //   Command, the Reader/Writer MAY write NLEN and ENLEN (Symbol 6), as
        //   well as the entire NDEF Message (Symbol 5) using a single
        //   UPDATE_BINARY Command. In this case the Reader/Writer SHALL
        //   proceed to Symbol 5 and merge Symbols 5 and 6 operations into a single
        //   UPDATE_BINARY Command.
        //
        // For debugging, this optimization can be turned off by setting this to |true|:
        if (!NDEF_TRANSACT_BYPASS_UPDATE_BINARY_OPTIMIZATION && encodedNdefMessage.size < 256 - 2) {
            updateBinary(0, encodeShort(encodedNdefMessage.size) + encodedNdefMessage)
        } else {
            // First command is UPDATE_BINARY to reset length
            updateBinary(0, encodeShort(0))

            // Subsequent commands are UPDATE_BINARY with payload, chopped into bits no longer
            // than 255 bytes each
            var offset = 0
            var remaining = encodedNdefMessage.size
            while (remaining > 0) {
                val numBytesToWrite = remaining.coerceAtMost(255)
                val bytesToWrite = encodedNdefMessage.copyOfRange(offset, offset + numBytesToWrite)
                updateBinary(offset + 2, bytesToWrite)
                remaining -= numBytesToWrite
                offset += numBytesToWrite
            }

            // Final command is UPDATE_BINARY to write the length
            updateBinary(0, encodeShort(encodedNdefMessage.size))
        }
        val tWait = Duration.fromWtInt(wtInt)
        delay(tWait)

        // Now read NDEF file...
        return ndefReadMessage(wtInt, nWait)
    }

    companion object {
        private const val TAG = "NfcIsoTag"

        // Only used for debugging
        private const val NDEF_TRANSACT_BYPASS_UPDATE_BINARY_OPTIMIZATION = false
    }
}

private fun encodeShort(value: Int): ByteArray =
    byteArrayOf(value.shr(8).and(0xff).toByte(), value.and(0xff).toByte())

private fun decodeShort(encoded: ByteArray) =
    encoded[0].toInt().and(0xff).shl(8) + encoded[1].toInt().and(0xff)
