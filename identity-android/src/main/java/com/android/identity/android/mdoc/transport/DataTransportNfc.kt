/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.android.mdoc.transport

import android.content.Context
import android.nfc.NdefRecord
import android.nfc.cardemulation.HostApduService
import android.nfc.tech.IsoDep
import android.util.Pair
import com.android.identity.android.util.NfcUtil
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodNfc
import com.android.identity.util.Logger
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Arrays
import java.util.Locale
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedTransferQueue
import java.util.concurrent.TimeUnit

/**
 * NFC data transport
 */
class DataTransportNfc(
    context: Context,
    role: Role,
    private val connectionMethod: ConnectionMethodNfc,
    options: DataTransportOptions
) : DataTransport(context, role, options) {
    var _isoDep: IsoDep? = null

    var listenerRemainingChunks: ArrayList<ByteArray>? = null
    var listenerTotalChunks = 0
    var listenerRemainingBytesAvailable = 0
    var listenerLeReceived = -1

    var writerQueue: BlockingQueue<ByteArray> = LinkedTransferQueue()
    var listenerStillActive = false
    var incomingMessage = ByteArrayOutputStream()
    var numChunksReceived = 0
    private var dataTransferAidSelected = false
    private var hostApduService: HostApduService? = null
    private var connectedAsMdoc = false

    override fun setEDeviceKeyBytes(encodedEDeviceKeyBytes: ByteArray) {
        // Not used.
    }

    private fun connectAsMdoc() {
        // From ISO 18013-5 8.3.3.1.2 Data retrieval using near field communication (NFC):
        //
        // NOTE 2: The minimum and maximum possible values for the command data field limit are
        // 'FF' and 'FF FF', i.e. the limit is between 255 and 65 535 bytes (inclusive). The
        // minimum and maximum possible values for the response data limit are '01 00' and
        // '01 00 00', i.e. the limit is between 256 and 65 536 bytes (inclusive).
        listenerStillActive = true
        setupListenerWritingThread()
        addActiveConnection(this)
        connectedAsMdoc = true
    }

    private fun setupListenerWritingThread() {
        val transceiverThread: Thread = object : Thread() {
            override fun run() {
                while (listenerStillActive) {
                    var messageToSend: ByteArray?
                    messageToSend = try {
                        writerQueue.poll(1000, TimeUnit.MILLISECONDS)
                    } catch (e: InterruptedException) {
                        continue
                    }
                    if (messageToSend == null) {
                        continue
                    }
                    Logger.dHex(TAG, "Sending message", messageToSend)
                    if (listenerLeReceived == -1) {
                        reportError(Error("ListenerLeReceived not set"))
                        return
                    }

                    // First message we send will be a response to the reader's
                    // ENVELOPE command.. further messages will be in response
                    // the GET RESPONSE commands. So we chop up this data in chunks
                    // so it's easy to hand off responses...
                    val chunks = ArrayList<ByteArray>()
                    val data = encapsulateInDo53(messageToSend)
                    var offset = 0
                    val maxChunkSize = listenerLeReceived
                    do {
                        var size = data.size - offset
                        if (size > maxChunkSize) {
                            size = maxChunkSize
                        }
                        val chunk = ByteArray(size)
                        System.arraycopy(data, offset, chunk, 0, size)
                        chunks.add(chunk)
                        offset += size
                    } while (offset < data.size)
                    Logger.d(TAG, "Have ${chunks.size} chunks..")
                    listenerRemainingChunks = chunks
                    listenerRemainingBytesAvailable = data.size
                    listenerTotalChunks = chunks.size
                    sendNextChunk()
                }
            }
        }
        transceiverThread.start()
    }

    private fun buildApduResponse(data: ByteArray, sw1: Int, sw2: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        try {
            baos.write(data)
        } catch (e: IOException) {
            throw IllegalStateException(e)
        }
        baos.write(sw1)
        baos.write(sw2)
        return baos.toByteArray()
    }

    /**
     * Called by reader when finding the [IsoDep] tag.
     *
     * @param isoDep the tag with [IsoDep] technology.
     */
    fun setIsoDep(isoDep: IsoDep) {
        this._isoDep = isoDep
    }

    private fun listenerSendResponse(apdu: ByteArray) {
        hostApduService!!.sendResponseApdu(apdu)
    }

    private fun nfcDataTransferProcessCommandApdu(
        hostApduService: HostApduService,
        apdu: ByteArray
    ): ByteArray? {
        var ret: ByteArray? = null
        this.hostApduService = hostApduService
        Logger.dHex(TAG, "nfcDataTransferProcessCommandApdu apdu", apdu)
        val commandType = NfcUtil.nfcGetCommandType(apdu)
        if (!dataTransferAidSelected) {
            if (commandType == NfcUtil.COMMAND_TYPE_SELECT_BY_AID) {
                ret = handleSelectByAid(apdu)
            }
        } else {
            ret = when (commandType) {
                NfcUtil.COMMAND_TYPE_ENVELOPE -> handleEnvelope(apdu)
                NfcUtil.COMMAND_TYPE_RESPONSE -> handleResponse()
                else -> {
                    Logger.w(TAG,"Unexpected APDU with commandType $commandType")
                    NfcUtil.STATUS_WORD_INSTRUCTION_NOT_SUPPORTED
                }
            }
        }
        return ret
    }

    private fun nfcDataTransferOnDeactivated(reason: Int) {
        Logger.d(TAG, "nfcDataTransferOnDeactivated reason $reason")
        if (dataTransferAidSelected) {
            Logger.d(TAG, "Acting on onDeactivated")
            dataTransferAidSelected = false
            reportDisconnected()
        } else {
            Logger.d(TAG, "Ignoring onDeactivated")
        }
    }

    private fun handleSelectByAid(apdu: ByteArray): ByteArray {
        if (apdu.size < 12) {
            Logger.w(TAG, "handleSelectByAid: unexpected APDU length ${apdu.size}")
            return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
        }
        if (Arrays.equals(apdu.copyOfRange(5, 12), NfcUtil.AID_FOR_MDL_DATA_TRANSFER)) {
            Logger.d(TAG, "handleSelectByAid: NFC data transfer AID selected")
            dataTransferAidSelected = true
            reportConnected()
            return NfcUtil.STATUS_WORD_OK
        }
        Logger.wHex(TAG, "handleSelectByAid: Unexpected AID selected in APDU", apdu)
        return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
    }

    private fun sendNextChunk() {
        val chunk = listenerRemainingChunks!!.removeAt(0)
        listenerRemainingBytesAvailable -= chunk.size
        val isLastChunk = listenerRemainingChunks!!.size == 0
        if (isLastChunk) {
            /* If Le ≥ the number of available bytes, the mdoc shall include all
             * available bytes in the response and set the status words to ’90 00’.
             */
            hostApduService!!.sendResponseApdu(buildApduResponse(chunk, 0x90, 0x00))
        } else {
            if (listenerRemainingBytesAvailable <= listenerLeReceived + 255) {
                /* If Le < the number of available bytes ≤ Le + 255, the mdoc shall
                 * include as many bytes in the response as indicated by Le and shall
                 * set the status words to ’61 XX’, where XX is the number of available
                 * bytes remaining. The mdoc reader shall respond with a GET RESPONSE
                 * command where Le is set to XX.
                 */
                val numBytesRemaining = listenerRemainingBytesAvailable - listenerLeReceived
                hostApduService!!.sendResponseApdu(
                    buildApduResponse(chunk, 0x61, numBytesRemaining and 0xff)
                )
            } else {
                /* If the number of available bytes > Le + 255, the mdoc shall include
                 * as many bytes in the response as indicated by Le and shall set the
                 * status words to ’61 00’. The mdoc readershall respond with a GET
                 * RESPONSE command where Le is set to the maximum length of the
                 * response data field that is supported by both the mdoc and the mdoc
                 * reader.
                 */
                hostApduService!!.sendResponseApdu(buildApduResponse(chunk, 0x61, 0x00))
            }
        }
    }

    private fun handleEnvelope(apdu: ByteArray): ByteArray? {
        Logger.d(TAG, "in handleEnvelope")
        if (apdu.size < 7) {
            return NfcUtil.STATUS_WORD_WRONG_LENGTH
        }
        var moreChunksComing = false
        val cla = apdu[0].toInt() and 0xff
        if (cla == 0x10) {
            moreChunksComing = true
        } else if (cla != 0x00) {
            reportError(Error("Unexpected value $cla in CLA of APDU"))
            return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
        }
        val data = apduGetData(apdu)
        if (data == null) {
            reportError(Error("Malformed APDU"))
            return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
        }
        if (data.size == 0) {
            reportError(Error("Received ENVELOPE with no data"))
            return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
        }
        val le = apduGetLe(apdu)
        numChunksReceived += try {
            incomingMessage.write(data)
            1
        } catch (e: IOException) {
            reportError(e)
            return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
        }
        if (moreChunksComing) {
            /* For all ENVELOPE commands in a chain except the last one, Le shall be absent, since
             * no data is expected in the response to these commands.
             */
            if (le != 0) {
                reportError(Error("More chunks are coming but LE is not zero"))
                return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
            }
            return NfcUtil.STATUS_WORD_OK
        }

        /* For the last ENVELOPE command in a chain, Le shall be set to the maximum length
         * of the response data field that is supported by both the mdoc and the mdoc reader.
         *
         *  We'll need this for later.
         */if (listenerLeReceived != 0) {
            listenerLeReceived = le
        }
        val encapsulatedMessage = incomingMessage.toByteArray()
        Logger.d(
            TAG, String.format(
                Locale.US, "Received %d bytes in %d chunk(s)",
                encapsulatedMessage.size, numChunksReceived
            )
        )
        incomingMessage.reset()
        numChunksReceived = 0
        val message = extractFromDo53(encapsulatedMessage)
        if (message == null) {
            reportError(Error("Error extracting message from DO53 encoding"))
            return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
        }
        Logger.d(TAG, String.format(Locale.US, "reportMessage %d bytes", message.size))
        reportMessageReceived(message)
        // Defer response...
        return null
    }

    private fun handleResponse(): ByteArray? {
        Logger.d(TAG, "in handleResponse")
        if (listenerRemainingChunks == null || listenerRemainingChunks!!.size == 0) {
            reportError(Error("GET RESPONSE but we have no outstanding chunks"))
            return null
        }
        sendNextChunk()
        return null
    }

    private fun apduGetLe(apdu: ByteArray): Int {
        val dataLength = apduGetDataLength(apdu)
        val haveExtendedLc = apdu[4].toInt() == 0x00
        val dataOffset = if (haveExtendedLc) 7 else 5
        val leOffset = dataOffset + dataLength
        val leNumBytes = apdu.size - dataOffset - dataLength
        if (leNumBytes < 0) {
            Logger.w(TAG, "leNumBytes is negative")
            return 0
        }
        if (leNumBytes == 0) {
            return 0
        } else if (leNumBytes == 1) {
            return if (apdu[leOffset].toInt() == 0x00) {
                0x100
            } else apdu[leOffset].toInt() and 0xff
        } else if (leNumBytes == 2) {
            if (!haveExtendedLc) {
                Logger.w(TAG, "Don't have extended LC but leNumBytes is 2")
            }
            if (apdu[leOffset].toInt() == 0x00 && apdu[leOffset + 1].toInt() == 0x00) {
                return 0x10000
            }
            var le = (apdu[leOffset].toInt() and 0xff) * 0x100
            le += apdu[leOffset + 1].toInt() and 0xff
            return le
        } else if (leNumBytes == 3) {
            if (haveExtendedLc) {
                Logger.w(TAG, "leNumBytes is 3 but we have extended LC")
            }
            if (apdu[leOffset].toInt() != 0x00) {
                Logger.w(TAG, "Expected 0x00 for first LE byte")
            }
            if (apdu[leOffset + 1].toInt() == 0x00 && apdu[leOffset + 2].toInt() == 0x00) {
                return 0x10000
            }
            var le = (apdu[leOffset + 1].toInt() and 0xff) * 0x100
            le += apdu[leOffset + 2].toInt() and 0xff
            return le
        }
        Logger.w(TAG, String.format(Locale.US, "leNumBytes is %d bytes which is unsupported", leNumBytes))
        return 0
    }

    private fun apduGetDataLength(apdu: ByteArray): Int {
        var length = apdu[4].toInt() and 0xff
        if (length == 0x00) {
            length = (apdu[5].toInt() and 0xff) * 256
            length += apdu[6].toInt() and 0xff
        }
        return length
    }

    private fun apduGetData(apdu: ByteArray): ByteArray? {
        val length = apduGetDataLength(apdu)
        val offset = if (apdu[4].toInt() == 0x00) 7 else 5
        if (apdu.size < offset + length) {
            return null
        }
        val data = ByteArray(length)
        System.arraycopy(apdu, offset, data, 0, length)
        return data
    }

    private fun buildApdu(
        cla: Int,
        ins: Int,
        p1: Int,
        p2: Int,
        data: ByteArray?,
        le: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.write(cla)
        baos.write(ins)
        baos.write(p1)
        baos.write(p2)
        var isExtended = true
        if (le > 256 || (data != null && data.size > 256)) {
            isExtended = true
            baos.write(0x00)
        }
        if (data != null && data.size > 0) {
            if (isExtended && le > 256 && data.size < 256 || data.size > 256) {
                baos.write(data.size / 0x100)
                baos.write(data.size and 0xff)
            } else {
                baos.write(data.size)
            }
            try {
                baos.write(data)
            } catch (e: IOException) {
                throw IllegalStateException(e)
            }
        }
        if (le > 0) {
            if (le == 256) {
                baos.write(0x00)
            } else if (le < 256) {
                baos.write(le)
            } else {
                if (le == 65536) {
                    baos.write(0x00)
                    baos.write(0x00)
                } else {
                    baos.write(le / 0x100)
                    baos.write(le and 0xff)
                }
            }
        }
        return baos.toByteArray()
    }

    private fun encapsulateInDo53(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.write(0x53)
        if (data.size < 0x80) {
            baos.write(data.size)
        } else if (data.size < 0x100) {
            baos.write(0x81)
            baos.write(data.size)
        } else if (data.size < 0x10000) {
            baos.write(0x82)
            baos.write(data.size / 0x100)
            baos.write(data.size and 0xff)
        } else if (data.size < 0x1000000) {
            baos.write(0x83)
            baos.write(data.size / 0x10000)
            baos.write(data.size / 0x100 and 0xff)
            baos.write(data.size and 0xff)
        } else {
            throw IllegalStateException("Data length cannot be bigger than 0x1000000")
        }
        try {
            baos.write(data)
        } catch (e: IOException) {
            throw IllegalStateException(e)
        }
        return baos.toByteArray()
    }

    private fun extractFromDo53(encapsulatedData: ByteArray): ByteArray? {
        if (encapsulatedData.size < 2) {
            Logger.w(TAG, "DO53 length ${encapsulatedData.size}, expected at least 2")
            return null
        }
        val tag = encapsulatedData[0].toInt() and 0xff
        if (tag != 0x53) {
            Logger.w(TAG, "DO53 first byte is $tag, expected 0x53")
            return null
        }
        var length = encapsulatedData[1].toInt() and 0xff
        if (length > 0x83) {
            Logger.w(TAG, "DO53 first byte of length is $length")
            return null
        }
        var offset = 2
        if (length == 0x80) {
            Logger.w(TAG, "DO53 first byte of length is 0x80")
            return null
        } else if (length == 0x81) {
            length = encapsulatedData[2].toInt() and 0xff
            offset = 3
        } else if (length == 0x82) {
            length = (encapsulatedData[2].toInt() and 0xff) * 0x100
            length += encapsulatedData[3].toInt() and 0xff
            offset = 4
        } else if (length == 0x83) {
            length = (encapsulatedData[2].toInt() and 0xff) * 0x10000
            length += (encapsulatedData[3].toInt() and 0xff) * 0x100
            length += encapsulatedData[4].toInt() and 0xff
            offset = 5
        }
        if (encapsulatedData.size != offset + length) {
            Logger.w(TAG, "Malformed BER-TLV encoding, ${encapsulatedData.size} $offset $length")
            return null
        }
        val data = ByteArray(length)
        System.arraycopy(encapsulatedData, offset, data, 0, length)
        return data
    }

    override fun connect() {
        if (role === Role.MDOC) {
            connectAsMdoc()
        } else {
            connectAsMdocReader()
        }
    }

    private fun connectAsMdocReader() {
        if (_isoDep == null) {
            reportError(Error("NFC IsoDep not set"))
            return
        }
        val maxTransceiveLength = Math.min(connectionMethod.commandDataFieldMaxLength.toInt(), _isoDep!!.maxTransceiveLength)
        Logger.d(TAG, "maxTransceiveLength: $maxTransceiveLength")
        Logger.d(TAG, "isExtendedLengthApduSupported: ${_isoDep!!.isExtendedLengthApduSupported}")
        val transceiverThread: Thread = object : Thread() {
            override fun run() {
                try {
                    // The passed in mIsoDep is supposed to already be connected, so we can start
                    // sending APDUs right away...
                    reportConnected()
                    val selectCommand = buildApdu(
                        0x00, 0xa4, 0x04, 0x00,
                        NfcUtil.AID_FOR_MDL_DATA_TRANSFER, 0
                    )
                    Logger.dHex(TAG, "selectCommand", selectCommand)
                    val selectResponse = _isoDep!!.transceive(selectCommand)
                    Logger.dHex(TAG, "selectResponse", selectResponse)
                    if (!Arrays.equals(selectResponse, NfcUtil.STATUS_WORD_OK)) {
                        reportError(Error("Unexpected response to AID SELECT"))
                        return
                    }
                    while (_isoDep!!.isConnected) {
                        var messageToSend: ByteArray? = null
                        try {
                            messageToSend = writerQueue.poll(1000, TimeUnit.MILLISECONDS)
                            if (messageToSend == null) {
                                continue
                            }
                        } catch (e: InterruptedException) {
                            continue
                        }
                        if (messageToSend.size == 0) {
                            // This is an indication that we're disconnecting
                            break
                        }
                        Logger.dHex(TAG, "Sending message", messageToSend)
                        val data = encapsulateInDo53(messageToSend)

                        // Less 7 for the APDU header and 3 for LE
                        //
                        val maxChunkSize = maxTransceiveLength - 10
                        var offset = 0
                        var lastEnvelopeResponse: ByteArray? = null
                        do {
                            val moreChunksComing = offset + maxChunkSize < data.size
                            var size = data.size - offset
                            if (size > maxChunkSize) {
                                size = maxChunkSize
                            }
                            val chunk = ByteArray(size)
                            System.arraycopy(data, offset, chunk, 0, size)
                            var le = 0
                            if (!moreChunksComing) {
                                le = maxTransceiveLength
                            }
                            val envelopeCommand = buildApdu(
                                if (moreChunksComing) 0x10 else 0x00,
                                0xc3, 0x00, 0x00, chunk, le
                            )
                            Logger.dHex(TAG, "envelopeCommand", envelopeCommand)
                            val t0 = System.currentTimeMillis()
                            val envelopeResponse = _isoDep!!.transceive(envelopeCommand)
                            val t1 = System.currentTimeMillis()
                            val durationSec = (t1 - t0) / 1000.0
                            val bitsPerSec =
                                ((envelopeCommand.size + envelopeResponse.size) * 8 / durationSec).toInt()
                            Logger.d(TAG, String.format(
                                    "transceive() took %.2f sec for %d + %d bytes => %d bits/sec",
                                    durationSec,
                                    envelopeCommand.size,
                                    envelopeResponse.size,
                                    bitsPerSec
                                )
                            )
                            Logger.dHex(TAG, "Received", envelopeResponse)
                            offset += size
                            if (moreChunksComing) {
                                // Don't care about response.
                                Logger.dHex(TAG, "envResponse (more chunks coming)", envelopeResponse)
                            } else {
                                lastEnvelopeResponse = envelopeResponse
                            }
                        } while (offset < data.size)
                        val erl = lastEnvelopeResponse!!.size
                        if (erl < 2) {
                            reportError(Error("APDU response smaller than expected"))
                            return
                        }
                        var encapsulatedMessage: ByteArray
                        val status = ((lastEnvelopeResponse[erl - 2].toInt() and 0xff) * 0x100
                                + (lastEnvelopeResponse[erl - 1].toInt() and 0xff))
                        if (status == 0x9000) {
                            // Woot, entire response fit in the response APDU
                            //
                            encapsulatedMessage = ByteArray(erl - 2)
                            System.arraycopy(
                                lastEnvelopeResponse, 0, encapsulatedMessage, 0,
                                erl - 2
                            )
                        } else if (status and 0xff00 == 0x6100) {
                            // More bytes are coming, have to use GET RESPONSE
                            //
                            val baos = ByteArrayOutputStream()
                            baos.write(lastEnvelopeResponse, 0, erl - 2)
                            var leForGetResponse = maxTransceiveLength - 10
                            if (status and 0xff != 0) {
                                leForGetResponse = status and 0xff
                            }
                            while (true) {
                                val grCommand = buildApdu(
                                    0x00,
                                    0xc0, 0x00, 0x00, null, leForGetResponse
                                )
                                val t0 = System.currentTimeMillis()
                                val grResponse = _isoDep!!.transceive(grCommand)
                                val t1 = System.currentTimeMillis()
                                val durationSec = (t1 - t0) / 1000.0
                                val bitsPerSec =
                                    ((grCommand.size + grResponse.size) * 8 / durationSec).toInt()
                                Logger.d(
                                    TAG, String.format(
                                        "transceive() took %.2f sec for %d + %d bytes => %d bits/sec",
                                        durationSec,
                                        grCommand.size,
                                        grResponse.size,
                                        bitsPerSec
                                    )
                                )
                                val grrl = grResponse.size
                                if (grrl < 2) {
                                    reportError(Error("GetResponse APDU response smaller than expected"))
                                    return
                                }
                                val grrStatus =
                                    (grResponse[grrl - 2].toInt() and 0xff) * 0x100 + (grResponse[grrl - 1].toInt() and 0xff)
                                baos.write(grResponse, 0, grrl - 2)

                                // TODO: add runaway check
                                if (grrStatus == 0x9000) {
                                    /* If Le ≥ the number of available bytes, the mdoc shall include
                                     * all available bytes in the response and set the status words
                                     * to ’90 00’.
                                     */
                                    break
                                } else if (grrStatus == 0x6100) {
                                    /* If the number of available bytes > Le + 255, the mdoc shall
                                     * include as many bytes in the response as indicated by Le and
                                     * shall set the status words to ’61 00’. The mdoc reader shall
                                     * respond with a GET RESPONSE command where Le is set to the
                                     * maximum length of the response data field that is supported
                                     * by both the mdoc and the mdoc reader.
                                     */
                                    leForGetResponse = maxTransceiveLength - 10
                                } else if (grrStatus and 0xff00 == 0x6100) {
                                    /* If Le < the number of available bytes ≤ Le + 255, the
                                     * mdoc shall include as many bytes in the response as
                                     * indicated by Le and shall set the status words to ’61 XX’,
                                     * where XX is the number of available bytes remaining. The
                                     * mdoc reader shall respond with a GET RESPONSE command where
                                     * Le is set to XX.
                                     */
                                    leForGetResponse = grrStatus and 0xff
                                } else {
                                    reportError(Error("Expected GetResponse APDU status $status"))
                                }
                            }
                            encapsulatedMessage = baos.toByteArray()
                        } else {
                            reportError(Error("Expected APDU status $status"))
                            return
                        }
                        val message = extractFromDo53(encapsulatedMessage)
                        if (message == null) {
                            reportError(Error("Error extracting message from DO53 encoding"))
                            return
                        }
                        reportMessageReceived(message)
                    }
                    reportDisconnected()
                } catch (e: IOException) {
                    reportError(e)
                }
                Logger.d(TAG, "Ending transceiver thread")
                _isoDep = null
            }
        }
        transceiverThread.start()
    }

    override fun close() {
        if (connectedAsMdoc) {
            removeActiveConnection(this)
        }
        inhibitCallbacks()
        writerQueue.add(ByteArray(0))
        listenerStillActive = false
    }

    override fun sendMessage(data: ByteArray) {
        writerQueue.add(data)
    }

    override fun sendTransportSpecificTerminationMessage() {
        reportError(Error("Transport-specific termination message not supported"))
    }

    override fun supportsTransportSpecificTerminationMessage(): Boolean {
        return false
    }

    override val connectionMethodForTransport: ConnectionMethod
        get() = connectionMethod

    companion object {
        private const val TAG = "DataTransportNfc"
        
        @JvmStatic
        fun fromNdefRecord(
            record: NdefRecord,
            isForHandoverSelect: Boolean
        ): ConnectionMethodNfc? {
            val payload = ByteBuffer.wrap(record.payload).order(ByteOrder.LITTLE_ENDIAN)
            val version = payload.get().toInt()
            if (version != 0x01) {
                Logger.w(TAG, "Expected version 0x01, found $version")
                return null
            }
            val cmdLen = payload.get().toInt() and 0xff
            val cmdType = payload.get().toInt() and 0xff
            if (cmdType != 0x01) {
                Logger.w(TAG, "expected type 0x01, found $cmdType")
                return null
            }
            if (cmdLen < 2 || cmdLen > 3) {
                Logger.w(TAG, "expected cmdLen in range 2-3, got $cmdLen")
                return null
            }
            var commandDataFieldMaxLength = 0
            for (n in 0 until cmdLen - 1) {
                commandDataFieldMaxLength *= 256
                commandDataFieldMaxLength += payload.get().toInt() and 0xff
            }
            val rspLen = payload.get().toInt() and 0xff
            val rspType = payload.get().toInt() and 0xff
            if (rspType != 0x02) {
                Logger.w(TAG, "expected type 0x02, found $rspType")
                return null
            }
            if (rspLen < 2 || rspLen > 4) {
                Logger.w(TAG, "expected rspLen in range 2-4, got $rspLen")
                return null
            }
            var responseDataFieldMaxLength = 0
            for (n in 0 until rspLen - 1) {
                responseDataFieldMaxLength *= 256
                responseDataFieldMaxLength += payload.get().toInt() and 0xff
            }
            return ConnectionMethodNfc(
                commandDataFieldMaxLength.toLong(),
                responseDataFieldMaxLength.toLong()
            )
        }

        private val activeTransports = mutableListOf<DataTransportNfc>()
        private fun addActiveConnection(transport: DataTransportNfc) {
            activeTransports.add(transport)
        }

        private fun removeActiveConnection(transport: DataTransportNfc) {
            activeTransports.remove(transport)
        }

        /**
         * Process APDU from remote reader.
         *
         * This should be called by an application using NFC data transport from
         * its [HostApduService.processCommandApdu] implementation
         * for handling the mDL NFC device retrieveal Application ID (A0 00 00 02 48 04 00).
         *
         * @param hostApduService the [HostApduService].
         * @param apdu the APDU.
         * @return the response APDU or `null`.
         */
        fun processCommandApdu(
            hostApduService: HostApduService,
            apdu: ByteArray
        ): ByteArray? {
            if (activeTransports.size == 0) {
                Logger.w(TAG, "processCommandApdu: No active DataTransportNfc")
                return null
            }
            val transport = activeTransports[0]
            return transport.nfcDataTransferProcessCommandApdu(hostApduService, apdu)
        }

        /**
         * Process remote reader deactivation.
         *
         * This should be called by an application using NFC data transport from
         * its [HostApduService.onDeactivated] implementation
         * for handling the mDL NFC device retrieveal Application ID (A0 00 00 02 48 04 00).
         *
         * @param reason the reason, either [HostApduService.DEACTIVATION_LINK_LOSS] or
         * [HostApduService.DEACTIVATION_DESELECTED].
         */
        fun onDeactivated(reason: Int) {
            if (activeTransports.size == 0) {
                Logger.w(TAG, "processCommandApdu: No active DataTransportNfc")
                return
            }
            val transport = activeTransports[0]
            transport.nfcDataTransferOnDeactivated(reason)
        }

        fun fromConnectionMethod(
            context: Context,
            cm: ConnectionMethodNfc,
            role: Role,
            options: DataTransportOptions
        ): DataTransport {
            // TODO: set mCommandDataFieldMaxLength and mResponseDataFieldMaxLength
            return DataTransportNfc(context, role, cm, options)
        }

        private fun encodeInt(dataType: Int, value: Int, baos: ByteArrayOutputStream) {
            if (value < 0x100) {
                baos.write(0x02) // Length
                baos.write(dataType)
                baos.write(value and 0xff)
            } else if (value < 0x10000) {
                baos.write(0x03) // Length
                baos.write(dataType)
                baos.write(value / 0x100)
                baos.write(value and 0xff)
            } else {
                baos.write(0x04) // Length
                baos.write(dataType)
                baos.write(value / 0x10000)
                baos.write(value / 0x100 and 0xff)
                baos.write(value and 0xff)
            }
        }

        fun toNdefRecord(
            cm: ConnectionMethodNfc,
            auxiliaryReferences: List<String>,
            isForHandoverSelect: Boolean
        ): Pair<NdefRecord, ByteArray> {
            val carrierDataReference = "nfc".toByteArray()

            // This is defined by ISO 18013-5 8.2.2.2 Alternative Carrier Record for device
            // retrieval using NFC.
            //
            var baos = ByteArrayOutputStream()
            baos.write(0x01) // Version
            encodeInt(0x01, cm.commandDataFieldMaxLength.toInt(), baos)
            encodeInt(0x02, cm.responseDataFieldMaxLength.toInt(), baos)
            val oobData = baos.toByteArray()
            val record = NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                "iso.org:18013:nfc".toByteArray(),
                carrierDataReference,
                oobData
            )

            // From 7.1 Alternative Carrier Record
            //
            baos = ByteArrayOutputStream()
            baos.write(0x01) // CPS: active
            baos.write(carrierDataReference.size) // Length of carrier data reference
            try {
                baos.write(carrierDataReference)
            } catch (e: IOException) {
                throw IllegalStateException(e)
            }
            baos.write(auxiliaryReferences.size) // Number of auxiliary references
            for (auxRef in auxiliaryReferences) {
                // Each auxiliary reference consists of a single byte for the length and then as
                // many bytes for the reference itself.
                val auxRefUtf8 = auxRef.toByteArray()
                baos.write(auxRefUtf8.size)
                baos.write(auxRefUtf8, 0, auxRefUtf8.size)
            }
            val acRecordPayload = baos.toByteArray()
            return Pair(record, acRecordPayload)
        }
    }
}
