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
package com.android.identity.android.mdoc.deviceretrieval

import android.content.Context
import com.android.identity.android.mdoc.transport.DataTransport
import com.android.identity.android.mdoc.transport.DataTransportBle
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.RawCbor
import com.android.identity.cbor.Tagged
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.mdoc.engagement.EngagementGenerator
import com.android.identity.mdoc.engagement.EngagementParser
import com.android.identity.mdoc.origininfo.OriginInfo
import com.android.identity.mdoc.sessionencryption.SessionEncryption
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.util.concurrent.Executor

/**
 * Helper used for establishing engagement with, interacting with, and presenting documents to a
 * remote *mdoc reader* device.
 *
 *
 * This class implements the interface between an *mdoc* and *mdoc reader* using
 * the connection setup and device retrieval interfaces defined in
 * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
 *
 *
 * Reverse engagement as per drafts of 18013-7 and 23220-4 is supported. These protocols
 * are not finalized so should only be used for testing.
 */
// Suppress with NotCloseable since we actually don't hold any resources needing to be
// cleaned up at object finalization time.
class DeviceRetrievalHelper internal constructor(
    private val context: Context,
    private val listener: Listener,
    private val listenerExecutor: Executor,
    private val eDeviceKey: EcPrivateKey
) {
    private var _eReaderKey: EcPublicKey? = null
    
    private var _handover: ByteArray? = null
    private var _deviceEngagement: ByteArray? = null
    
    private var sessionEncryption: SessionEncryption? = null
    private var encodedSessionTranscript: ByteArray? = null
    private var transport: DataTransport? = null
    private var receivedSessionTerminated = false
    private var inhibitCallbacks = false
    private var reverseEngagementReaderEngagement: ByteArray? = null
    private var reverseEngagementOriginInfos: List<OriginInfo>? = null
    private var reverseEngagementEncodedEReaderKey: ByteArray? = null
    private val listenerCoroutineScope = CoroutineScope(listenerExecutor.asCoroutineDispatcher())
    /**
     * The bytes of the device engagement being used.
     */
    val deviceEngagement: ByteArray
        get() {
            return _deviceEngagement!!
        }

    /**
     * The bytes of the handover being used.
     */
    val handover: ByteArray
        get() {
            return _handover!!
        }

    /**
     * The bytes of the session transcript.
     *
     * This must not be called until [Listener.onEReaderKeyReceived] has been called.
     *
     * See [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) for the
     * definition of the bytes in the session transcript.
     */
    val sessionTranscript: ByteArray
        get() {
            checkNotNull(encodedSessionTranscript) { "No message received from reader" }
            return encodedSessionTranscript!!
        }

    /**
     * Gets the ephemeral reader key.
     *
     * This must not be called until [Listener.onEReaderKeyReceived] has been called.
     */
    val eReaderKey: EcPublicKey
        get() {
            checkNotNull(_eReaderKey) { "No message received from reader" }
            return _eReaderKey!!
        }

    // Note: The report*() methods are safe to call from any thread.
    fun reportEReaderKeyReceived(eReaderKey: EcPublicKey) {
        Logger.d(TAG, "reportEReaderKeyReceived: $eReaderKey")
        listenerCoroutineScope.launch {
            if (!inhibitCallbacks) {
                listener.onEReaderKeyReceived(eReaderKey)
            }
        }
    }

    fun reportDeviceRequest(deviceRequestBytes: ByteArray) {
        Logger.d(TAG, "reportDeviceRequest: deviceRequestBytes: ${deviceRequestBytes.size} bytes")
        listenerCoroutineScope.launch {
            if (!inhibitCallbacks) {
                listener.onDeviceRequest(deviceRequestBytes)
            }
        }
    }

    fun reportDeviceDisconnected(transportSpecificTermination: Boolean) {
        Logger.d(TAG, "reportDeviceDisconnected: transportSpecificTermination: " +
                    "$transportSpecificTermination")
        listenerCoroutineScope.launch {
            if (!inhibitCallbacks) {
                listener.onDeviceDisconnected(transportSpecificTermination)
            }
        }
    }

    fun reportError(error: Throwable) {
        Logger.d(TAG, "reportError: error: ", error)
        listenerCoroutineScope.launch {
            if (!inhibitCallbacks) {
                listener.onError(error)
            }
        }
    }

    fun start() {
        transport!!.setListener(object : DataTransport.Listener {
            override fun onConnecting() {
                Logger.d(TAG, "onConnecting")
            }

            override fun onDisconnected() {
                Logger.d(TAG, "onDisconnected")
                if (transport != null) {
                    transport!!.close()
                }
                if (!receivedSessionTerminated) {
                    reportError(Error("Peer disconnected without proper session termination"))
                } else {
                    reportDeviceDisconnected(false)
                }
            }

            override fun onConnected() {
                Logger.d(TAG, "onConnected")
                if (reverseEngagementReaderEngagement != null) {
                    Logger.d(TAG, "onConnected for reverse engagement")
                    val generator = EngagementGenerator(
                        eDeviceKey.publicKey,
                        EngagementGenerator.ENGAGEMENT_VERSION_1_1
                    )
                    generator.addOriginInfos(reverseEngagementOriginInfos!!)
                    _deviceEngagement = generator.generate()

                    // 18013-7 says to use ReaderEngagementBytes for Handover when ReaderEngagement
                    // is available and neither QR or NFC is used.
                    _handover = Cbor.encode(Tagged(24, Bstr(reverseEngagementReaderEngagement!!)))

                    // 18013-7 says to transmit DeviceEngagementBytes in MessageData
                    val builder = CborMap.builder()
                    builder.put(
                        "deviceEngagementBytes",
                        Cbor.encode(Tagged(24, Bstr(_deviceEngagement!!)))
                    )
                    val messageData = Cbor.encode(builder.end().build())
                    Logger.dCbor(TAG, "MessageData for reverse engagement to send", messageData)
                    transport!!.sendMessage(messageData)
                } else {
                    throw IllegalStateException("Unexpected onConnected callback")
                }
            }

            override fun onError(error: Throwable) {
                if (transport != null) {
                    transport!!.close()
                }
                reportError(error)
            }

            override fun onMessageReceived() {
                val data = transport!!.getMessage()
                if (data == null) {
                    reportError(Error("onMessageReceived but no message"))
                    return
                }
                processMessageReceived(data)
            }

            override fun onTransportSpecificSessionTermination() {
                Logger.d(TAG, "Received transport-specific session termination")
                receivedSessionTerminated = true
                if (transport != null) {
                    transport!!.close()
                }
                reportDeviceDisconnected(true)
            }
        }, listenerExecutor)
        val data = transport!!.getMessage()
        data?.let { processMessageReceived(it) }
        if (reverseEngagementReaderEngagement != null) {
            // Get EReaderKey
            val parser = EngagementParser(reverseEngagementReaderEngagement!!)
            val readerEngagement = parser.parse()
            reverseEngagementEncodedEReaderKey = Cbor.decode(readerEngagement.eSenderKeyBytes).asTagged.asBstr

            // This is reverse engagement, we actually haven't connected yet...
            val encodedEDeviceKeyBytes: ByteArray = Cbor.encode(
                Tagged(
                    24, Bstr(
                        Cbor.encode(eDeviceKey.toCoseKey().toDataItem())
                    )
                )
            )
            transport!!.setEDeviceKeyBytes(encodedEDeviceKeyBytes)
            transport!!.connect()
        }
    }

    // Returns nothing if everything parses correctly or session encryption has already been set
    // up, otherwise the status code (10, 11, 20 as per 18013-5 table 20) to include in the
    // SessionData response.
    private fun ensureSessionEncryption(data: ByteArray): Long? {
        if (sessionEncryption != null) {
            return null
        }

        // For reverse engagement, we get EReaderKeyBytes via Reverse Engagement...
        val encodedEReaderKey: ByteArray
        if (reverseEngagementEncodedEReaderKey != null) {
            encodedEReaderKey = reverseEngagementEncodedEReaderKey!!
            // This is unnecessary but a nice warning regardless...
            val map = Cbor.decode(data)
            if (map.hasKey("eReaderKey")) {
                Logger.w(TAG, "Ignoring eReaderKey in SessionEstablishment since we "
                            + "already got this get in ReaderEngagement")
            }
        } else {
            // This is the first message. Extract eReaderKey to set up session encryption...
            val map = Cbor.decode(data)
            encodedEReaderKey = try {
                map["eReaderKey"].asTagged.asBstr
            } catch (e: Exception) {
                Logger.w(TAG, "Error extracting eReaderKey", e)
                return Constants.SESSION_DATA_STATUS_ERROR_CBOR_DECODING
            }
        }
        _eReaderKey = Cbor.decode(encodedEReaderKey).asCoseKey.ecPublicKey
        encodedSessionTranscript = Cbor.encode(
            CborArray.builder()
                .add(Tagged(24, Bstr(_deviceEngagement!!)))
                .add(Tagged(24, Bstr(encodedEReaderKey)))
                .add(RawCbor(_handover!!))
                .end()
                .build()
        )
        sessionEncryption = SessionEncryption(
            SessionEncryption.Role.MDOC,
            eDeviceKey,
            _eReaderKey!!,
            encodedSessionTranscript!!
        )
        reportEReaderKeyReceived(_eReaderKey!!)
        return null
    }

    private fun processMessageReceived(data: ByteArray) {
        Logger.dCbor(TAG, "SessionData received", data)
        val status = ensureSessionEncryption(data)
        if (status != null) {
            transport!!.sendMessage(SessionEncryption.encodeStatus(status))
            transport!!.close()
            reportError(Error("Error decoding EReaderKey in SessionEstablishment, returning status $status"))
            return
        }

        val decryptedMessage =
        try {
            sessionEncryption!!.decryptMessage(data)
        } catch(e: IllegalStateException) {
            Logger.d(TAG, "Decryption failed!")
            transport!!.sendMessage(
                sessionEncryption!!.encryptMessage(
                    null, Constants.SESSION_DATA_STATUS_ERROR_SESSION_ENCRYPTION
                )
            )
            transport!!.close()
            reportError(Error("Error decrypting message from reader"))
            return
        }

        // If there's data in the message, assume it's DeviceRequest (ISO 18013-5
        // currently does not define other kinds of messages).
        //
        if (decryptedMessage.first != null) {
            Logger.dCbor(TAG, "DeviceRequest received", decryptedMessage.first!!)
            reportDeviceRequest(decryptedMessage.first!!)
        } else {
            // No data, so status must be set.
            if (decryptedMessage.second == null) {
                transport!!.close()
                reportError(Error("No data and no status in SessionData"))
            } else {
                val statusCode = decryptedMessage.second
                Logger.d(TAG, "Message received from reader with status: $statusCode")
                if (statusCode == Constants.SESSION_DATA_STATUS_SESSION_TERMINATION) {
                    receivedSessionTerminated = true
                    transport!!.close()
                    reportDeviceDisconnected(false)
                } else {
                    transport!!.close()
                    reportError(Error("Expected status code 20, got $statusCode instead"))
                }
            }
        }
    }
    
    /**
     * Send a response to the remote mdoc verifier.
     *
     * This is typically called in response to the [Listener.onDeviceRequest] callback.
     *
     * If set, `deviceResponseBytes` parameter should contain CBOR conforming to
     * `DeviceResponse` as specified in ISO/IEC 18013-5 section 8.3 Device Retrieval.
     *
     * At least one of `deviceResponseBytes` and `status` must be set.
     *
     * @param deviceResponseBytes the response to send or `null`.
     * @param status optional status code to send.
     */
    fun sendDeviceResponse(
        deviceResponseBytes: ByteArray?,
        status: Long?
    ) {
        val sessionDataMessage = if (deviceResponseBytes == null) {
            require(status != null) { "deviceResponseBytes and status cannot both be null" }
            Logger.d(TAG, "sendDeviceResponse: status is $status and data is unset")
            SessionEncryption.encodeStatus(status)
        } else {
            if (status != null) {
                Logger.dCbor(TAG, "sendDeviceResponse: status is $status and data is",
                    deviceResponseBytes)
            } else {
                Logger.dCbor(TAG, "sendDeviceResponse: status is unset and data is",
                    deviceResponseBytes)
            }
            sessionEncryption!!.encryptMessage(deviceResponseBytes, status)
        }
        if (transport == null) {
            Logger.d(TAG, "sendDeviceResponse: ignoring because transport is unset")
            return
        }
        transport!!.sendMessage(sessionDataMessage)
    }

    /**
     * Stops the presentation and shuts down the transport.
     *
     * This does not send a message to terminate the session. Applications should use
     * [sendTransportSpecificTermination] or [sendDeviceResponse]
     * with status [Constants.SESSION_DATA_STATUS_SESSION_TERMINATION] to do that.
     *
     * No callbacks will be done on a listener after calling this.
     *
     * This method is idempotent so it is safe to call multiple times.
     */
    fun disconnect() {
        inhibitCallbacks = true
        if (transport == null) {
            Logger.d(TAG, "disconnect: ignoring call because transport is unset")
            return
        }
        Logger.d(TAG, "disconnect: closing transport")
        transport!!.close()
        transport = null
    }

    /**
     * Whether transport specific termination is available for the current connection.
     */
    val isTransportSpecificTerminationSupported: Boolean
        get() = if (transport == null) {
            false
        } else transport!!.supportsTransportSpecificTerminationMessage()

    /**
     * Sends a transport-specific termination message.
     *
     * Transport-specific session terminated is only supported for certain device-retrieval
     * methods. Use [isTransportSpecificTerminationSupported] to figure out if it
     * is supported for the current connection.
     *
     * If a session is not established or transport-specific session termination is not
     * supported this is a no-op.
     */
    fun sendTransportSpecificTermination() {
        if (transport == null) {
            Logger.w(TAG, "No current transport")
            return
        }
        if (!transport!!.supportsTransportSpecificTerminationMessage()) {
            Logger.w(TAG, "Current transport does not support transport-specific termination message")
            return
        }
        Logger.d(TAG, "Sending transport-specific termination message")
        transport!!.sendTransportSpecificTerminationMessage()
    }

    /**
     * The time spent doing BLE scanning or 0 if no scanning happened.
     */
    val scanningTimeMillis: Long
        get() = if (transport is DataTransportBle) {
            (transport as DataTransportBle?)!!.scanningTimeMillis
        } else 0

    /**
     * Interface for listening to messages from the remote verifier device.
     *
     * The [Listener.onError] callback can be called at any time - for
     * example - if the remote verifier disconnects without using session termination or if the
     * underlying transport encounters an unrecoverable error.
     *
     * TODO: consider redoing this API through flows.
     */
    interface Listener {
        /**
         * Called when the reader ephemeral key has been received.
         *
         * When this is called, it's safe to read [sessionTranscript] on
         * the [DeviceRetrievalHelper].
         *
         * @param eReaderKey the ephemeral reader key.
         */
        suspend fun onEReaderKeyReceived(eReaderKey: EcPublicKey)

        /**
         * Called when the remote verifier device sends a request.
         *
         * The `deviceRequestBytes` parameter contains the bytes of `DeviceRequest`
         * as specified in ISO/IEC 18013-5 section 8.3 Device Retrieval.
         *
         * @param deviceRequestBytes the device request.
         */
        suspend fun onDeviceRequest(deviceRequestBytes: ByteArray)

        /**
         * Called when the remote verifier device disconnects normally, that is
         * using the session termination functionality in the underlying protocols.
         *
         * If this is called the application should call [.disconnect] and the
         * object should no longer be used.
         *
         * @param transportSpecificTermination set to `true` if the termination
         * mechanism used was transport specific.
         */
        suspend fun onDeviceDisconnected(transportSpecificTermination: Boolean)

        /**
         * Called when an unrecoverable error happens, for example if the remote device
         * disconnects unexpectedly (e.g. without first sending a session termination request).
         *
         * If this is called the application should call [disconnect] and the object should no
         * longer be used.
         *
         * @param error the error.
         */
        suspend fun onError(error: Throwable)
    }

    /**
     * Builder for [DeviceRetrievalHelper].
     *
     * Use [useForwardEngagement] or [useReverseEngagement] to specify which
     * kind of engagement will be used. At least one of these must be used.
     *
     * @param context the application context.
     * @param listener a listener.
     * @param executor a [Executor] to use with the listener.
     * @param eDeviceKey the ephemeral device session encryption key.
     */
    class Builder(
        context: Context,
        listener: Listener,
        executor: Executor,
        eDeviceKey: EcPrivateKey
    ) {
        var helper = DeviceRetrievalHelper(context, listener, executor, eDeviceKey)

        /**
         * Configures the helper to use normal engagement.
         *
         * @param transport the transport the mdoc reader used to connect with.
         * @param deviceEngagement the bytes of the `DeviceEngagement` CBOR.
         * @param handover the bytes of the `Handover` CBOR.
         * @return the builder.
         */
        fun useForwardEngagement(
            transport: DataTransport,
            deviceEngagement: ByteArray,
            handover: ByteArray
        ) = apply {
            helper.transport = transport
            helper._deviceEngagement = deviceEngagement
            helper._handover = handover
        }

        /**
         * Configures the helper to use reverse engagement.
         *
         * @param transport the transport to use.
         * @param readerEngagement the bytes of the `ReaderEngagement` CBOR.
         * @param originInfos a set of origin infos describing how reader engagement was obtained.
         * @return the builder.
         */
        fun useReverseEngagement(
            transport: DataTransport,
            readerEngagement: ByteArray?,
            originInfos: List<OriginInfo>?
        ) = apply {
            helper.transport = transport
            helper.reverseEngagementReaderEngagement = readerEngagement
            helper.reverseEngagementOriginInfos = originInfos
        }

        /**
         * Builds the [DeviceRetrievalHelper] and starts presentation.
         *
         * @return the helper, ready to be used.
         * @throws IllegalStateException if engagement direction hasn't been configured.
         */
        fun build(): DeviceRetrievalHelper {
            checkNotNull(helper.transport) { "Neither forward nor reverse engagement configured" }
            helper.start()
            return helper
        }
    }

    companion object {
        private const val TAG = "DeviceRetrievalHelper"
    }
}
