package com.android.identity.mdoc.transport

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.Build
import android.os.ParcelUuid
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.Tagged
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcPublicKey
import com.android.identity.util.AndroidContexts
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import com.android.identity.util.toHex
import com.android.identity.util.toJavaUuid
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.io.bytestring.ByteStringBuilder
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.min

internal class BlePeripheralManagerAndroid: BlePeripheralManager {
    companion object {
        private const val TAG = "BlePeripheralManagerAndroid"
    }

    private lateinit var stateCharacteristicUuid: UUID
    private lateinit var client2ServerCharacteristicUuid: UUID
    private lateinit var server2ClientCharacteristicUuid: UUID
    private var identCharacteristicUuid: UUID? = null
    private var l2capCharacteristicUuid: UUID? = null

    private var negotiatedMtu = -1
    private var maxCharacteristicSizeMemoized = 0
    private val maxCharacteristicSize: Int
        get() {
            if (maxCharacteristicSizeMemoized > 0) {
                return maxCharacteristicSizeMemoized
            }
            var mtuSize = negotiatedMtu
            if (mtuSize == -1) {
                Logger.w(TAG, "MTU not negotiated, defaulting to 23. Performance will suffer.")
                mtuSize = 23
            }
            maxCharacteristicSizeMemoized = min(512, mtuSize - 3)
            Logger.i(TAG, "Using maxCharacteristicSize $maxCharacteristicSizeMemoized")
            return maxCharacteristicSizeMemoized
        }

    override fun setUuids(
        stateCharacteristicUuid: UUID,
        client2ServerCharacteristicUuid: UUID,
        server2ClientCharacteristicUuid: UUID,
        identCharacteristicUuid: UUID?,
        l2capCharacteristicUuid: UUID?
    ) {
        this.stateCharacteristicUuid = stateCharacteristicUuid
        this.client2ServerCharacteristicUuid = client2ServerCharacteristicUuid
        this.server2ClientCharacteristicUuid = server2ClientCharacteristicUuid
        this.identCharacteristicUuid = identCharacteristicUuid
        this.l2capCharacteristicUuid = l2capCharacteristicUuid
    }

    private lateinit var onError: (error: Throwable) -> Unit
    private lateinit var onClosed: () -> Unit

    override fun setCallbacks(onError: (Throwable) -> Unit, onClosed: () -> Unit) {
        this.onError = onError
        this.onClosed = onClosed
    }

    internal enum class WaitState {
        SERVICE_ADDED,
        STATE_CHARACTERISTIC_WRITTEN_OR_L2CAP_CLIENT,
        START_ADVERTISING,
        CHARACTERISTIC_WRITE_COMPLETED,
    }

    private data class WaitFor(
        val state: WaitState,
        val continuation: CancellableContinuation<Boolean>,
    )

    private var waitFor: WaitFor? = null

    private fun setWaitCondition(
        state: WaitState,
        continuation: CancellableContinuation<Boolean>
    ) {
        check(waitFor == null)
        waitFor = WaitFor(
            state,
            continuation,
        )
    }

    private fun resumeWait() {
        val continuation = waitFor!!.continuation
        waitFor = null
        continuation.resume(true)
    }

    private fun resumeWaitWithException(exception: Throwable) {
        val continuation = waitFor!!.continuation
        waitFor = null
        continuation.resumeWithException(exception)
    }

    override val incomingMessages = Channel<ByteArray>(Channel.UNLIMITED)

    private val context = AndroidContexts.applicationContext
    private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)
    private var gattServer: BluetoothGattServer? = null
    private var service: BluetoothGattService? = null
    private var readCharacteristic: BluetoothGattCharacteristic? = null
    private var writeCharacteristic: BluetoothGattCharacteristic? = null
    private var stateCharacteristic: BluetoothGattCharacteristic? = null
    private var identCharacteristic: BluetoothGattCharacteristic? = null
    private var l2capCharacteristic: BluetoothGattCharacteristic? = null
    private var identValue: ByteArray? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var device: BluetoothDevice? = null

    private val gattServerCallback = object: BluetoothGattServerCallback() {

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            Logger.d(TAG, "onServiceAdded: $status")
            if (waitFor?.state == WaitState.SERVICE_ADDED) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    resumeWait()
                } else {
                    resumeWaitWithException(Error("onServiceAdded: Expected GATT_SUCCESS got $status"))
                }
            } else {
                Logger.w(TAG, "onServiceAdded but not waiting")
            }
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            Logger.d(TAG, "onConnectionStateChange: ${device.address} $status + $newState")
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            Logger.d(TAG, "onCharacteristicReadRequest: ${device.address} $requestId " +
                    "$offset ${characteristic.uuid}")
            if (characteristic == identCharacteristic) {
                if (identValue == null) {
                    onError(Error("Received request for ident before it's set.."))
                } else {
                    gattServer!!.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        0,
                        identValue ?: byteArrayOf()
                    )
                }
            } else if (characteristic == l2capCharacteristic) {
                var encodedPsm = byteArrayOf()
                if (l2capServerSocket != null) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        val psm = l2capServerSocket!!.psm.toUInt()
                        val bsb = ByteStringBuilder()
                        bsb.apply {
                            append((psm shr 24).and(0xffU).toByte())
                            append((psm shr 16).and(0xffU).toByte())
                            append((psm shr 8).and(0xffU).toByte())
                            append((psm shr 0).and(0xffU).toByte())
                        }
                        encodedPsm = bsb.toByteString().toByteArray()
                    }
                } else {
                    Logger.w(TAG, "Got a request for L2CAP characteristic but not listening")
                }
                gattServer!!.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    encodedPsm
                )
            } else {
                Logger.w(TAG, "Read on unexpected characteristic with UUID ${characteristic.uuid}")
            }

        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            Logger.d(TAG, "onCharacteristicWriteRequest: ${device.address} $requestId " +
                    "$offset ${characteristic.uuid} ${value.toHex()}")

            if (responseNeeded) {
                gattServer!!.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    null
                )
            }

            if (characteristic.uuid == stateCharacteristicUuid.toJavaUuid()) {
                if (value contentEquals byteArrayOf(
                        BleTransportConstants.STATE_CHARACTERISTIC_START.toByte()
                )) {
                    if (waitFor?.state == WaitState.STATE_CHARACTERISTIC_WRITTEN_OR_L2CAP_CLIENT) {
                        this@BlePeripheralManagerAndroid.device = device
                        // Since the central found us, we can stop advertising....
                        advertiser?.stopAdvertising(advertiseCallback)
                        // Also, stop listening for L2CAP connections...
                        l2capNotUsed = true
                        l2capServerSocket?.close()
                        l2capServerSocket = null
                        resumeWait()
                    }
                } else if (value contentEquals byteArrayOf(BleTransportConstants.STATE_CHARACTERISTIC_END.toByte())) {
                    Logger.i(TAG, "Received transport-specific termination message")
                    runBlocking {
                        incomingMessages.send(byteArrayOf())
                    }
                } else {
                    Logger.w(TAG, "Ignoring unexpected write to state characteristic")
                }
            } else if (characteristic.uuid == client2ServerCharacteristicUuid.toJavaUuid()) {
                try {
                    handleIncomingData(value)
                } catch (e: Throwable) {
                    onError(Error("Error processing incoming data", e))
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray
        ) {
            if (Logger.isDebugEnabled) {
                Logger.d(
                    TAG, "onDescriptorWriteRequest: ${device.address}" +
                            "${descriptor.characteristic.uuid} $offset ${value.toHex()}"
                )
            }
            if (responseNeeded) {
                gattServer!!.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    null
                )
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            negotiatedMtu = mtu
            Logger.d(TAG, "Negotiated MTU $mtu for $${device.address}")
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            Logger.d(TAG, "onNotificationSent $status for ${device.address}")
            if (waitFor?.state == WaitState.CHARACTERISTIC_WRITE_COMPLETED) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    resumeWaitWithException(Error("onNotificationSent: Expected GATT_SUCCESS but got $status"))
                } else {
                    resumeWait()
                }
            } else {
                Logger.w(TAG, "onNotificationSent but not waiting")
            }
        }
    }

    private val advertiseCallback: AdvertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            if (waitFor?.state == WaitState.START_ADVERTISING) {
                resumeWait()
            } else {
                Logger.w(TAG, "Unexpected AdvertiseCallback.onStartSuccess() callback")
            }
        }

        override fun onStartFailure(errorCode: Int) {
            if (waitFor?.state == WaitState.START_ADVERTISING) {
                resumeWaitWithException(Error("Started advertising failed with $errorCode"))
            } else {
                Logger.w(TAG, "Unexpected AdvertiseCallback.onStartFailure() callback")
            }
        }
    }

    private var incomingMessage = ByteStringBuilder()

    private fun handleIncomingData(chunk: ByteArray) {
        if (chunk.size < 1) {
            throw Error("Invalid data length ${chunk.size} for Client2Server characteristic")
        }
        incomingMessage.append(chunk, 1, chunk.size)
        when {
            chunk[0].toInt() == 0x00 -> {
                // Last message.
                val newMessage = incomingMessage.toByteString().toByteArray()
                incomingMessage = ByteStringBuilder()
                runBlocking {
                    incomingMessages.send(newMessage)
                }
            }

            chunk[0].toInt() == 0x01 -> {
                if (chunk.size != maxCharacteristicSize) {
                    Logger.w(TAG, "Client2Server received ${chunk.size} bytes which is not the " +
                            "expected $maxCharacteristicSize bytes")
                }
            }

            else -> {
                throw Error("Invalid first byte ${chunk[0]} in Client2Server data chunk, " +
                        "expected 0 or 1")
            }
        }
    }

    override suspend fun waitForPowerOn() {
        // Not needed on Android
        return
    }

    // This is what the 16-bit UUID 0x29 0x02 is encoded like.
    private var clientCharacteristicConfigUuid = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    private fun addCharacteristic(
        characteristicUuid: UUID,
        properties: Int,
        permissions: Int,
    ): BluetoothGattCharacteristic {
        val characteristic = BluetoothGattCharacteristic(
            characteristicUuid.toJavaUuid(),
            properties,
            permissions
        )
        if (properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0) {
            val descriptor = BluetoothGattDescriptor(
                clientCharacteristicConfigUuid.toJavaUuid(),
                BluetoothGattDescriptor.PERMISSION_WRITE
            )
            descriptor.setValue(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
            characteristic.addDescriptor(descriptor)
        }
        service!!.addCharacteristic(characteristic)
        return characteristic
    }

    override suspend fun advertiseService(uuid: UUID) {
        gattServer = bluetoothManager.openGattServer(context, gattServerCallback)
        service = BluetoothGattService(
            uuid.toJavaUuid(),
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        stateCharacteristic = addCharacteristic(
            characteristicUuid = stateCharacteristicUuid,
            properties = BluetoothGattCharacteristic.PROPERTY_NOTIFY + BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            permissions = BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        readCharacteristic = addCharacteristic(
            characteristicUuid = client2ServerCharacteristicUuid,
            properties = BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            permissions = BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        writeCharacteristic = addCharacteristic(
            characteristicUuid = server2ClientCharacteristicUuid,
            properties = BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            permissions = BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        if (identCharacteristicUuid != null) {
            identCharacteristic = addCharacteristic(
                characteristicUuid = identCharacteristicUuid!!,
                properties = BluetoothGattCharacteristic.PROPERTY_READ,
                permissions = BluetoothGattCharacteristic.PERMISSION_READ
            )
        }
        if (l2capCharacteristicUuid != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                l2capServerSocket = bluetoothManager.adapter.listenUsingInsecureL2capChannel()
                // Listen in a coroutine
                CoroutineScope(Dispatchers.IO).launch {
                    l2capListen()
                }
                l2capCharacteristic = addCharacteristic(
                    characteristicUuid = l2capCharacteristicUuid!!,
                    properties = BluetoothGattCharacteristic.PROPERTY_READ,
                    permissions = BluetoothGattCharacteristic.PERMISSION_READ
                )
            } else {
                Logger.w(TAG, "L2CAP only support on API 29 or later")
            }
        }
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.SERVICE_ADDED, continuation)
            gattServer!!.addService(service!!)
        }

        advertiser = bluetoothManager.adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            throw Error("Advertiser not available, is Bluetooth off?")
        }
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(uuid.toJavaUuid()))
            .build()
        Logger.d(TAG, "Started advertising UUID $uuid")
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.START_ADVERTISING, continuation)
            advertiser!!.startAdvertising(settings, data, advertiseCallback)
        }
    }

    override suspend fun setESenderKey(eSenderKey: EcPublicKey) {
        val ikm = Cbor.encode(Tagged(24, Bstr(Cbor.encode(eSenderKey.toCoseKey().toDataItem()))))
        val info = "BLEIdent".encodeToByteArray()
        val salt = byteArrayOf()
        identValue = Crypto.hkdf(Algorithm.HMAC_SHA256, ikm, salt, info, 16)
    }

    override suspend fun waitForStateCharacteristicWriteOrL2CAPClient() {
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.STATE_CHARACTERISTIC_WRITTEN_OR_L2CAP_CLIENT, continuation)
        }
    }

    override suspend fun sendMessage(message: ByteArray) {
        if (l2capSocket != null) {
            l2capSendMessage(message)
            return
        }
        Logger.i(TAG, "sendMessage ${message.size} length")
        val maxChunkSize = maxCharacteristicSize - 1  // Need room for the leading 0x00 or 0x01
        val offsets = 0 until message.size step maxChunkSize
        for (offset in offsets) {
            val moreDataComing = (offset != offsets.last)
            val size = min(maxChunkSize, message.size - offset)

            val builder = ByteStringBuilder(size + 1)
            builder.append(if (moreDataComing) 0x01 else 0x00)
            builder.append(message, offset, offset + size)
            val chunk = builder.toByteString().toByteArray()

            writeToCharacteristic(writeCharacteristic!!, chunk)
        }
        Logger.i(TAG, "sendMessage completed")
    }

    private suspend fun writeToCharacteristic(
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val rc = gattServer!!.notifyCharacteristicChanged(
                    device!!,
                    characteristic,
                    false,
                    value)
            if (rc != BluetoothStatusCodes.SUCCESS) {
                throw Error("Error notifyCharacteristicChanged on characteristic ${characteristic.uuid} rc=$rc")
            }
        } else {
            characteristic.setValue(value)
            if (!gattServer!!.notifyCharacteristicChanged(
                device!!,
                characteristic,
                false)
            ) {
                throw Error("Error notifyCharacteristicChanged on characteristic ${characteristic.uuid}")
            }
        }
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.CHARACTERISTIC_WRITE_COMPLETED, continuation)
        }
    }

    override suspend fun writeToStateCharacteristic(value: Int) {
        writeToCharacteristic(stateCharacteristic!!, byteArrayOf(value.toByte()))
    }

    override fun close() {
        Logger.d(TAG, "close()")
        device = null
        advertiser?.stopAdvertising(advertiseCallback)
        advertiser = null
        gattServer?.removeService(service)
        gattServer?.close()
        gattServer = null
        service = null
        l2capServerSocket?.close()
        l2capServerSocket = null
        incomingMessages.close()
        l2capSocket?.let {
            CoroutineScope(Dispatchers.IO).launch() {
                delay(5000)
                it.close()
            }
        }
        l2capSocket = null
    }

    override val usingL2cap: Boolean
        get() = (l2capSocket != null)

    override val l2capPsm: Int?
        get() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                return l2capServerSocket?.psm
            } else {
                return null
            }
        }


    private var l2capServerSocket: BluetoothServerSocket? = null
    private var l2capSocket: BluetoothSocket? = null
    // Set to true iff the other peer ended up using GATT instead of L2CAP
    private var l2capNotUsed = false

    private suspend fun l2capListen() {
        try {
            l2capSocket = l2capServerSocket!!.accept()

            l2capServerSocket?.close()
            l2capServerSocket = null

            if (waitFor?.state == WaitState.STATE_CHARACTERISTIC_WRITTEN_OR_L2CAP_CLIENT) {
                Logger.i(TAG, "L2CAP connection")
                device = l2capSocket!!.remoteDevice
                // Since the central found us, we can stop advertising....
                advertiser?.stopAdvertising(advertiseCallback)
                resumeWait()
            } else {
                Logger.w(TAG, "Got a L2CAP client but not waiting")
                return
            }

            val inputStream = l2capSocket!!.inputStream
            while (true) {
                val encodedLength = inputStream.readNOctets(4U)
                val length = (encodedLength[0].toUInt().and(0xffU) shl 24) +
                        (encodedLength[1].toUInt().and(0xffU) shl 16) +
                        (encodedLength[2].toUInt().and(0xffU) shl 8) +
                        (encodedLength[3].toUInt().and(0xffU) shl 0)
                val message = inputStream.readNOctets(length)
                incomingMessages.send(message)
            }
        } catch (e: Throwable) {
            if (l2capNotUsed) {
                Logger.d(TAG, "Ignoring error since l2capNotUsed is true", e)
            } else {
                onError(Error("Accepting/reading from L2CAP socket failed", e))
            }
        }
    }

    private suspend fun l2capSendMessage(message: ByteArray) {
        Logger.i(TAG, "l2capSendMessage ${message.size} length")
        val bsb = ByteStringBuilder()
        val length = message.size.toUInt()
        bsb.apply {
            append((length shr 24).and(0xffU).toByte())
            append((length shr 16).and(0xffU).toByte())
            append((length shr 8).and(0xffU).toByte())
            append((length shr 0).and(0xffU).toByte())
        }
        bsb.append(message)
        l2capSocket?.outputStream?.write(bsb.toByteString().toByteArray())
        l2capSocket?.outputStream?.flush()
    }
}