package com.android.identity.mdoc.transport

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothSocket
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.os.Build
import android.os.ParcelUuid
import androidx.annotation.RequiresApi
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
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.bytestring.ByteStringBuilder
import java.io.InputStream
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.min
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal class BleCentralManagerAndroid: BleCentralManager {
    companion object {
        private const val TAG = "BleCentralManagerAndroid"
    }

    private lateinit var stateCharacteristicUuid: UUID
    private lateinit var client2ServerCharacteristicUuid: UUID
    private lateinit var server2ClientCharacteristicUuid: UUID
    private var identCharacteristicUuid: UUID? = null
    private var l2capCharacteristicUuid: UUID? = null

    override fun setUuids(
        stateCharacteristicUuid: UUID,
        client2ServerCharacteristicUuid: UUID,
        server2ClientCharacteristicUuid: UUID,
        identCharacteristicUuid: UUID?,
        l2capCharacteristicUuid: UUID?,
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
        PERIPHERAL_DISCOVERED,
        CONNECT_TO_PERIPHERAL,
        REQUEST_MTU,
        PERIPHERAL_DISCOVER_SERVICES,
        GET_READER_IDENT,
        GET_L2CAP_PSM,
        WRITE_TO_DESCRIPTOR,
        CHARACTERISTIC_WRITE_COMPLETED,
    }

    private data class WaitFor(
        val state: WaitState,
        val continuation: CancellableContinuation<Boolean>,
    )

    private var waitFor: WaitFor? = null

    private fun setWaitCondition(
        state: WaitState,
        continuation: CancellableContinuation<Boolean>,
    ) {
        check(waitFor == null)
        waitFor = WaitFor(
            state,
            continuation,
        )
    }

    private fun clearWaitCondition() {
        waitFor = null
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
    private var device: BluetoothDevice? = null
    private var gatt: BluetoothGatt? = null
    private var service: BluetoothGattService? = null

    private var characteristicState: BluetoothGattCharacteristic? = null
    private var characteristicClient2Server: BluetoothGattCharacteristic? = null
    private var characteristicServer2Client: BluetoothGattCharacteristic? = null
    private var characteristicIdent: BluetoothGattCharacteristic? = null
    private var characteristicL2cap: BluetoothGattCharacteristic? = null

    private class ConnectionFailedException(
        message: String
    ) : Throwable(message)

    private val scanCallback: ScanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            Logger.d(TAG, "onScanResult: callbackType=$callbackType result=$result")
            try {
                if (waitFor?.state == WaitState.PERIPHERAL_DISCOVERED) {
                    device = result.device
                    resumeWait()
                } else {
                    Logger.w(TAG, "onScanResult but not waiting")
                }
            } catch (error: Throwable) {
                onError(Error("onScanResult failed", error))
            }
        }

        override fun onScanFailed(errorCode: Int) {
            Logger.d(TAG, "onScanFailed: errorCode=$errorCode")
            try {
                if (waitFor?.state == WaitState.PERIPHERAL_DISCOVERED) {
                    resumeWaitWithException(Error("BLE scan failed with error code $errorCode"))
                } else {
                    Logger.w(TAG, "onScanFailed but not waiting")
                }
            } catch (error: Throwable) {
                onError(Error("onScanFailed failed", error))
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            Logger.d(TAG, "onConnectionStateChange: status=$status newState=$newState")
            try {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                        if (waitFor?.state == WaitState.CONNECT_TO_PERIPHERAL) {
                            resumeWait()
                        } else {
                            Logger.w(TAG, "onConnectionStateChange but not waiting")
                        }
                    }

                    BluetoothProfile.STATE_DISCONNECTED -> {
                        if (waitFor?.state == WaitState.CONNECT_TO_PERIPHERAL) {
                            // See connectToPeripheral() for retries based on this exception
                            resumeWaitWithException(ConnectionFailedException("Failed to connect to peripheral"))
                        } else {
                            throw Error("Peripheral unexpectedly disconnected")
                        }
                    }

                    else -> {
                        Logger.w(TAG, "onConnectionStateChange(): Unexpected newState $newState")
                    }
                }
            } catch (error: Throwable) {
                onError(Error("onConnectionStateChange failed", error))
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt?, mtu: Int, status: Int) {
            Logger.d(TAG, "onMtuChanged: mtu=$mtu status=$status")
            try {
                if (waitFor?.state == WaitState.REQUEST_MTU) {
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        resumeWaitWithException(Error("Expected GATT_SUCCESS but got $status"))
                    } else {
                        if (mtu < 22) {
                            resumeWaitWithException(Error("Unexpected MTU size $mtu"))
                        } else {
                            maxCharacteristicSize = min(mtu - 3, 512)
                            Logger.i(
                                TAG,
                                "MTU is $mtu, using $maxCharacteristicSize as maximum data size for characteristics"
                            )
                            resumeWait()
                        }
                    }
                } else {
                    Logger.w(TAG, "onMtuChanged but not waiting")
                }
            } catch (error: Throwable) {
                onError(Error("onMtuChanged failed", error))
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            Logger.d(TAG, "onServicesDiscovered: status=$status")
            try {
                if (waitFor?.state == WaitState.PERIPHERAL_DISCOVER_SERVICES) {
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        resumeWaitWithException(Error("Expected GATT_SUCCESS but got $status"))
                    } else {
                        resumeWait()
                    }
                } else {
                    Logger.w(TAG, "onServicesDiscovered but not waiting")
                }
            } catch (error: Throwable) {
                onError(Error("onServicesDiscovered failed", error))
            }
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            Logger.d(
                TAG,
                "onCharacteristicRead: characteristic=${characteristic.uuid} value=[${value.size} bytes] status=$status"
            )
            try {
                if (characteristic.uuid == l2capCharacteristicUuid?.toJavaUuid()) {
                    if (waitFor?.state == WaitState.GET_L2CAP_PSM) {
                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            resumeWaitWithException(
                                Error("onCharacteristicRead: Expected GATT_SUCCESS but got $status")
                            )
                        } else {
                            if (value.size != 4) {
                                resumeWaitWithException(
                                    Error("onCharacteristicRead: Expected four bytes for PSM, got ${value.size}")
                                )
                            }
                            _l2capPsm = ((value[0].toUInt().and(0xffU) shl 24) +
                                    (value[1].toUInt().and(0xffU) shl 16) +
                                    (value[2].toUInt().and(0xffU) shl 8) +
                                    (value[3].toUInt().and(0xffU) shl 0)).toInt()
                            Logger.i(TAG, "L2CAP PSM is $_l2capPsm")
                            resumeWait()
                        }
                    } else {
                        Logger.w(TAG, "onCharacteristicRead for L2CAP PSM but not waiting")
                    }

                } else if (characteristic.uuid == identCharacteristicUuid!!.toJavaUuid()) {
                    if (waitFor?.state == WaitState.GET_READER_IDENT) {
                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            resumeWaitWithException(
                                Error("onCharacteristicRead: Expected GATT_SUCCESS but got $status")
                            )
                        }
                        if (expectedIdentValue contentEquals value) {
                            resumeWait()
                        } else {
                            resumeWaitWithException(
                                Error(
                                    "onCharacteristicRead: Expected ${expectedIdentValue!!.toHex()} " +
                                            "for ident, got ${value.toHex()} instead"
                                )
                            )
                        }
                    } else {
                        Logger.w(TAG, "onCharacteristicRead for ident but not waiting")
                    }
                }
            } catch (error: Throwable) {
                onError(Error("onCharacteristicRead failed", error))
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt?,
            characteristic: BluetoothGattCharacteristic?,
            status: Int
        ) {
            Logger.d(TAG, "onCharacteristicWrite: characteristic=${characteristic?.uuid ?: ""} status=$status")
            if (waitFor?.state == WaitState.CHARACTERISTIC_WRITE_COMPLETED) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    resumeWaitWithException(Error("onCharacteristicWrite: Expected GATT_SUCCESS but got $status"))
                } else {
                    resumeWait()
                }
            } else {
                Logger.w(TAG, "onCharacteristicWrite for characteristic ${characteristic?.uuid} but not waiting")
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt?,
            descriptor: BluetoothGattDescriptor?,
            status: Int
        ) {
            Logger.d(TAG, "onDescriptorWrite: descriptor=${descriptor?.uuid ?: ""} status=$status")
            if (waitFor?.state == WaitState.WRITE_TO_DESCRIPTOR) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    resumeWaitWithException(Error("Expected GATT_SUCCESS but got $status"))
                } else {
                    resumeWait()
                }
            } else {
                Logger.w(TAG, "onDescriptorWrite but not waiting")
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            Logger.d(TAG, "onCharacteristicChanged: characteristic=${characteristic.uuid} value=[${value.size} bytes]")
            try {
                if (characteristic.uuid == server2ClientCharacteristicUuid.toJavaUuid()) {
                    handleIncomingData(value)
                } else if (characteristic.uuid == stateCharacteristicUuid.toJavaUuid()) {
                    // Transport-specific session termination as per 18013-5 clause 8.3.3.1.1.5 Connection state
                    if (value contentEquals byteArrayOf(BleTransportConstants.STATE_CHARACTERISTIC_END.toByte())) {
                        Logger.i(TAG, "Received transport-specific termination message")
                        runBlocking {
                            incomingMessages.send(byteArrayOf())
                        }
                    } else {
                        Logger.w(TAG, "Ignoring unexpected write to state characteristic")
                    }
                }
            } catch (error: Throwable) {
                onError(Error("onCharacteristicChanged failed", error))
            }
        }
    }

    var incomingMessage = ByteStringBuilder()

    var maxCharacteristicSize = -1

    private fun handleIncomingData(chunk: ByteArray) {
        if (chunk.size < 1) {
            throw Error("Invalid data length ${chunk.size} for Server2Client characteristic")
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
                    // Because this is not fatal and some buggy implementations do this, we treat
                    // it just as a warning, not an error.
                    Logger.w(
                        TAG, "Server2Client received ${chunk.size} bytes which is not the " +
                                "expected $maxCharacteristicSize bytes"
                    )
                }
            }

            else -> {
                throw Error(
                    "Invalid first byte ${chunk[0]} in Server2Client data chunk, " +
                            "expected 0 or 1"
                )
            }
        }
    }


    override suspend fun waitForPowerOn() {
        // Not needed on Android
        return
    }

    override suspend fun waitForPeripheralWithUuid(uuid: UUID) {

        // The Android Bluetooth stack has protection built-in against applications scanning
        // too frequently. The way this works is that Android will simply not report
        // anything back to the app but will print
        //
        //   App 'com.example.appname' is scanning too frequently
        //
        // to logcat. We work around this by retrying the scan operation if we haven't
        // gotten a result in 10 seconds.
        //
        var retryCount = 0
        while (true) {
            val rc = withTimeoutOrNull(10.seconds) {
                suspendCancellableCoroutine<Boolean> { continuation ->
                    setWaitCondition(WaitState.PERIPHERAL_DISCOVERED, continuation)
                    val filter = ScanFilter.Builder()
                        .setServiceUuid(ParcelUuid(uuid.toJavaUuid()))
                        .build()
                    val settings = ScanSettings.Builder()
                        .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                        .build()
                    bluetoothManager.adapter.bluetoothLeScanner
                        .startScan(listOf(filter), settings, scanCallback)
                }
                true
            }
            bluetoothManager.adapter.bluetoothLeScanner.stopScan(scanCallback)
            if (rc != null) {
                break
            }
            clearWaitCondition()
            retryCount++
            // Note: we never give up b/c it's possible this is used by a wallet app which is simply
            // sitting at the "Show QR code" dialog.
            //
            Logger.i(TAG, "Failed to find peripheral after $retryCount attempt(s) of 10 secs. Restarting scan.")
        }
    }

    override suspend fun connectToPeripheral() {
        check(device != null)

        // Connection attempts sometimes fail... but will work on subsequent
        // tries. So we implement a simple retry loop.
        var retryCount = 0
        while (true) {
            try {
                suspendCancellableCoroutine<Boolean> { continuation ->
                    setWaitCondition(WaitState.CONNECT_TO_PERIPHERAL, continuation)
                    gatt = device!!.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
                }
                break
            } catch (error: ConnectionFailedException) {
                if (retryCount < 10) {
                    retryCount++
                    Logger.w(TAG, "Failed connecting to peripheral after $retryCount attempt(s), retrying in 500 msec")
                    delay(500.milliseconds)
                } else {
                    Logger.w(TAG, "Failed connecting to peripheral after $retryCount attempts. Giving up.")
                    throw error
                }
            }
        }
    }

    override suspend fun requestMtu() {
        check(device != null && gatt != null)
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.REQUEST_MTU, continuation)
            // 515 is the largest MTU that makes sense given that characteristics must be 512
            // bytes or less.
            gatt!!.requestMtu(515)
        }
    }

    override suspend fun peripheralDiscoverServices(uuid: UUID) {
        check(device != null && gatt != null)
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.PERIPHERAL_DISCOVER_SERVICES, continuation)
            gatt!!.discoverServices()
        }
        service = gatt!!.getService(uuid.toJavaUuid())
        if (service == null) {
            throw Error("No service with the given UUID")
        }
    }

    override suspend fun peripheralDiscoverCharacteristics() {
        check(device != null && gatt != null && service != null)
        characteristicState = service!!.getCharacteristic(stateCharacteristicUuid.toJavaUuid())
        if (characteristicState == null) {
            throw Error("State characteristic not found")
        }
        characteristicClient2Server =
            service!!.getCharacteristic(client2ServerCharacteristicUuid.toJavaUuid())
        if (characteristicClient2Server == null) {
            throw Error("Client2Server characteristic not found")
        }
        characteristicServer2Client =
            service!!.getCharacteristic(server2ClientCharacteristicUuid.toJavaUuid())
        if (characteristicServer2Client == null) {
            throw Error("Server2Client characteristic not found")
        }
        if (identCharacteristicUuid != null) {
            characteristicIdent = service!!.getCharacteristic(identCharacteristicUuid!!.toJavaUuid())
            if (characteristicIdent == null) {
                throw Error("Ident characteristic not found")
            }
        }
        if (l2capCharacteristicUuid != null) {
            characteristicL2cap = service!!.getCharacteristic(l2capCharacteristicUuid!!.toJavaUuid())
            if (characteristicL2cap == null) {
                Logger.i(TAG, "L2CAP characteristic requested but not found")
            } else {
                suspendCancellableCoroutine<Boolean> { continuation ->
                    setWaitCondition(WaitState.GET_L2CAP_PSM, continuation)
                    gatt!!.readCharacteristic(characteristicL2cap)
                }
            }
        }
    }

    var expectedIdentValue: ByteArray? = null

    override suspend fun checkReaderIdentMatches(eSenderKey: EcPublicKey) {
        check(device != null && gatt != null && identCharacteristicUuid != null)

        val ikm = Cbor.encode(Tagged(24, Bstr(Cbor.encode(eSenderKey.toCoseKey().toDataItem()))))
        val info = "BLEIdent".encodeToByteArray()
        val salt = byteArrayOf()
        expectedIdentValue = Crypto.hkdf(Algorithm.HMAC_SHA256, ikm, salt, info, 16)

        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.GET_READER_IDENT, continuation)
            gatt!!.readCharacteristic(characteristicIdent)
        }
    }

    private suspend fun enableNotifications(
        characteristic: BluetoothGattCharacteristic
    ) {
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.WRITE_TO_DESCRIPTOR, continuation)

            // This is what the 16-bit UUID 0x29 0x02 is encoded like.
            val clientCharacteristicConfigUuid = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

            if (!gatt!!.setCharacteristicNotification(characteristic, true)) {
                throw Error("Error setting notification")
            }
            val descriptor = characteristic.getDescriptor(clientCharacteristicConfigUuid.toJavaUuid())
            if (descriptor == null) {
                throw Error("Error getting clientCharacteristicConfig descriptor")
            }
            descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            if (!gatt!!.writeDescriptor(descriptor)) {
                throw Error("Error writing to clientCharacteristicConfig descriptor")
            }
        }
    }

    override suspend fun subscribeToCharacteristics() {
        enableNotifications(characteristicState!!)
        enableNotifications(characteristicServer2Client!!)
    }

    private suspend fun writeToCharacteristic(
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val rc = gatt!!.writeCharacteristic(
                characteristic,
                value,
                BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            )
            if (rc != BluetoothStatusCodes.SUCCESS) {
                throw Error("Error writing to characteristic ${characteristic.uuid}, rc=$rc")
            }
        } else {
            characteristic!!.setValue(value)
            if (!gatt!!.writeCharacteristic(characteristic)) {
                throw Error("Error writing to characteristic ${characteristic.uuid}")
            }
        }
        suspendCancellableCoroutine<Boolean> { continuation ->
            setWaitCondition(WaitState.CHARACTERISTIC_WRITE_COMPLETED, continuation)
        }
    }

    override suspend fun writeToStateCharacteristic(value: Int) {
        writeToCharacteristic(characteristicState!!, byteArrayOf(value.toByte()))
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

            writeToCharacteristic(characteristicClient2Server!!, chunk)
        }
        Logger.i(TAG, "sendMessage completed")
    }

    override fun close() {
        Logger.d(TAG, "close()")
        bluetoothManager.adapter.bluetoothLeScanner.stopScan(scanCallback)
        gatt?.disconnect()
        gatt?.close()
        gatt = null
        device = null
        // Needed since l2capSocket.outputStream.flush() isn't working
        l2capSocket?.let {
            CoroutineScope(Dispatchers.IO).launch() {
                delay(5000)
                it.close()
            }
        }
        l2capSocket = null
        incomingMessages.close()
    }

    private var _l2capPsm: Int? = null

    override val l2capPsm: Int?
        get() = _l2capPsm

    override val usingL2cap: Boolean
        get() = (l2capSocket != null)

    private var l2capSocket: BluetoothSocket? = null

    override suspend fun connectL2cap(psm: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            connectL2capQ(psm)
        } else {
            throw IllegalStateException("L2CAP only support on API 29 or later")
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private suspend fun connectL2capQ(psm: Int) {
        l2capSocket = device!!.createInsecureL2capChannel(psm)
        l2capSocket!!.connect()

        // Start reading in a coroutine
        CoroutineScope(Dispatchers.IO).launch {
            l2capReadSocket(l2capSocket!!.inputStream)
        }
    }

    private suspend fun l2capReadSocket(inputStream: InputStream) {
        try {
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
            onError(Error("Reading from L2CAP socket failed", e))
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

// Cannot call it readNBytes() b/c that's taken on API >= 33
//
internal fun InputStream.readNOctets(len: UInt): ByteArray {
    val bsb = ByteStringBuilder()
    var remaining = len.toInt()
    while (remaining > 0) {
        val buf = ByteArray(remaining.toInt())
        val numBytesRead = this.read(buf, 0, remaining)
        if (numBytesRead == -1) {
            throw IllegalStateException("Failed reading from input stream")
        }
        bsb.append(buf, 0, numBytesRead)
        remaining -= numBytesRead
    }
    return bsb.toByteString().toByteArray()
}

