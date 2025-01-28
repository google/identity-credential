package com.android.identity.age_verifier_mdl

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.nfc.NfcAdapter
import android.preference.PreferenceManager
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper
import com.android.identity.android.mdoc.transport.ConnectionMethodTcp
import com.android.identity.android.mdoc.transport.ConnectionMethodUdp
import com.android.identity.android.mdoc.transport.DataTransportOptions
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.connectionmethod.ConnectionMethodNfc
import com.android.identity.mdoc.connectionmethod.ConnectionMethodWifiAware
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.storage.Storage
import com.android.identity.storage.android.AndroidStorage
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import java.io.File

class TransferHelper private constructor(
    private var context: Context,
    private var activity: Activity
) {

    companion object {
        private val TAG = "TransferHelper"

        val PREFERENCE_KEY_INCLUDE_PORTRAIT_IN_REQUEST = "include_portrait_in_request"

        val PREFERENCE_KEY_BLE_CENTRAL_CLIENT_DATA_TRANSFER_ENABLED = "ble_central_client_data_transfer_enabled"
        val PREFERENCE_KEY_BLE_PERIPHERAL_SERVER_DATA_TRANSFER_ENABLED = "ble_peripheral_server_data_transfer_enabled"
        val PREFERENCE_KEY_WIFI_AWARE_DATA_TRANSFER_ENABLED = "wifi_aware_data_transfer_enabled"
        val PREFERENCE_KEY_NFC_DATA_TRANSFER_ENABLED = "nfc_data_transfer_enabled"
        val PREFERENCE_KEY_TCP_DATA_TRANSFER_ENABLED = "tcp_data_transfer_enabled"
        val PREFERENCE_KEY_UDP_DATA_TRANSFER_ENABLED = "udp_data_transfer_enabled"

        val PREFERENCE_KEY_EXPERIMENTAL_PSM_ENABLED = "experimental_psm_enabled"
        val PREFERENCE_KEY_L2CAP_ENABLED = "l2cap_enabled"
        val PREFERENCE_KEY_DEBUG_ENABLED = "debug_enabled"

        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: TransferHelper? = null

        fun getInstance(context: Context, activity: Activity) =
            instance ?: synchronized(this) {
                instance ?: TransferHelper(context, activity).also { instance = it }
            }
    }

    private var sharedPreferences: SharedPreferences
    private var storage: Storage
    var androidKeystoreSecureAreaProvider: SecureAreaProvider<AndroidKeystoreSecureArea>

    private var verificationHelper: VerificationHelper? = null
    var deviceResponseBytes: ByteArray? = null
    var error: Throwable? = null
    private var connectionMethodUsed: ConnectionMethod? = null

    private var state = MutableLiveData<State>()

    enum class State {
        IDLE,
        ENGAGING,
        CONNECTING,
        CONNECTED,
        REQUEST_SENT,
        TRANSACTION_COMPLETE,
    }

    private val listener = object : VerificationHelper.Listener {
        override fun onReaderEngagementReady(readerEngagement: ByteArray) {
            Logger.d(TAG, "onReaderEngagementReady")
        }

        override fun onDeviceEngagementReceived(connectionMethods: List<ConnectionMethod>) {
            Logger.d(TAG, "onDeviceEngagementReceived")
            connectionMethodUsed = connectionMethods.first()
            verificationHelper!!.connect(connectionMethods.first())
            state.value = State.CONNECTING
        }

        override fun onMoveIntoNfcField() {
            Logger.d(TAG, "onMoveIntoNfcField")
        }

        override fun onDeviceConnected() {
            Logger.d(TAG, "onDeviceConnected")
            state.value = State.CONNECTED
        }

        override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
            Logger.d(TAG, "onDeviceDisconnected, $transportSpecificTermination")
            close()
        }

        override fun onResponseReceived(deviceResponseBytes_: ByteArray) {
            Logger.d(TAG, "onResponseReceived")
            deviceResponseBytes = deviceResponseBytes_
            state.value = State.TRANSACTION_COMPLETE
        }

        override fun onError(error_: Throwable) {
            Logger.d(TAG, "onError $error")
            error = error_
            state.value = State.TRANSACTION_COMPLETE
        }
    }

    // Called when setings have changed
    fun reinitializeVerificationHelper() {
        initializeVerificationHelper()
    }

    private fun initializeVerificationHelper() {
        val builder = VerificationHelper.Builder(context, listener, context.mainExecutor)
        val options = DataTransportOptions.Builder()
            .setBleUseL2CAP(getL2CapEnabled())
            .setExperimentalBleL2CAPPsmInEngagement(getExperimentalPsmEnabled())
            .build()
        builder.setDataTransportOptions(options)

        val connectionMethods = mutableListOf<ConnectionMethod>()
        val bleUuid = UUID.randomUUID()
        if (getBleCentralClientDataTransferEnabled()) {
            connectionMethods.add(ConnectionMethodBle(
                false,
                true,
                null,
                bleUuid))
        }
        if (getBlePeripheralServerDataTransferEnabled()) {
            connectionMethods.add(ConnectionMethodBle(
                true,
                false,
                bleUuid,
                null))
        }
        if (getWifiAwareDataTransferEnabled()) {
            connectionMethods.add(ConnectionMethodWifiAware(null, null, null, null))
        }
        if (getNfcDataTransferEnabled()) {
            connectionMethods.add(ConnectionMethodNfc(4096, 32768))
        }
        if (getTcpDataTransferEnabled()) {
            connectionMethods.add(ConnectionMethodTcp("", 0))
        }
        if (getUdpDataTransferEnabled()) {
            connectionMethods.add(ConnectionMethodUdp("", 0))
        }
        builder.setNegotiatedHandoverConnectionMethods(connectionMethods)


        verificationHelper?.disconnect()
        verificationHelper = builder.build()
        deviceResponseBytes = null
        connectionMethodUsed = null
        error = null
        Logger.d(TAG, "Initialized VerificationHelper")
    }

    fun getSessionTranscript(): ByteArray {
        return verificationHelper!!.sessionTranscript
    }

    fun sendRequest(deviceRequestBytes: ByteArray) {
        check(state.value == State.CONNECTED)
        verificationHelper!!.sendRequest(deviceRequestBytes)
        state.value = State.REQUEST_SENT
    }


    fun getTapToEngagementDurationMillis(): Long {
        return verificationHelper!!.tapToEngagementDurationMillis
    }

    fun getEngagementToRequestDurationMillis(): Long {
        return verificationHelper!!.engagementToRequestDurationMillis
    }

    fun getRequestToResponseDurationMillis(): Long {
        return verificationHelper!!.requestToResponseDurationMillis
    }

    fun getScanningDurationMillis(): Long {
        return verificationHelper!!.scanningTimeMillis
    }


    fun getEngagementMethod(): VerificationHelper.EngagementMethod {
        return verificationHelper!!.engagementMethod
    }

    init {
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        val storageFile = File(context.noBackupFilesDir.path, "identity.db")
        storage = AndroidStorage(storageFile.absolutePath)
        androidKeystoreSecureAreaProvider = SecureAreaProvider {
            AndroidKeystoreSecureArea.create(context, storage)
        }
        state.value = State.IDLE

        initializeVerificationHelper()

        val nfcAdapter = NfcAdapter.getDefaultAdapter(context)
        nfcAdapter.enableReaderMode(
            activity,
            { tag ->
                if (state.value == State.IDLE) {
                    verificationHelper!!.nfcProcessOnTagDiscovered(tag)
                }
                state.postValue(State.ENGAGING)
            },
            NfcAdapter.FLAG_READER_NFC_A + NfcAdapter.FLAG_READER_NFC_B
                    + NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK + NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
            null)
    }

    fun getState(): LiveData<State> {
        return state
    }

    fun close() {
        if (state.value == State.IDLE) {
            return
        }
        Logger.i(TAG, "close")
        initializeVerificationHelper()
        state.value = State.IDLE
    }

    fun getConnectionMethod(): String {
        return connectionMethodUsed?.toString() ?: ""
    }

    fun getIncludePortraitInRequest(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_INCLUDE_PORTRAIT_IN_REQUEST, true)
    }

    fun setIncludePortraitInRequest(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_INCLUDE_PORTRAIT_IN_REQUEST, enabled)
        }
    }

    fun getWifiAwareDataTransferEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_WIFI_AWARE_DATA_TRANSFER_ENABLED, false)
    }

    fun setWifiAwareDataTransferEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_WIFI_AWARE_DATA_TRANSFER_ENABLED, enabled)
        }
    }

    fun getNfcDataTransferEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_NFC_DATA_TRANSFER_ENABLED, false)
    }

    fun setNfcDataTransferEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_NFC_DATA_TRANSFER_ENABLED, enabled)
        }
    }

    fun getTcpDataTransferEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_TCP_DATA_TRANSFER_ENABLED, false)
    }

    fun setTcpDataTransferEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_TCP_DATA_TRANSFER_ENABLED, enabled)
        }
    }

    fun getUdpDataTransferEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_UDP_DATA_TRANSFER_ENABLED, false)
    }

    fun setUdpDataTransferEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_UDP_DATA_TRANSFER_ENABLED, enabled)
        }
    }

    fun getBleCentralClientDataTransferEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_BLE_CENTRAL_CLIENT_DATA_TRANSFER_ENABLED, true)
    }

    fun setBleCentralClientDataTransferEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_BLE_CENTRAL_CLIENT_DATA_TRANSFER_ENABLED, enabled)
        }
    }

    fun getBlePeripheralServerDataTransferEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_BLE_PERIPHERAL_SERVER_DATA_TRANSFER_ENABLED, false)
    }

    fun setBlePeripheralServerDataTransferEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_BLE_PERIPHERAL_SERVER_DATA_TRANSFER_ENABLED, enabled)
        }
    }

    fun getExperimentalPsmEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_EXPERIMENTAL_PSM_ENABLED, false)
    }

    fun setExperimentalPsmEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_EXPERIMENTAL_PSM_ENABLED, enabled)
        }
    }

    fun getL2CapEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_L2CAP_ENABLED, false)
    }

    fun setL2CapEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_L2CAP_ENABLED, enabled)
        }
    }

    fun getDebugEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_DEBUG_ENABLED, false)
    }

    fun setDebugEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_DEBUG_ENABLED, enabled)
        }
    }


}