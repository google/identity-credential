/*
 * Copyright (C) 2023 Google LLC
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

package com.android.identity.preconsent_mdl

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.preference.PreferenceManager
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.android.identity.android.mdoc.deviceretrieval.DeviceRetrievalHelper
import com.android.identity.android.mdoc.transport.DataTransport
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.credential.CredentialFactory
import com.android.identity.document.DocumentStore
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.Storage
import com.android.identity.storage.android.AndroidStorage
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import kotlinx.datetime.Clock
import java.io.File

class TransferHelper private constructor(private val context: Context) {

    companion object {
        private val TAG = "TransferHelper"

        val PREFERENCE_KEY_NFC_STATIC_HANDOVER_ENABLED = "nfc_static_handover_enabled"
        val PREFERENCE_KEY_NFC_NEGOTIATED_HANDOVER_ENABLED = "nfc_negotiated_handover_enabled"

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

        fun getInstance(context: Context) =
            instance ?: synchronized(this) {
                instance ?: TransferHelper(context).also { instance = it }
            }
    }

    var secureAreaRepository: SecureAreaRepository
    var documentStore: DocumentStore
    private var credentialFactory: CredentialFactory

    private var sharedPreferences: SharedPreferences
    private var storage: Storage
    private var deviceRetrievalHelper: DeviceRetrievalHelper? = null
    private var connectionMethod: ConnectionMethod? = null
    private var deviceRequest: ByteArray? = null

    private var timestampTap: Long = 0
    private var timestampEngagementSent: Long = 0
    private var timestampRequestAvailable: Long = 0
    private var timestampResponseSent: Long = 0
    private var scanningDurationMillis: Long = 0

    private var state = MutableLiveData<State>()

    enum class State {
        NOT_CONNECTED,
        ENGAGING,
        ENGAGEMENT_SENT,
        CONNECTED,
        REQUEST_AVAILABLE,
        RESPONSE_SENT
    }

    init {
        val storagePath = File(context.noBackupFilesDir.path, "identity.bin").absolutePath
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        storage = AndroidStorage(storagePath)
        secureAreaRepository = SecureAreaRepository.build {
            add(AndroidKeystoreSecureArea.create(context, storage))
        }
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(MdocCredential::class) {
            document -> MdocCredential(document)
        }
        documentStore = DocumentStore(
            storage = storage,
            secureAreaRepository = secureAreaRepository,
            credentialFactory = credentialFactory,
            documentMetadataFactory = PreconsentDocumentMetadata::create
        )
        state.value = State.NOT_CONNECTED
    }

    fun getState(): LiveData<State> {
        return state
    }

    fun getNfcStaticHandoverEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_NFC_STATIC_HANDOVER_ENABLED, false)
    }

    fun setNfcStaticHandoverEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_NFC_STATIC_HANDOVER_ENABLED, enabled)
        }
    }

    fun getNfcNegotiatedHandoverEnabled(): Boolean {
        return sharedPreferences.getBoolean(PREFERENCE_KEY_NFC_NEGOTIATED_HANDOVER_ENABLED, true)
    }

    fun setNfcNegotiatedHandoverEnabled(enabled: Boolean) {
        sharedPreferences.edit {
            putBoolean(PREFERENCE_KEY_NFC_NEGOTIATED_HANDOVER_ENABLED, enabled)
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

    fun setEngagementSent() {
        timestampEngagementSent = Clock.System.now().toEpochMilliseconds()
        state.value = State.ENGAGEMENT_SENT
    }

    fun setEngaging() {
        timestampTap = Clock.System.now().toEpochMilliseconds()
        state.value = State.ENGAGING
    }

    fun setConnected(
        eDeviceKey: EcPrivateKey,
        transport: DataTransport,
        deviceEngagement: ByteArray,
        handover: ByteArray
    ) {
        scanningDurationMillis = 0
        deviceRetrievalHelper = DeviceRetrievalHelper.Builder(
            context,
            object : DeviceRetrievalHelper.Listener {
                override fun onEReaderKeyReceived(eReaderKey: EcPublicKey) {
                    Logger.i(TAG, "onEReaderKeyReceived")
                }

                override fun onDeviceRequest(deviceRequestBytes: ByteArray) {
                    Logger.i(TAG, "onDeviceRequest")
                    deviceRequest = deviceRequestBytes
                    timestampRequestAvailable = Clock.System.now().toEpochMilliseconds()
                    scanningDurationMillis = deviceRetrievalHelper?.scanningTimeMillis ?: 0
                    state.value = State.REQUEST_AVAILABLE
                }

                override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
                    Logger.i(TAG, "onDeviceDisconnected $transportSpecificTermination")
                    deviceRetrievalHelper?.disconnect()
                    deviceRetrievalHelper = null
                    state.value = State.NOT_CONNECTED
                }

                override fun onError(error: Throwable) {
                    Logger.i(TAG, "onError", error)
                    deviceRetrievalHelper?.disconnect()
                    deviceRetrievalHelper = null
                    state.value = State.NOT_CONNECTED
                }

            },
            context.mainExecutor,
            eDeviceKey)
            .useForwardEngagement(transport, deviceEngagement, handover)
            .build()
        connectionMethod = transport.connectionMethodForTransport
        state.value = State.CONNECTED
    }

    fun getDeviceRequest(): ByteArray {
        check(state.value == State.REQUEST_AVAILABLE) { "Not in REQUEST_AVAILABLE state"}
        check(deviceRequest != null) { "No request available "}
        return deviceRequest as ByteArray
    }

    fun getSessionTranscript(): ByteArray {
        return deviceRetrievalHelper!!.sessionTranscript
    }

    fun sendResponse(deviceResponseBytes: ByteArray) {
        check(state.value == State.REQUEST_AVAILABLE) { "Not in REQUEST_AVAILABLE state"}
        deviceRetrievalHelper!!.sendDeviceResponse(
            deviceResponseBytes,
            Constants.SESSION_DATA_STATUS_SESSION_TERMINATION
        )
        timestampResponseSent = Clock.System.now().toEpochMilliseconds()
        state.value = State.RESPONSE_SENT
    }

    fun getConnectionMethod(): ConnectionMethod {
        return connectionMethod!!
    }

    fun getTapToEngagementSentDurationMillis(): Long {
        return timestampEngagementSent - timestampTap
    }

    fun getEngagementSentToRequestAvailableDurationMillis(): Long {
        return timestampRequestAvailable - timestampEngagementSent;
    }

    fun getRequestToResponseDurationMillis(): Long {
        return timestampResponseSent - timestampRequestAvailable
    }

    fun getTotalDurationMillis(): Long {
        return timestampResponseSent - timestampTap
    }

    fun getScanningDurationMillis(): Long {
        return scanningDurationMillis
    }

    fun disconnect() {
        Logger.i(TAG, "disconnect")
        if (deviceRetrievalHelper == null) {
            Logger.i(TAG, "already closed")
            return
        }
        if (state.value == State.REQUEST_AVAILABLE) {
            val deviceResponseGenerator = DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_GENERAL_ERROR)
            sendResponse(deviceResponseGenerator.generate())
        }
        deviceRetrievalHelper?.disconnect()
        deviceRetrievalHelper = null
        state.value = State.NOT_CONNECTED
    }

}