package com.android.mdl.appreader.transfer

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.security.identity.DataRetrievalAddress
import androidx.security.identity.DeviceRequestGenerator
import androidx.security.identity.DeviceResponseParser
import androidx.security.identity.VerificationHelper
import com.android.mdl.appreader.document.RequestDocumentList
import com.android.mdl.appreader.util.IssuerKeys
import com.android.mdl.appreader.util.PreferencesHelper
import com.android.mdl.appreader.util.TransferStatus
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.Executor


class TransferManager private constructor(private val context: Context) {

    companion object {
        private const val LOG_TAG = "TransferManager"

        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: TransferManager? = null

        fun getInstance(context: Context) =
            instance ?: synchronized(this) {
                instance ?: TransferManager(context).also { instance = it }
            }
    }


    var mdocAddress: DataRetrievalAddress? = null
        private set
    private var hasStarted = false
    var responseBytes: ByteArray? = null
        private set
    private var verification: VerificationHelper? = null
    var availableMdocAddresses: Collection<DataRetrievalAddress>? = null
        private set

    private var transferStatusLd = MutableLiveData<TransferStatus>()

    fun getTransferStatus(): LiveData<TransferStatus> = transferStatusLd

    fun initVerificationHelper() {
        verification = VerificationHelper(context)
        verification?.setListener(responseListener, context.mainExecutor())
        verification?.setLoggingFlags(PreferencesHelper.getLoggingFlags(context))
    }

    fun setQrDeviceEngagement(qrDeviceEngagement: String) {
        verification?.setDeviceEngagementFromQrCode(qrDeviceEngagement)
    }

    fun setNdefDeviceEngagement(adapter: NfcAdapter, activity: Activity) {
        verification?.setNfcAdapter(adapter, activity)
        verification?.verificationBegin()
    }

    fun setAvailableTransferMethods(availableMdocAddresses: Collection<DataRetrievalAddress>) {
        this.availableMdocAddresses = availableMdocAddresses
        // Select the first method as default, let the user select other transfer method
        // if there are more than one
        if (availableMdocAddresses.isNotEmpty()) {
            this.mdocAddress = availableMdocAddresses.first()
        }
    }

    fun connect() {
        if (hasStarted)
            throw IllegalStateException("Connection has already started. It is necessary to stop verification before starting a new one.")

        if (verification == null)
            throw IllegalStateException("It is necessary to start a new engagement.")

        if (mdocAddress == null)
            throw IllegalStateException("No mdoc address selected.")

        // Start connection
        verification?.let {
            mdocAddress?.let { dr ->
                it.connect(dr)
            }
            hasStarted = true
        }
    }

    fun stopVerification(
        sendSessionTerminationMessage: Boolean,
        useTransportSpecificSessionTermination: Boolean
    ) {
        verification?.setSendSessionTerminationMessage(sendSessionTerminationMessage)
        verification?.setUseTransportSpecificSessionTermination(
            useTransportSpecificSessionTermination
        )
        verification?.setListener(null, null)
        try {
            verification?.disconnect()
        } catch (e: RuntimeException) {
            Log.e(LOG_TAG, "Error ignored.", e)
        }
        transferStatusLd = MutableLiveData<TransferStatus>()
        destroy()
        hasStarted = false
    }

    private fun destroy() {
        responseBytes = null
        verification = null
    }


    private val responseListener = object : VerificationHelper.Listener {
        override fun onDeviceEngagementReceived(addresses: MutableList<DataRetrievalAddress>) {
            setAvailableTransferMethods(addresses)
            transferStatusLd.value = TransferStatus.ENGAGED
        }

        override fun onDeviceConnected() {
            transferStatusLd.value = TransferStatus.CONNECTED
        }

        override fun onResponseReceived(deviceResponseBytes: ByteArray) {
            responseBytes = deviceResponseBytes
            transferStatusLd.value = TransferStatus.RESPONSE
        }

        override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
            transferStatusLd.value = TransferStatus.DISCONNECTED
        }

        override fun onError(error: Throwable) {
            Log.e(LOG_TAG, "onError: ${error.message}")
            transferStatusLd.value = TransferStatus.ERROR
        }
    }

    private fun Context.mainExecutor(): Executor {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            mainExecutor
        } else {
            ContextCompat.getMainExecutor(context)
        }
    }

    fun sendRequest(requestDocumentList: RequestDocumentList) {
        if (verification == null)
            throw IllegalStateException("It is necessary to start a new engagement.")

        verification?.let {
            var readerKey: PrivateKey? = null
            var readerKeyCertificateChain: Collection<X509Certificate>? = null

            // Check in preferences if reader authentication should be used
            when (PreferencesHelper.getReaderAuth(context)) {
                "1" -> {
                    readerKey = IssuerKeys.getRAGooglePrivateKey(context)
                    readerKeyCertificateChain = listOf(IssuerKeys.getRAGoogleCertificate(context))
                }
            }

            val generator = DeviceRequestGenerator()
            generator.setSessionTranscript(it.sessionTranscript)
            requestDocumentList.getAll().forEach { requestDocument ->
                generator.addDocumentRequest(
                    requestDocument.docType,
                    requestDocument.getItemsToRequest(),
                    null,
                    readerKey,
                    readerKeyCertificateChain
                )
            }
            verification?.sendRequest(generator.generate())
        }
    }

    fun sendNewRequest(requestDocumentList: RequestDocumentList) {
        // reset transfer status
        transferStatusLd = MutableLiveData<TransferStatus>()
        sendRequest(requestDocumentList)
    }

    fun setMdocAddress(address: DataRetrievalAddress) {
        this.mdocAddress = address
    }

    fun getDeviceResponse(): DeviceResponseParser.DeviceResponse {
        responseBytes?.let { rb ->
            verification?.let { v ->
                val parser = DeviceResponseParser()
                parser.setSessionTranscript(v.sessionTranscript)
                parser.setEphemeralReaderKey(v.ephemeralReaderKey)
                parser.setDeviceResponse(rb)
                return parser.parse()
            } ?: throw IllegalStateException("Verification is null")
        } ?: throw IllegalStateException("Response not received")
    }
}