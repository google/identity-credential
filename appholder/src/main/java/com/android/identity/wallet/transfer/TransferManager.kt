package com.android.identity.wallet.transfer

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color.BLACK
import android.graphics.Color.WHITE
import android.view.View
import android.widget.ImageView
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.android.identity.document.DocumentRequest
import com.android.identity.document.NameSpacedData
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.origininfo.OriginInfo
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.crypto.Algorithm
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.wallet.document.DocumentManager
import com.android.identity.wallet.documentdata.DocumentDataReader
import com.android.identity.wallet.documentdata.DocumentElements
import com.android.identity.wallet.util.ProvisioningUtil
import com.android.identity.wallet.util.TransferStatus
import com.android.identity.wallet.util.log
import com.android.identity.wallet.util.logWarning
import com.android.identity.wallet.util.requireValidProperty
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.datetime.Clock
import kotlin.coroutines.resume

class TransferManager private constructor(private val context: Context) {

    companion object {
        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: TransferManager? = null

        fun getInstance(context: Context) =
            instance ?: synchronized(this) {
                instance ?: TransferManager(context).also { instance = it }
            }
    }

    private var reversedQrCommunicationSetup: ReverseQrCommunicationSetup? = null
    private var qrCommunicationSetup: QrCommunicationSetup? = null
    private var hasStarted = false

    private lateinit var communication: Communication

    private var transferStatusLd = MutableLiveData<TransferStatus>()

    fun setCommunication(communication: Communication) {
        this.communication = communication
    }

    fun getTransferStatus(): LiveData<TransferStatus> = transferStatusLd

    fun updateStatus(status: TransferStatus) {
        transferStatusLd.value = status
    }

    fun documentRequests(): Collection<DeviceRequestParser.DocRequest> {
        return communication.getDeviceRequest().docRequests
    }

    fun startPresentationReverseEngagement(
        reverseEngagementUri: String,
        origins: List<OriginInfo>
    ) {
        if (hasStarted) {
            throw IllegalStateException("Transfer has already started.")
        }
        communication = Communication.getInstance(context)
        reversedQrCommunicationSetup = ReverseQrCommunicationSetup(
            context = context,
            onPresentationReady = { deviceRetrievalHelper ->
                communication.deviceRetrievalHelper = deviceRetrievalHelper
            },
            onNewRequest = { request ->
                communication.setDeviceRequest(request)
                transferStatusLd.value = TransferStatus.REQUEST
            },
            onDisconnected = { transferStatusLd.value = TransferStatus.DISCONNECTED },
            onCommunicationError = { error ->
                log("onError: ${error.message}")
                transferStatusLd.value = TransferStatus.ERROR
            }
        ).apply {
            configure(reverseEngagementUri, origins)
        }
        hasStarted = true
    }

    fun startQrEngagement() {
        if (hasStarted) {
            throw IllegalStateException("Transfer has already started.")
        }
        communication = Communication.getInstance(context)
        qrCommunicationSetup = QrCommunicationSetup(
            context = context,
            onConnecting = { transferStatusLd.value = TransferStatus.CONNECTING },
            onDeviceRetrievalHelperReady = { deviceRetrievalHelper ->
                communication.deviceRetrievalHelper = deviceRetrievalHelper
                transferStatusLd.value = TransferStatus.CONNECTED
            },
            onNewDeviceRequest = { deviceRequest ->
                communication.setDeviceRequest(deviceRequest)
                transferStatusLd.value = TransferStatus.REQUEST
            },
            onDisconnected = { transferStatusLd.value = TransferStatus.DISCONNECTED }
        ) { error ->
            log("onError: ${error.message}")
            transferStatusLd.value = TransferStatus.ERROR
        }.apply {
            configure()
        }
        hasStarted = true
    }

    fun getDeviceEngagementQrCode(): View {
        val deviceEngagementForQrCode = qrCommunicationSetup!!.deviceEngagementUriEncoded
        val qrCodeBitmap = encodeQRCodeAsBitmap(deviceEngagementForQrCode)
        val qrCodeView = ImageView(context)
        qrCodeView.setImageBitmap(qrCodeBitmap)

        return qrCodeView
    }

    private fun encodeQRCodeAsBitmap(str: String): Bitmap {
        val width = 800
        val result: BitMatrix = try {
            MultiFormatWriter().encode(
                str,
                BarcodeFormat.QR_CODE, width, width, null
            )
        } catch (e: WriterException) {
            throw java.lang.IllegalArgumentException(e)
        }
        val w = result.width
        val h = result.height
        val pixels = IntArray(w * h)
        for (y in 0 until h) {
            val offset = y * w
            for (x in 0 until w) {
                pixels[offset + x] = if (result[x, y]) BLACK else WHITE
            }
        }
        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bitmap.setPixels(pixels, 0, width, 0, 0, w, h)
        return bitmap
    }

    @Throws(IllegalStateException::class)
    suspend fun addDocumentToResponse(
        documentName: String,
        docType: String,
        issuerSignedEntriesToRequest: MutableMap<String, Collection<String>>,
        deviceResponseGenerator: DeviceResponseGenerator,
        credential: MdocCredential?,
        authKeyUnlockData: KeyUnlockData?,
    ) = suspendCancellableCoroutine { continuation ->
        var result: AddDocumentToResponseResult
        var signingKeyUsageLimitPassed = false
        val documentManager = DocumentManager.getInstance(context)
        val documentInformation = documentManager.getDocumentInformation(documentName)
        requireValidProperty(documentInformation) { "Document not found!" }

        val document = requireNotNull(documentManager.getDocumentByName(documentName))
        val dataElements = issuerSignedEntriesToRequest.keys.flatMap { key ->
            issuerSignedEntriesToRequest.getOrDefault(key, emptyList()).map { value ->
                DocumentRequest.DataElement(key, value, false)
            }
        }

        val request = DocumentRequest(dataElements)

        val credentialToUse: MdocCredential
        if (credential != null) {
            credentialToUse = credential
        } else {
            credentialToUse = document.findCredential(
                ProvisioningUtil.MDOC_CREDENTIAL_DOMAIN,
                Clock.System.now()
            ) as MdocCredential?
                ?: throw IllegalStateException("No credential available")
        }

        if (credentialToUse.usageCount >= documentInformation.maxUsagesPerKey) {
            logWarning("Using Credential previously used ${credentialToUse.usageCount} times, and maxUsagesPerKey is ${documentInformation.maxUsagesPerKey}")
            signingKeyUsageLimitPassed = true
        }

        val staticAuthData = StaticAuthDataParser(credentialToUse.issuerProvidedData).parse()
        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            request,
            document.applicationData.getNameSpacedData("documentData"),
            staticAuthData
        )

        val transcript = communication.getSessionTranscript() ?: byteArrayOf()

        try {
            val generator = DocumentGenerator(docType, staticAuthData.issuerAuth, transcript)
                .setIssuerNamespaces(mergedIssuerNamespaces)
            val keyInfo = credentialToUse.secureArea.getKeyInfo(credentialToUse.alias)
            if (keyInfo.keyPurposes.contains(KeyPurpose.SIGN)) {
                generator.setDeviceNamespacesSignature(
                    NameSpacedData.Builder().build(),
                    credentialToUse.secureArea,
                    credentialToUse.alias,
                    authKeyUnlockData,
                    Algorithm.ES256
                )
            } else {
                generator.setDeviceNamespacesMac(
                    NameSpacedData.Builder().build(),
                    credentialToUse.secureArea,
                    credentialToUse.alias,
                    authKeyUnlockData,
                    communication.deviceRetrievalHelper!!.eReaderKey
                )
            }
            val data = generator.generate()
            deviceResponseGenerator.addDocument(data)
            log("Increasing usage count on ${credentialToUse.alias}")
            credentialToUse.increaseUsageCount()
            ProvisioningUtil.getInstance(context).trackUsageTimestamp(document)
            result = AddDocumentToResponseResult.DocumentAdded(signingKeyUsageLimitPassed)
        } catch (lockedException: KeyLockedException) {
            result = AddDocumentToResponseResult.DocumentLocked(credentialToUse)
        }
        continuation.resume(result)
    }

    fun stopPresentation(
        sendSessionTerminationMessage: Boolean,
        useTransportSpecificSessionTermination: Boolean
    ) {
        communication.stopPresentation(
            sendSessionTerminationMessage,
            useTransportSpecificSessionTermination
        )
        disconnect()
    }

    fun disconnect() {
        communication.disconnect()
        qrCommunicationSetup?.close()
        transferStatusLd = MutableLiveData<TransferStatus>()
        destroy()
    }

    fun destroy() {
        qrCommunicationSetup = null
        reversedQrCommunicationSetup = null
        hasStarted = false
    }

    fun sendResponse(deviceResponse: ByteArray, closeAfterSending: Boolean) {
        communication.sendResponse(deviceResponse, closeAfterSending)
        if (closeAfterSending) {
            disconnect()
        }
    }

    fun readDocumentEntries(documentName: String): DocumentElements {
        val documentManager = DocumentManager.getInstance(context)
        val documentInformation = documentManager.getDocumentInformation(documentName)

        val document = requireNotNull(documentManager.getDocumentByName(documentName))
        val nameSpacedData = document.applicationData.getNameSpacedData("documentData")
        return DocumentDataReader(documentInformation?.docType ?: "").read(nameSpacedData)
    }

    fun setResponseServed() {
        transferStatusLd.value = TransferStatus.REQUEST_SERVED
    }
}