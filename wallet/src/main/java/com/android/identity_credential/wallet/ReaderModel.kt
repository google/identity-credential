package com.android.identity_credential.wallet

import android.app.Activity
import android.content.Context
import android.content.res.Resources
import android.graphics.BitmapFactory
import android.nfc.NfcAdapter
import android.os.VibrationEffect
import android.os.Vibrator
import androidx.compose.runtime.mutableStateOf
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.documenttype.DocumentAttributeType
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.DocumentCannedRequest
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.request.DeviceRequestGenerator
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.util.Logger
import kotlinx.datetime.Clock

class ReaderModel(
    val context: Context,
    val documentTypeRepository: DocumentTypeRepository,
    val settingsModel: SettingsModel
) {
    companion object {
        private const val TAG = "ReaderModel"
    }

    var phase = mutableStateOf(Phase.IDLE)
    var response: ReaderResponse? = null
    var error: Throwable? = null

    enum class Phase {
        IDLE,
        WAITING_FOR_ENGAGEMENT,
        WAITING_FOR_CONNECTION,
        WAITING_FOR_RESPONSE,
        COMPLETE,
    }

    private val nfcAdapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(context)
    private val vibrator = context.getSystemService(Vibrator::class.java)

    private var activityForNfcReaderMode: Activity? = null
    private var requestToUse: DocumentCannedRequest? = null
    private var activityToUse: Activity? = null
    private var trustManagerToUse: TrustManager? = null

    private var verificationHelper: VerificationHelper? = null

    private val nfcReaderModeListener = NfcAdapter.ReaderCallback { tag ->
        verificationHelper?.nfcProcessOnTagDiscovered(tag)
    }

    private fun releaseResources() {
        if (verificationHelper != null) {
            Logger.i(TAG, "Stopping VerificationHelper instance")
            verificationHelper?.disconnect()
            verificationHelper = null
        }
        if (activityForNfcReaderMode != null) {
            if (nfcAdapter != null) {
                Logger.i(TAG, "Disabling reader mode on NfcAdapter")
                nfcAdapter.disableReaderMode(activityForNfcReaderMode)
            }
            activityForNfcReaderMode = null
        }
    }

    // Should be called when getting ready to use the reader.
    //
    // Transitions to Phase.IDLE.
    //
    fun cancel() {
        Logger.i(TAG, "Canceled")
        releaseResources()
        response = null
        error = null
        phase.value = Phase.IDLE
    }

    fun restart() {
        Logger.i(TAG, "Restart")
        releaseResources()
        response = null
        error = null
        startRequest(activityToUse!!, requestToUse!!, trustManagerToUse!!)
    }

    private fun reportError(e: Throwable) {
        Logger.i(TAG, "Completed with error", e)
        releaseResources()
        error = e
        response = null
        phase.value = Phase.COMPLETE
    }

    private fun reportResponse(response: ReaderResponse) {
        Logger.i(TAG, "Completed with response")
        releaseResources()
        this.response = response
        error = null
        phase.value = Phase.COMPLETE
    }

    fun setQrCode(qrCode: String) {
        verificationHelper?.setDeviceEngagementFromQrCode(qrCode)
        phase.value = Phase.WAITING_FOR_CONNECTION
    }

    fun updateRequest(request: DocumentCannedRequest) {
        requestToUse = request
    }

    // Should be called to start reading
    fun startRequest(
        activity: Activity,
        request: DocumentCannedRequest,
        trustManager: TrustManager
    ) {
        releaseResources()
        response = null
        error = null
        activityToUse = activity
        requestToUse = request
        trustManagerToUse = trustManager
        phase.value = Phase.WAITING_FOR_ENGAGEMENT

        val (connectionMethods, dataTransportOptions) =
            settingsModel.createConnectionMethodsAndOptions()

        val listener = object : VerificationHelper.Listener {
            override fun onReaderEngagementReady(readerEngagement: ByteArray) {
            }

            override fun onDeviceEngagementReceived(connectionMethods: List<ConnectionMethod>) {
                Logger.i(TAG, "onDeviceEngagementReceived")
                vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_HEAVY_CLICK))
                if (connectionMethods.isEmpty()) {
                    reportError(Error("List of connectionMethods is empty"))
                } else {
                    // For now, just connect to the first method... might have UI in the future to ask
                    // the user which one to connect to...
                    verificationHelper!!.connect(connectionMethods.first())
                }
                phase.value = Phase.WAITING_FOR_CONNECTION
            }

            override fun onMoveIntoNfcField() {
                // TODO
            }

            override fun onDeviceConnected() {
                sendRequest()
            }

            override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
                Logger.i(TAG, "onDeviceDisconnected transportSpecificTermination=$transportSpecificTermination")
            }

            override fun onResponseReceived(deviceResponseBytes: ByteArray) {
                Logger.i(TAG, "onResponseReceived")
                try {
                    reportResponse(
                        processResponse(
                            deviceResponseBytes,
                            trustManager,
                            activity.resources
                        )
                    )
                } catch (e: Throwable) {
                    reportError(e)
                }
            }

            override fun onError(e: Throwable) {
                Logger.i(TAG, "onError", e)
                reportError(e)
            }
        }

        verificationHelper = VerificationHelper.Builder(context, listener, context.mainExecutor)
            .setDataTransportOptions(dataTransportOptions)
            .setNegotiatedHandoverConnectionMethods(connectionMethods)
            .build()
        activityForNfcReaderMode = activity
        if (nfcAdapter != null) {
            nfcAdapter.enableReaderMode(
                activityForNfcReaderMode, nfcReaderModeListener,
                NfcAdapter.FLAG_READER_NFC_A + NfcAdapter.FLAG_READER_NFC_B
                        + NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK + NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                null
            )
            Logger.i(TAG, "Enabling reader mode on NfcAdapter")
        } else {
            Logger.i(TAG, "NfcAdapter not available")
        }
        phase.value = Phase.WAITING_FOR_ENGAGEMENT
    }

    private fun sendRequest() {
        val mdocRequest = requestToUse!!.mdocRequest!!

        val namespacesToRequest = mutableMapOf<String, Map<String, Boolean>>()
        for (ns in mdocRequest.namespacesToRequest) {
            val dataElementsToRequest = mutableMapOf<String, Boolean>()
            for ((de, intentToRetain) in ns.dataElementsToRequest) {
                dataElementsToRequest[de.attribute.identifier] = intentToRetain
            }
            namespacesToRequest[ns.namespace] = dataElementsToRequest
        }

        // TODO: add reader auth
        val deviceRequestGenerator = DeviceRequestGenerator(verificationHelper!!.sessionTranscript)
            .addDocumentRequest(
                mdocRequest.docType,
                namespacesToRequest,
                null,
                null,
                Algorithm.UNSET,
                null
            )
        verificationHelper!!.sendRequest(deviceRequestGenerator.generate())
        phase.value = Phase.WAITING_FOR_RESPONSE
    }

    private fun processResponse(
        deviceResponseBytes: ByteArray,
        trustManager: TrustManager,
        res: Resources
    ): ReaderResponse {
        val parser = DeviceResponseParser(deviceResponseBytes, verificationHelper!!.sessionTranscript)
        val deviceResponse = parser.parse()

        val readerDocuments = mutableListOf<ReaderDocument>()
        for (document in deviceResponse.documents) {
            val infoTexts = mutableListOf<String>()
            val warningTexts = mutableListOf<String>()

            if (document.issuerSignedAuthenticated) {
                val trustResult = trustManager.verify(
                    document.issuerCertificateChain.certificates,
                )
                if (trustResult.isTrusted) {
                    val trustPoint = trustResult.trustPoints[0]
                    val displayName = trustPoint.displayName
                        ?: trustPoint.certificate.javaX509Certificate.subjectX500Principal.name
                    infoTexts.add(res.getString(R.string.reader_model_info_in_trust_list, displayName))
                } else {
                    val dsCert = document.issuerCertificateChain.certificates[0]
                    val displayName = dsCert.issuer.name
                    warningTexts.add(res.getString(R.string.reader_model_warning_not_in_trust_list, displayName))
                }
            }
            if (!document.deviceSignedAuthenticated) {
                warningTexts.add(res.getString(R.string.reader_model_warning_device_auth))
            }
            if (!document.issuerSignedAuthenticated) {
                warningTexts.add(res.getString(R.string.reader_model_warning_issuer_auth))
            }
            if (document.numIssuerEntryDigestMatchFailures > 0) {
                warningTexts.add(res.getString(R.string.reader_model_warning_data_elem_auth))
            }
            val now = Clock.System.now()
            if (now < document.validityInfoValidFrom || now > document.validityInfoValidUntil) {
                warningTexts.add(res.getString(R.string.reader_model_warning_validity_period))
            }

            val mdocType = documentTypeRepository.getDocumentTypeForMdoc(document.docType)?.mdocDocumentType
            val resultNs = mutableListOf<ReaderNamespace>()
            for (namespace in document.issuerNamespaces) {
                val resultDataElements = mutableMapOf<String, ReaderDataElement>()

                val mdocNamespace = if (mdocType !=null) {
                    mdocType.namespaces.get(namespace)
                } else {
                    // Some DocTypes not known by [documentTypeRepository] - could be they are
                    // private or was just never added - may use namespaces from existing
                    // DocTypes... support that as well.
                    //
                    documentTypeRepository.getDocumentTypeForMdocNamespace(namespace)
                        ?.mdocDocumentType?.namespaces?.get(namespace)
                }

                for (dataElement in document.getIssuerEntryNames(namespace)) {
                    val value = document.getIssuerEntryData(namespace, dataElement)
                    val cborValue = Cbor.decode(value)
                    val mdocDataElement = mdocNamespace?.dataElements?.get(dataElement)
                    val bitmap = if (cborValue is Bstr &&
                        mdocDataElement?.attribute?.type == DocumentAttributeType.Picture) {
                        val bitmapData = cborValue.asBstr
                        val options = BitmapFactory.Options()
                        options.inMutable = true
                        BitmapFactory.decodeByteArray(
                            bitmapData,
                            0,
                            bitmapData.size,
                            options
                        )
                    } else {
                        null
                    }
                    resultDataElements[dataElement] = ReaderDataElement(
                        mdocDataElement,
                        value,
                        bitmap
                    )
                }
                resultNs.add(ReaderNamespace(namespace, resultDataElements))
            }
            readerDocuments.add(
                ReaderDocument(
                    document.docType,
                    document.validityInfoValidFrom,
                    document.validityInfoValidUntil,
                    document.validityInfoSigned,
                    document.validityInfoExpectedUpdate,
                    resultNs,
                    infoTexts,
                    warningTexts
                )
            )
        }
        return ReaderResponse(readerDocuments)
    }

}