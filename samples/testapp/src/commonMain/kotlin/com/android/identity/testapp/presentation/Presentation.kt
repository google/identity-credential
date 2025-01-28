package com.android.identity.testapp.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.appsupport.ui.consent.ConsentModalBottomSheet
import com.android.identity.appsupport.ui.consent.ConsentRelyingParty
import com.android.identity.appsupport.ui.consent.MdocConsentField
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.Tagged
import com.android.identity.crypto.Algorithm
import com.android.identity.document.Document
import com.android.identity.document.DocumentStore
import com.android.identity.document.NameSpacedData
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.sessionencryption.SessionEncryption
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.mdoc.transport.MdocTransportClosedException
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.jetbrains.compose.resources.ExperimentalResourceApi

private const val TAG = "Presentation"

private data class ConsentSheetData(
    val showConsentPrompt: Boolean,
    val continuation:  CancellableContinuation<Boolean>,
    val document: ConsentDocument,
    val consentFields: List<MdocConsentField>,
    val relyingParty: ConsentRelyingParty,
)

/**
 * A composable used for credential presentations.
 *
 * The [allowMultipleRequests] parameter is only meaningful if the [PresentationMechanism] allows for multiple
 * requests, not all do.
 *
 * @param documentStore a [DocumentStore] used to find credentials to present.
 * @param documentTypeRepository a [DocumentTypeRepository] used to find metadata about documents being requested.
 * @param readerTrustManager a [TrustManager] used to find trust points for the credential requester.
 * @param allowMultipleRequests whether the connection should be closed after sending the first resppnse.
 * @param showToast a function to show a message.
 * @param onPresentationComplete called when the presentation is complete.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Presentation(
    documentStore: DocumentStore,
    documentTypeRepository: DocumentTypeRepository,
    readerTrustManager: TrustManager,
    allowMultipleRequests: Boolean,
    showToast: (message: String) -> Unit,
    onPresentationComplete: () -> Unit,
) {
    val presentationModel = PresentationModel.getInstance()

    Logger.i(TAG, "entering")
    val coroutineScope = rememberCoroutineScope()

    val consentSheetData = remember { mutableStateOf<ConsentSheetData?>(null)}

    // Make sure we clean up the PresentationModel when we're done. This is to ensure
    // we're closing all open connections to prevent resource leakage.
    DisposableEffect(presentationModel) {
        onDispose {
            Logger.i(TAG, "onDispose")
            presentationModel.reset()
        }
    }

    if (consentSheetData.value != null && consentSheetData.value!!.showConsentPrompt) {
        // TODO: use sheetGesturesEnabled=false when available - see
        //  https://issuetracker.google.com/issues/288211587 for details
        val sheetState = rememberModalBottomSheetState(
            skipPartiallyExpanded = true
        )
        ConsentModalBottomSheet(
            sheetState = sheetState,
            consentFields = consentSheetData.value!!.consentFields,
            document = consentSheetData.value!!.document,
            relyingParty = consentSheetData.value!!.relyingParty,
            onConfirm = {
                coroutineScope.launch {
                    sheetState.hide()
                    consentSheetData.value!!.continuation.resume(true, null)
                    consentSheetData.value = null
                }
            },
            onCancel = {
                coroutineScope.launch {
                    sheetState.hide()
                    consentSheetData.value!!.continuation.resume(false, null)
                    consentSheetData.value = null
                }
            }
        )
    }

    val mdocPresentationMechanism = presentationModel.mechanism as? MdocPresentationMechanism
    when (presentationModel.state.collectAsState().value) {
        PresentationModel.State.IDLE -> {
            Logger.i(TAG, "IDLE")
        }
        PresentationModel.State.WAITING -> {
            Logger.i(TAG, "WAITING")
        }
        PresentationModel.State.RUNNING -> {
            Logger.i(TAG, "RUNNING")
            if (mdocPresentationMechanism != null) {
                LaunchedEffect(presentationModel) {
                    Logger.i(TAG, "Running mdoc presentation flow")
                    runMdocPresentationFlow(
                        documentStore = documentStore,
                        documentTypeRepository = documentTypeRepository,
                        readerTrustManager = readerTrustManager,
                        presentationModel = presentationModel,
                        mdocPresentationMechanism = mdocPresentationMechanism,
                        allowMultipleRequests = allowMultipleRequests,
                        consentSheetData = consentSheetData,
                        showToast = showToast,
                    )
                }
            }
        }
        PresentationModel.State.COMPLETED -> {
            Logger.i(TAG, "COMPLETED")
            onPresentationComplete()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        if (mdocPresentationMechanism != null) {
            Text(
                text = "Connection State: ${mdocPresentationMechanism.transport.state.value}",
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Bold,
            )
        }
        if (!allowMultipleRequests) {
            Spacer(modifier = Modifier.height(10.dp))
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.SpaceEvenly,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Button(
                    onClick = {
                        coroutineScope.launch {
                            if (mdocPresentationMechanism != null) {
                                try {
                                    mdocPresentationMechanism.transport.sendMessage(
                                        SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION)
                                    )
                                    mdocPresentationMechanism.transport.close()
                                } catch (error: Throwable) {
                                    Logger.e(TAG, "Caught exception", error)
                                    error.printStackTrace()
                                    showToast("Error: ${error.message}")
                                }
                            }
                        }
                    }
                ) {
                    Text("Close (Message)")
                }
                Button(
                    onClick = {
                        coroutineScope.launch {
                            if (mdocPresentationMechanism != null) {
                                try {
                                    mdocPresentationMechanism.transport.sendMessage(byteArrayOf())
                                    mdocPresentationMechanism.transport.close()
                                } catch (error: Throwable) {
                                    Logger.e(TAG, "Caught exception", error)
                                    error.printStackTrace()
                                    showToast("Error: ${error.message}")
                                }
                            }
                        }
                    }
                ) {
                    Text("Close (Transport-Specific)")
                }
                Button(
                    onClick = {
                        if (mdocPresentationMechanism != null) {
                            try {
                                coroutineScope.launch {
                                    mdocPresentationMechanism.transport.close()
                                }
                            } catch (error: Throwable) {
                                Logger.e(TAG, "Caught exception", error)
                                error.printStackTrace()
                                showToast("Error: ${error.message}")
                            }
                        }
                    }
                ) {
                    Text("Close (None)")
                }
            }
        }
    }
}

private suspend fun runMdocPresentationFlow(
    documentStore: DocumentStore,
    documentTypeRepository: DocumentTypeRepository,
    readerTrustManager: TrustManager,
    presentationModel: PresentationModel,
    mdocPresentationMechanism: MdocPresentationMechanism,
    allowMultipleRequests: Boolean,
    consentSheetData: MutableState<ConsentSheetData?>,
    showToast: (message: String) -> Unit,
) {
    val transport = mdocPresentationMechanism.transport

    // Wait until state changes to CONNECTED, FAILED, or CLOSED
    transport.state.first {
        it == MdocTransport.State.CONNECTED ||
                it == MdocTransport.State.FAILED ||
                it == MdocTransport.State.CLOSED
    }
    if (transport.state.value != MdocTransport.State.CONNECTED) {
        presentationModel.setCompleted(Error("Expected state CONNECTED but found ${transport.state.value}"))
        return
    }

    try {
        var sessionEncryption: SessionEncryption? = null
        var encodedSessionTranscript: ByteArray? = null
        while (true) {
            Logger.i(TAG, "Waiting for message from reader...")
            val sessionData = transport.waitForMessage()
            if (sessionData.isEmpty()) {
                showToast("Received transport-specific session termination message from reader")
                presentationModel.setCompleted()
                break
            }

            if (sessionEncryption == null) {
                val eReaderKey = SessionEncryption.getEReaderKey(sessionData)
                encodedSessionTranscript =
                    Cbor.encode(
                        CborArray.builder()
                            .add(Tagged(24, Bstr(mdocPresentationMechanism.encodedDeviceEngagement.toByteArray())))
                            .add(Tagged(24, Bstr(Cbor.encode(eReaderKey.toCoseKey().toDataItem()))))
                            .add(mdocPresentationMechanism.handover)
                            .end()
                            .build()
                    )
                sessionEncryption = SessionEncryption(
                    SessionEncryption.Role.MDOC,
                    mdocPresentationMechanism.eDeviceKey,
                    eReaderKey,
                    encodedSessionTranscript,
                )
            }
            val (encodedDeviceRequest, status) = sessionEncryption.decryptMessage(sessionData)

            if (status == Constants.SESSION_DATA_STATUS_SESSION_TERMINATION) {
                showToast("Received session termination message from reader")
                presentationModel.setCompleted()
                break
            }

            val deviceResponseGenerator = DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)

            val deviceRequest = DeviceRequestParser(
                encodedDeviceRequest!!,
                encodedSessionTranscript!!,
            ).parse()
            for (docRequest in deviceRequest.docRequests) {
                val documentAndCredential = mdocFindDocumentForRequest(
                    documentStore = documentStore,
                    docRequest = docRequest,
                )
                if (documentAndCredential == null) {
                    Logger.w(TAG, "No credential found for docType ${docRequest.docType}")
                    // No credential was found
                    continue
                }
                val consentFields = showConsentPrompt(
                    document = documentAndCredential.first,
                    credential = documentAndCredential.second,
                    docRequest = docRequest,
                    documentTypeRepository = documentTypeRepository,
                    consentSheetData = consentSheetData,
                    readerTrustManager = readerTrustManager
                )
                if (consentFields == null) {
                    // User did not consent
                    continue
                }
                deviceResponseGenerator.addDocument(calcDocument(
                    document = documentAndCredential.first,
                    credential = documentAndCredential.second,
                    consentFields = consentFields,
                    encodedSessionTranscript = encodedSessionTranscript,
                ))
            }

            val encodedDeviceResponse = deviceResponseGenerator.generate()
            transport.sendMessage(
                sessionEncryption.encryptMessage(
                    encodedDeviceResponse,
                    if (!allowMultipleRequests) {
                        Constants.SESSION_DATA_STATUS_SESSION_TERMINATION
                    } else {
                        null
                    }
                )
            )
            if (!allowMultipleRequests) {
                showToast("Response sent, closing connection")
                presentationModel.setCompleted()
                break
            } else {
                showToast("Response sent, keeping connection open")
            }
        }
    } catch (_: MdocTransportClosedException) {
        // Nothing to do, this is thrown when transport.close() is called from another coroutine, that
        // is, the onClick handlers for the close buttons.
        Logger.i(TAG, "Ending holderJob due to MdocTransportClosedException")
        presentationModel.setCompleted()
    } catch (error: Throwable) {
        Logger.e(TAG, "Caught exception", error)
        error.printStackTrace()
        showToast("Error: ${error.message}")
        presentationModel.setCompleted(error)
    }
}

private suspend fun mdocFindDocumentForRequest(
    documentStore: DocumentStore,
    docRequest: DeviceRequestParser.DocRequest,
    now: Instant = Clock.System.now()
): Pair<Document, MdocCredential>? {
    // For now we just pick the first valid credential we find..
    //
    // TODO:
    //  - also look at usage count and for a document, return the credential with the lowest use count
    //  - if multiple mdocs with the given doctype are available, prompt the user for which one to return
    //
    for (documentName in documentStore.listDocuments()) {
        val document = documentStore.lookupDocument(documentName) ?: continue
        for (credential in document.certifiedCredentials) {
            if (credential is MdocCredential &&
                credential.docType == docRequest.docType &&
                !credential.isInvalidated() &&
                now >= credential.validFrom && now <= credential.validUntil) {
                return Pair(document, credential)
            }
        }
    }
    return null
}

// Returns consent-fields if confirmed by the user, false otherwise.
//
@OptIn(ExperimentalResourceApi::class)
private suspend fun showConsentPrompt(
    document: Document,
    credential: MdocCredential,
    docRequest: DeviceRequestParser.DocRequest,
    documentTypeRepository: DocumentTypeRepository,
    consentSheetData: MutableState<ConsentSheetData?>,
    readerTrustManager: TrustManager,
): List<MdocConsentField>? {
    Logger.i(TAG, "docRequest.readerAuthenticated=${docRequest.readerAuthenticated}")
    val trustPoint = if (docRequest.readerAuthenticated) {
        val trustResult = readerTrustManager.verify(docRequest.readerCertificateChain!!.certificates)
        Logger.i(TAG, "trustResult.isTrusted=${trustResult.isTrusted}")
        Logger.i(TAG, "trustResult.error=${trustResult.error}")
        if (trustResult.isTrusted) {
            trustResult.trustPoints[0]
        } else {
            null
        }
    } else {
        null
    }
    val cardArt = document.applicationData.getData("cardArt")
    val consentFields = MdocConsentField.generateConsentFields(
        docRequest,
        documentTypeRepository,
        credential
    )
    if (suspendCancellableCoroutine { continuation ->
            consentSheetData.value = ConsentSheetData(
                showConsentPrompt = true,
                continuation = continuation,
                document = ConsentDocument(
                    name = "Erika's Driving License",
                    cardArt = cardArt,
                    description = "Driving License",
                ),
                consentFields = consentFields,
                relyingParty = ConsentRelyingParty(
                    trustPoint = trustPoint,
                    websiteOrigin = null,
                )
            )
        }) {
        return consentFields
    } else {
        return null
    }
}

private suspend fun calcDocument(
    document: Document,
    credential: MdocCredential,
    consentFields: List<MdocConsentField>,
    encodedSessionTranscript: ByteArray
): ByteArray {
    val nsAndDataElements = mutableMapOf<String, MutableList<String>>()
    consentFields.forEach {
        nsAndDataElements.getOrPut(it.namespaceName, { mutableListOf() }).add(it.dataElementName)
    }

    val staticAuthData = StaticAuthDataParser(credential.issuerProvidedData).parse()

    val documentData = document.applicationData.getNameSpacedData("documentData")
    val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
        nsAndDataElements,
        documentData,
        staticAuthData
    )
    val issuerAuthCoseSign1 = Cbor.decode(staticAuthData.issuerAuth).asCoseSign1
    val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
    val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)
    val mso = MobileSecurityObjectParser(encodedMso).parse()

    val documentGenerator = DocumentGenerator(
        mso.docType,
        staticAuthData.issuerAuth,
        encodedSessionTranscript,
    )
    documentGenerator.setIssuerNamespaces(mergedIssuerNamespaces)

    documentGenerator.setDeviceNamespacesSignature(
        NameSpacedData.Builder().build(),
        credential.secureArea,
        credential.alias,
        null,
        Algorithm.ES256,
    )
    return documentGenerator.generate()
}
