package com.android.identity_credential.wallet

import android.content.Context
import android.graphics.BitmapFactory
import androidx.compose.runtime.mutableStateListOf
import androidx.fragment.app.FragmentActivity
import com.android.identity.android.direct_access.DirectAccess
import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.securearea.SecureArea
import com.android.identity.android.securearea.AndroidKeystoreCreateKeySettings
import com.android.identity.android.securearea.AndroidKeystoreKeyInfo
import com.android.identity.android.securearea.AndroidKeystoreKeyUnlockData
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.securearea.cloud.CloudCreateKeySettings
import com.android.identity.android.securearea.cloud.CloudKeyInfo
import com.android.identity.android.securearea.cloud.CloudSecureArea
import com.android.identity.android.securearea.UserAuthenticationType
import com.android.identity.android.securearea.cloud.CloudKeyLockedException
import com.android.identity.android.securearea.cloud.CloudKeyUnlockData
import com.android.identity.cbor.Cbor
import com.android.identity.credential.Credential
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.EcCurve
import com.android.identity.device.AssertionBindingKeys
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.document.Document
import com.android.identity.document.DocumentAdded
import com.android.identity.document.DocumentDeleted
import com.android.identity.document.DocumentStore
import com.android.identity.document.DocumentUpdated
import com.android.identity.document.DocumentUtil
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.issuance.DocumentCondition
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.issuance.DocumentExtensions.documentIdentifier
import com.android.identity.issuance.DocumentExtensions.issuingAuthorityIdentifier
import com.android.identity.issuance.DocumentExtensions.numDocumentConfigurationsDownloaded
import com.android.identity.issuance.DocumentExtensions.state
import com.android.identity.issuance.CredentialFormat
import com.android.identity.issuance.CredentialRequest
import com.android.identity.issuance.DocumentExtensions.documentSlot
import com.android.identity.issuance.DocumentExtensions.issuingAuthorityConfiguration
import com.android.identity.issuance.DocumentExtensions.walletDocumentMetadata
import com.android.identity.issuance.IssuingAuthority
import com.android.identity.issuance.IssuingAuthorityException
import com.android.identity.issuance.KeyPossessionProof
import com.android.identity.securearea.config.SecureAreaConfigurationAndroidKeystore
import com.android.identity.securearea.config.SecureAreaConfigurationCloud
import com.android.identity.securearea.config.SecureAreaConfigurationSoftware
import com.android.identity.issuance.remote.WalletServerProvider
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.sdjwt.SdJwtVerifiableCredential
import com.android.identity.sdjwt.credential.KeyBoundSdJwtVcCredential
import com.android.identity.sdjwt.credential.KeylessSdJwtVcCredential
import com.android.identity.sdjwt.vc.JwtBody
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyInvalidatedException
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.securearea.software.SoftwareCreateKeySettings
import com.android.identity.securearea.software.SoftwareKeyInfo
import com.android.identity.securearea.software.SoftwareKeyUnlockData
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.credman.CredmanRegistry
import com.android.identity_credential.wallet.logging.EventLogger
import com.android.identity_credential.wallet.logging.MdocPresentationEvent
import com.android.identity_credential.wallet.presentation.UserCanceledPromptException
import com.android.identity_credential.wallet.ui.destination.document.formatDate
import com.android.identity_credential.wallet.ui.prompt.biometric.showBiometricPrompt
import com.android.identity_credential.wallet.ui.prompt.passphrase.showPassphrasePrompt
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.sample
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class DocumentModel(
    private val context: Context,
    private val settingsModel: SettingsModel,
    private val documentStore: DocumentStore,
    private val secureAreaRepository: SecureAreaRepository,
    private val documentTypeRepository: DocumentTypeRepository,
    private val walletServerProvider: WalletServerProvider,
    private val walletApplication: WalletApplication
) {
    companion object {
        private const val TAG = "DocumentModel"
    }

    val documentInfos = mutableStateListOf<DocumentInfo>()
    var activity: FragmentActivity? = null
    private var updateJob: Job? = null

    fun getDocumentInfo(cardId: String): DocumentInfo? {
        for (card in documentInfos) {
            if (card.documentId == cardId) {
                return card
            }
        }
        return null
    }

    fun getCardIndex(cardId: String): Int? {
        for (n in documentInfos.indices) {
            if (documentInfos[n].documentId == cardId) {
                return n
            }
        }
        return null
    }

    /**
     * Refreshes a card.
     *
     * This may throw e.g. [ScreenLockRequiredException] if for example the document
     * is set up to use auth-backed Android Keystore keys but the device has no LSKF. So
     * the caller should always try and catch exceptions.
     *
     * @param documentInfo the card to refresh
     * @throws Exception if an error occurs
     */
    suspend fun refreshCard(documentInfo: DocumentInfo) {
        val document = documentStore.lookupDocument(documentInfo.documentId)
        if (document == null) {
            Logger.w(TAG, "No document with id ${documentInfo.documentId}")
            return
        }
        syncDocumentWithIssuer(document)
    }

    suspend fun developerModeRequestUpdate(
        documentInfo: DocumentInfo,
        requestRemoteDeletion: Boolean,
        notifyApplicationOfUpdate: Boolean
    ) {
        val document = documentStore.lookupDocument(documentInfo.documentId)
        if (document == null) {
            Logger.w(TAG, "No document with id ${documentInfo.documentId}")
            return
        }
        val issuer = walletServerProvider.getIssuingAuthority(document.issuingAuthorityIdentifier)
        issuer.developerModeRequestUpdate(
            document.documentIdentifier,
            requestRemoteDeletion,
            notifyApplicationOfUpdate
        )
    }

    suspend fun deleteCard(documentInfo: DocumentInfo) {
        val document = documentStore.lookupDocument(documentInfo.documentId)
        if (document == null) {
            Logger.w(TAG, "No document with id ${documentInfo.documentId}")
        } else {
            documentStore.deleteDocument(document.identifier)
        }
    }

    fun attachToActivity(activity: FragmentActivity) {
        this.activity = activity
    }

    fun detachFromActivity(activity: FragmentActivity) {
        if (activity == this.activity) {
            this.activity = null
        }
    }

    private fun getStr(getStrId: Int): String {
        return context.resources.getString(getStrId)
    }

    suspend fun getEventInfos(documentId: String): List<EventInfo> {
        val eventLogger = walletApplication.eventLogger
        val events = eventLogger.getEntries(documentId)

        return events.map { event ->
            when (event) {
                is MdocPresentationEvent -> {
                    val parser = DeviceRequestParser(event.deviceRequestCbor, event.deviceResponseCbor)
                    val deviceRequest = parser.parse()
                    val targetNamespaces = setOf("eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1")
                    val requestedFields = deviceRequest.docRequests.flatMap { docRequest ->
                        targetNamespaces.flatMap { namespace ->
                            if (docRequest.namespaces.contains(namespace)) {
                                docRequest.getEntryNames(namespace)
                            } else {
                                emptyList()
                            }
                        }
                    }.joinToString(", ")

                    // Format timestamp and other UI-friendly data
                    EventInfo(
                        timestamp = formatDate(event.timestamp),
                        requesterInfo = event.requesterInfo,
                        requestedFields = requestedFields,
                    )
                }
                else -> {
                    EventInfo(
                        timestamp = formatDate(event.timestamp),
                        requesterInfo = EventLogger.RequesterInfo(EventLogger.Requester.Anonymous(), EventLogger.ShareType.UNKNOWN),
                        requestedFields = "Unknown event type"
                    )
                }
            }
        }
    }

    suspend fun deleteEventInfos(documentId: String) {
        val eventLogger = walletApplication.eventLogger
        eventLogger.deleteEntriesForDocument(documentId)
    }

    private suspend fun createCardForDocument(document: Document): DocumentInfo? {
        /*
        // TODO: we may want to do this in future:
        if (!document.walletDocumentMetadata.provisioned) {
            return null
        }
        */
        val documentConfiguration = document.documentConfiguration
        val options = BitmapFactory.Options()
        options.inMutable = true
        val documentBitmap = BitmapFactory.decodeByteArray(
            documentConfiguration.cardArt,
            0,
            documentConfiguration.cardArt.size,
            options
        )

        val issuerConfiguration = document.issuingAuthorityConfiguration
        val issuerLogo = BitmapFactory.decodeByteArray(
            issuerConfiguration.issuingAuthorityLogo,
            0,
            issuerConfiguration.issuingAuthorityLogo.size,
            options
        )

        val data = document.renderDocumentDetails(context, documentTypeRepository)

        val keyInfos = mutableStateListOf<CredentialInfo>()
        for (credential in document.getCertifiedCredentials()) {
            when (credential) {
                is MdocCredential -> {
                    keyInfos.add(createCardInfoForMdocCredential(credential))
                }
                is KeyBoundSdJwtVcCredential -> {
                    keyInfos.add(createCardInfoForSdJwtVcCredential(credential))
                }
                is KeylessSdJwtVcCredential -> {
                    keyInfos.add(createCardInfoForSdJwtVcCredential(credential))
                }
                is DirectAccessCredential -> {
                    keyInfos.add(createCardInfoForMdocCredential(credential))
                }
                else -> {
                    Logger.w(TAG, "No CardInfo support for ${credential::class}")
                }
            }
        }

        var attentionNeeded = false
        val statusString = when (document.state!!.condition) {
            DocumentCondition.NO_SUCH_DOCUMENT -> getStr(R.string.document_model_status_no_such_document)
            DocumentCondition.PROOFING_REQUIRED -> getStr(R.string.document_model_status_proofing_required)
            DocumentCondition.PROOFING_PROCESSING -> getStr(R.string.document_model_status_proofing_processing)
            DocumentCondition.PROOFING_FAILED -> getStr(R.string.document_model_status_proofing_failed)
            DocumentCondition.CONFIGURATION_AVAILABLE -> {
                attentionNeeded = true
                getStr(R.string.document_model_status_configuration_available)
            }

            DocumentCondition.READY -> {
                // TODO: hmm, this can become stale as time progresses... maybe we need
                //  a timer to refresh the model to reflect this.
                val usableCredentials = document.countUsableCredentials(Clock.System.now())
                if (usableCredentials.numCredentials == 0) {
                    attentionNeeded = true
                    getStr(R.string.document_model_status_no_usable_credential)
                } else {
                    getStr(R.string.document_model_status_ready)
                }
            }

            DocumentCondition.DELETION_REQUESTED -> {
                attentionNeeded = true
                getStr(R.string.document_model_status_deletion_requested)
            }
        }

        return DocumentInfo(
            documentId = document.identifier,
            attentionNeeded = attentionNeeded,
            requireUserAuthenticationToViewDocument = documentConfiguration.requireUserAuthenticationToViewDocument,
            name = documentConfiguration.displayName,
            issuerName = issuerConfiguration.issuingAuthorityName,
            issuerDocumentDescription = issuerConfiguration.issuingAuthorityDescription,
            typeName = documentConfiguration.typeDisplayName,
            issuerLogo = issuerLogo,
            documentArtwork = documentBitmap,
            lastRefresh = document.state!!.timestamp,
            status = statusString,
            attributes = data.attributes,
            credentialInfos = keyInfos,
        )
    }

    private suspend fun addSecureAreaBoundCredentialInfo(
        credential: SecureAreaBoundCredential,
        kvPairs: MutableMap<String, String>
    ) {
        // TODO: set up translations via strings.xml
        try {
            val deviceKeyInfo = credential.secureArea.getKeyInfo(credential.alias)
            kvPairs.put("Device Key Curve", deviceKeyInfo.publicKey.curve.humanReadableName)
            kvPairs.put("Device Key Purposes", renderKeyPurposes(deviceKeyInfo.keyPurposes))
            kvPairs.put("Secure Area", credential.secureArea.displayName)

            if (deviceKeyInfo is AndroidKeystoreKeyInfo) {
                val userAuthString =
                    if (!deviceKeyInfo.isUserAuthenticationRequired) {
                        "None"
                    } else {
                        val authTimeoutString =
                            if (deviceKeyInfo.userAuthenticationTimeoutMillis > 0) {
                                String.format(
                                    "Timeout %.1f Seconds",
                                    deviceKeyInfo.userAuthenticationTimeoutMillis / 1000
                                )
                            } else {
                                "Every use"
                            }
                        renderUserAuthenticationTypes(deviceKeyInfo.userAuthenticationTypes) +
                                " ($authTimeoutString)"
                    }
                kvPairs.put("User Authentication", userAuthString)
                val isStrongBoxBacked =
                    if (deviceKeyInfo.isStrongBoxBacked) {
                        "Yes"
                    } else {
                        "No"
                    }
                kvPairs.put("In StrongBox", isStrongBoxBacked)
            } else if (deviceKeyInfo is CloudKeyInfo) {
                kvPairs.put("Cloud Secure Area URL", (credential.secureArea as CloudSecureArea).serverUrl)
                val userAuthString =
                    if (!deviceKeyInfo.isUserAuthenticationRequired) {
                        "None"
                    } else {
                        val authTimeoutString =
                            if (deviceKeyInfo.userAuthenticationTimeoutMillis > 0) {
                                String.format(
                                    "Timeout %.1f Seconds",
                                    deviceKeyInfo.userAuthenticationTimeoutMillis / 1000
                                )
                            } else {
                                "Every use"
                            }
                        renderUserAuthenticationTypes(deviceKeyInfo.userAuthenticationTypes) +
                                " ($authTimeoutString)"
                    }
                kvPairs.put("User Authentication", userAuthString)
                val isPassphraseRequired =
                    if (deviceKeyInfo.isPassphraseRequired) {
                        "Yes"
                    } else {
                        "No"
                    }
                kvPairs.put("Passphrase Required", isPassphraseRequired)
            } else if (deviceKeyInfo is SoftwareKeyInfo) {
                val passphraseProtected =
                    if (deviceKeyInfo.isPassphraseProtected) {
                        val constraints = deviceKeyInfo.passphraseConstraints
                        if (constraints == null) {
                            "Yes"
                        } else {
                            if (constraints.requireNumerical) {
                                if (constraints.maxLength == Int.MAX_VALUE) {
                                    "Numerical, at least ${constraints.minLength} digits"
                                } else if (constraints.minLength == constraints.maxLength) {
                                    "Numerical, ${constraints.minLength} digits"
                                } else {
                                    "Numerical, ${constraints.minLength}-${constraints.maxLength} digits"
                                }
                            } else {
                                if (constraints.maxLength == Int.MAX_VALUE) {
                                    "At least ${constraints.minLength} characters"
                                } else if (constraints.minLength == constraints.maxLength) {
                                    "${constraints.minLength} characters"
                                } else {
                                    "${constraints.minLength}-${constraints.maxLength} characters"
                                }
                            }
                        }
                    } else {
                        "None"
                    }
                kvPairs.put("Passphrase", passphraseProtected)
            }
        } catch (e: KeyInvalidatedException) {
            kvPairs.put("Device Key", "Invalidated")
        }
    }

    private suspend fun createCardInfoForMdocCredential(mdocCredential: Credential): CredentialInfo {
        assert(((mdocCredential is MdocCredential) or (mdocCredential is DirectAccessCredential))
        ) { "Credential must be either MdocCredential or DirectAccessCredential" }

        val credentialData = StaticAuthDataParser(mdocCredential.issuerProvidedData).parse()
        val issuerAuthCoseSign1 = Cbor.decode(credentialData.issuerAuth).asCoseSign1
        val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
        val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)
        val mso = MobileSecurityObjectParser(encodedMso).parse()


        val kvPairs = mutableMapOf<String, String>()
        kvPairs.put("Document Type", mso.docType)
        kvPairs.put("MSO Version", mso.version)
        kvPairs.put("Issuer Data Digest Algorithm", mso.digestAlgorithm)

        if (mdocCredential is MdocCredential) {
            addSecureAreaBoundCredentialInfo(mdocCredential, kvPairs)
        }

        kvPairs.put("Issuer Provided Data", "${mdocCredential.issuerProvidedData.size} bytes")

        val replacement =
            mdocCredential.document.getReplacementCredentialFor(mdocCredential.identifier)

        return CredentialInfo(
            format = CredentialFormat.MDOC_MSO,
            description = "ISO/IEC 18013-5:2021 mdoc MSO",
            usageCount = mdocCredential.usageCount,
            signedAt = mso.signed,
            validFrom = mso.validFrom,
            validUntil = mso.validUntil,
            expectedUpdate = mso.expectedUpdate,
            replacementPending = replacement != null,
            details = kvPairs
        )
    }

    private suspend fun createCardInfoForSdJwtVcCredential(sdJwtVcCredential: Credential): CredentialInfo {

        val kvPairs = mutableMapOf<String, String>()

        val sdJwt = SdJwtVerifiableCredential.fromString(
            String(sdJwtVcCredential.issuerProvidedData, Charsets.US_ASCII)
        )
        val body = JwtBody.fromString(sdJwt.body)

        kvPairs.put("Issuer", body.issuer)
        kvPairs.put("Document Type", body.docType)
        kvPairs.put("Digest Hash Algorithm", body.sdHashAlg.toString())

        if (sdJwtVcCredential is SecureAreaBoundCredential) {
            addSecureAreaBoundCredentialInfo(sdJwtVcCredential, kvPairs)
        } else {
            kvPairs.put("Keyless", "true")
        }

        kvPairs.put("Issuer Provided Data", "${sdJwtVcCredential.issuerProvidedData.size} bytes")

        val replacement =
            sdJwtVcCredential.document.getReplacementCredentialFor(sdJwtVcCredential.identifier)

        return CredentialInfo(
            format = CredentialFormat.SD_JWT_VC,
            description = "IETF SD-JWT Verifiable Credential",
            usageCount = sdJwtVcCredential.usageCount,
            signedAt = body.timeSigned,
            validFrom = body.timeValidityBegin,
            validUntil = body.timeValidityEnd,
            expectedUpdate = null,
            replacementPending = replacement != null,
            details = kvPairs
        )
    }


    private suspend fun addDocument(document: Document) {
        createCardForDocument(document)?.let { documentInfos.add(it) }
    }

    private fun removeDocument(documentId: String) {
        val cardIndex = documentInfos.indexOfFirst { it.documentId == documentId }
        if (cardIndex < 0) {
            Logger.w(TAG, "No card for document with id $documentId")
            return
        }
        documentInfos.removeAt(cardIndex)
    }

    private suspend fun updateDocument(document: Document) {
        val info = createCardForDocument(document)
        val cardIndex = documentInfos.indexOfFirst { it.documentId == document.identifier }
        if (cardIndex >= 0) {
            if (info == null) {
                documentInfos.removeAt(cardIndex)
            } else {
                documentInfos[cardIndex] = info
            }
        } else if (info != null) {
            // metadata was not ready when the document was added, add it now
            documentInfos.add(info)
        }
    }

    private suspend fun updateCredman() {
        CredmanRegistry.registerCredentials(context, documentStore, documentTypeRepository)
    }

    init {
        reset()
        walletServerProvider.addResetListener(this::reset)
    }

    private fun reset() {
        // This keeps our `cards` property in sync with the contents of `documentStore`.
        //
        // Since DOCUMENT_UPDATED is very chatty (an event for every single property
        // change in the Document) we want to coalesce many calls in a short timeframe into
        // timed chunks and process those in batches (at most one per second).
        //
        updateJob?.cancel()
        val batchDuration = 1.seconds
        val batchedUpdateFlow = MutableSharedFlow<String>()
        updateJob = CoroutineScope(Dispatchers.IO).launch {
            val issuingAuthorityIdSet = documentStore.listDocuments().mapNotNull { documentId ->
                documentStore.lookupDocument(documentId)?.issuingAuthorityIdentifier
            }.toMutableSet()
            for (issuingAuthorityId in issuingAuthorityIdSet) {
                startListeningForNotifications(issuingAuthorityId)
            }

            documentStore.eventFlow
                .onEach { event ->
                    Logger.i(TAG, "DocumentStore event ${event::class.simpleName} ${event.documentId}")
                    when (event) {
                        is DocumentAdded -> {
                            val document = documentStore.lookupDocument(event.documentId)
                            // Could have been deleted before the event is handled
                            if (document == null) {
                                Logger.w(TAG, "Document '${event.documentId}' deleted before it could be processed")
                            } else {
                                addDocument(document)
                                val metadata = document.walletDocumentMetadata
                                val issuingAuthorityIdentifier =
                                    metadata.issuingAuthorityIdentifier
                                if (!issuingAuthorityIdSet.contains(issuingAuthorityIdentifier)) {
                                    issuingAuthorityIdSet.add(issuingAuthorityIdentifier)
                                    startListeningForNotifications(issuingAuthorityIdentifier)
                                }
                                updateCredman()
                            }
                        }

                        is DocumentDeleted -> {
                            removeDocument(event.documentId)
                            updateCredman()
                        }

                        is DocumentUpdated -> {
                            // Store the name rather than instance to handle the case that the
                            // document may have been deleted between now and the time it's
                            // processed below...
                            batchedUpdateFlow.emit(event.documentId)
                        }
                    }
                }
                .launchIn(this)

            batchedUpdateFlow.timedChunk(batchDuration)
                .onEach {
                    it.distinct().forEach {
                        documentStore.lookupDocument(it)?.let {
                            Logger.i(TAG, "Processing delayed update event ${it.identifier}")
                            updateDocument(it)
                            updateCredman()
                        }
                    }
                }
                .launchIn(this)
        }

        // If the LSKF is removed, make sure we delete all credentials with invalidated keys...
        //
        settingsModel.screenLockIsSetup.observeForever() {
            Logger.i(
                TAG, "screenLockIsSetup changed to " +
                        "${settingsModel.screenLockIsSetup.value}"
            )
            CoroutineScope(Dispatchers.IO).launch {
                for (documentId in documentStore.listDocuments()) {
                    documentStore.lookupDocument(documentId)?.let { document ->
                        document.deleteInvalidatedCredentials()
                    }
                }
            }
        }

        CoroutineScope(Dispatchers.IO).launch {
            // Initial data population and export to Credman
            //
            for (documentId in documentStore.listDocuments()) {
                documentStore.lookupDocument(documentId)?.let {
                    addDocument(it)
                }
            }
            updateCredman()
        }
    }

    // This processes events from an Issuing Authority which is a stream of events
    // for when an issuer notifies that one of their documents has an update.
    //
    // For every event, we  initiate a sequence of calls into the issuer to get the latest.
    private fun startListeningForNotifications(issuingAuthorityId: String) {
        CoroutineScope(Dispatchers.IO).launch {
            val issuingAuthority = walletServerProvider.getIssuingAuthority(issuingAuthorityId)
            Logger.i(TAG, "collecting notifications for $issuingAuthorityId...")
            issuingAuthority.notifications.collect { notification ->
                Logger.i(
                    TAG,
                    "received notification $issuingAuthorityId.${notification.documentId}"
                )
                // Find the local [Document] instance, if any
                for (id in documentStore.listDocuments()) {
                    val document = documentStore.lookupDocument(id)
                    if (document?.issuingAuthorityIdentifier == issuingAuthorityId &&
                        document.documentIdentifier == notification.documentId
                    ) {
                        Logger.i(TAG, "Handling issuer update on ${notification.documentId}")
                        try {
                            syncDocumentWithIssuer(document)
                        } catch (e: Throwable) {
                            Logger.e(TAG, "Error when syncing with issuer", e)
                            // For example, this can happen if the user removed the LSKF and the
                            // issuer wants auth-bound keys when using Android Keystore. In this
                            // case [ScreenLockRequiredException] is thrown... it can also happen
                            // if e.g. there's intermittent network connectivity.
                            //
                            // There's no point in bubbling this up to the user and since we have
                            // a background service running [syncDocumentWithIssuer] _anyway_
                            // we'll recover at some point.
                            //
                        }
                    }
                }
            }
        }
    }

    /**
     * Called periodically by [WalletApplication.SyncDocumentWithIssuerWorker].
     */
    fun periodicSyncForAllDocuments() {
        CoroutineScope(Dispatchers.IO).launch {
            for (documentId in documentStore.listDocuments()) {
                documentStore.lookupDocument(documentId)?.let { document ->
                    Logger.i(TAG, "Periodic sync for ${document.identifier}")
                    try {
                        syncDocumentWithIssuer(document)
                    } catch (e: Throwable) {
                        Logger.e(TAG, "Error when syncing with issuer", e)
                    }
                }
            }
        }
    }

    /**
     * This performs all the essential bits of housekeeping for a document, including
     * requesting credentials, checking for PII updates, and so on.
     *
     * This will also post notifications to the user for key events, including
     * - when the document has been remote deleted
     * - when the document has been successfully proofed
     * - when there are PII updates
     *
     * The model itself isn't updated.
     *
     * This may throw e.g. [ScreenLockRequiredException] if for example the document
     * is set up to use auth-backed Android Keystore keys but the device has no LSKF. So
     * the caller should always try and catch exceptions.
     *
     * @throws IllegalArgumentException if the issuer isn't known.
     */
    private suspend fun syncDocumentWithIssuer(document: Document) {
        try {
            syncDocumentWithIssuerCore(document)
        } catch (e: IssuingAuthorityException) {
            // IssuingAuthorityException contains human-readable message
            walletApplication.postNotificationForDocument(document, e.message!!)
        }
    }

    private suspend fun syncDocumentWithIssuerCore(document: Document) {
        Logger.i(TAG, "syncDocumentWithIssuer: Refreshing ${document.identifier}")
        val metadata = document.walletDocumentMetadata
        val issuer = walletServerProvider.getIssuingAuthority(document.issuingAuthorityIdentifier)

        // Download latest issuer configuration.
        metadata.setIssuingAuthorityConfiguration(issuer.getConfiguration())

        // OK, let's see what's new...
        metadata.refreshState(walletServerProvider)

        // It's possible the document was remote deleted...
        if (document.state!!.condition == DocumentCondition.NO_SUCH_DOCUMENT) {
            Logger.i(TAG, "syncDocumentWithIssuer: ${document.identifier} was deleted")
            walletApplication.postNotificationForDocument(
                document,
                walletApplication.applicationContext.getString(
                    R.string.notifications_document_deleted_by_issuer
                )
            )
            documentStore.deleteDocument(document.identifier)
            return
        }

        // It's possible a new configuration is available...
        if (document.state!!.condition == DocumentCondition.CONFIGURATION_AVAILABLE) {
            Logger.i(TAG, "syncDocumentWithIssuer: ${document.identifier} has a new configuration")

            // New configuration (= PII) is available, nuke all existing credentials
            //
            document.getCredentials().forEach { document.deleteCredential(it.identifier) }
            metadata.setDocumentConfiguration(
                issuer.getDocumentConfiguration(metadata.documentIdentifier))

            // Notify the user that the document is either ready or an update has been downloaded.
            if (document.numDocumentConfigurationsDownloaded == 0L) {
                if (document.documentConfiguration.directAccessConfiguration != null) {
                    document.walletDocumentMetadata.setDocumentSlot(
                        DirectAccess.allocateDocumentSlot()
                    )
                }
                walletApplication.postNotificationForDocument(
                    document,
                    walletApplication.applicationContext.getString(
                        R.string.notifications_document_application_approved_and_ready_to_use
                    )
                )
            } else {
                walletApplication.postNotificationForDocument(
                    document,
                    walletApplication.applicationContext.getString(
                        R.string.notifications_document_update_from_issuer
                    )
                )
            }
            metadata.incrementNumDocumentConfigurationsDownloaded()

            metadata.refreshState(walletServerProvider)
        }

        // If the document is in the READY state, we can request credentials. See if we need
        // to do that.
        if (document.state!!.condition == DocumentCondition.READY) {
            val docConf = document.documentConfiguration

            if (docConf.mdocConfiguration != null) {
                refreshCredentials(
                    issuer,
                    document,
                    WalletApplication.CREDENTIAL_DOMAIN_MDOC,
                    CredentialFormat.MDOC_MSO
                ) { credentialToReplace, credentialDomain, secureArea, createKeySettings ->
                    MdocCredential.create(
                        document,
                        credentialToReplace,
                        credentialDomain,
                        secureArea,
                        docConf.mdocConfiguration!!.docType,
                        createKeySettings
                    )
                }
            }

            if (docConf.directAccessConfiguration != null) {
                refreshCredentials(
                    issuer,
                    document,
                    WalletApplication.CREDENTIAL_DOMAIN_DIRECT_ACCESS,
                    CredentialFormat.DirectAccess
                ) { credentialToReplace, credentialDomain, secureArea, createKeySettings ->
                    DirectAccessCredential(
                        document,
                        credentialToReplace,
                        credentialDomain,
                        docConf.directAccessConfiguration!!.docType,
                        document.documentSlot
                    )
                }
            }

            val configuration = docConf.sdJwtVcDocumentConfiguration
            if (configuration != null && configuration.keyBound != false) {
                refreshCredentials(
                    issuer,
                    document,
                    WalletApplication.CREDENTIAL_DOMAIN_SD_JWT_VC,
                    CredentialFormat.SD_JWT_VC
                ) { credentialToReplace, credentialDomain, secureArea, createKeySettings ->
                    KeyBoundSdJwtVcCredential.create(
                        document,
                        credentialToReplace,
                        credentialDomain,
                        secureArea,
                        configuration.vct,
                        createKeySettings
                    )
                }
            }
        }

        // It's possible the request credentials have already been minted..
        metadata.refreshState(walletServerProvider)

        // ... if so, download them.
        var lastCertified: DirectAccessCredential? = null
        var numCredentialsRefreshed = 0
        if (document.state!!.numAvailableCredentials > 0) {
            for (credentialData in issuer.getCredentials(document.documentIdentifier)) {
                val pendingCredential = if (credentialData.secureAreaBoundKey == null) {
                    // Keyless credential
                    KeylessSdJwtVcCredential.create(
                        document,
                        null,
                        WalletApplication.CREDENTIAL_DOMAIN_SD_JWT_VC,
                        document.documentConfiguration.sdJwtVcDocumentConfiguration!!.vct
                    )
                } else {
                    document.getPendingCredentials().find {
                        val attestation = if (it is DirectAccessCredential) {
                            it.attestation
                        } else {
                            (it as SecureAreaBoundCredential).getAttestation()
                        }
                        attestation.publicKey == credentialData.secureAreaBoundKey
                    }
                }
                if (pendingCredential == null) {
                    Logger.w(TAG, "No pending Credential for pubkey ${credentialData.secureAreaBoundKey}")
                    continue
                }
                pendingCredential.certify(
                    credentialData.data,
                    credentialData.validFrom,
                    credentialData.validUntil
                )
                numCredentialsRefreshed += 1
                if (pendingCredential is DirectAccessCredential) {
                    lastCertified = pendingCredential
                }
            }
            lastCertified?.setAsActiveCredential()
            metadata.refreshState(walletServerProvider)
        }
    }

    private suspend fun refreshCredentials(
        issuer: IssuingAuthority,
        document: Document,
        credentialDomain: String,
        credentialFormat: CredentialFormat,
        createCredential: suspend (
            credentialToReplace: String?,
            credentialDomain: String,
            secureArea: SecureArea,
            createKeySettings: CreateKeySettings,
                ) -> Credential
    ) {
        val numCreds = document.issuingAuthorityConfiguration.numberOfCredentialsToRequest ?: 3
        val minValidTimeMillis = document.issuingAuthorityConfiguration.minCredentialValidityMillis ?: (30 * 24 * 3600L)
        val maxUsesPerCredential = document.issuingAuthorityConfiguration.maxUsesPerCredentials ?: 1

        val now = Clock.System.now()
        // First do a dry-run to see how many pending credentials will be created
        val numPendingCredentialsToCreate = DocumentUtil.managedCredentialHelper(
            document,
            credentialDomain,
            null,
            now,
            numCreds,
            maxUsesPerCredential,
            minValidTimeMillis,
            true
        )
        if (numPendingCredentialsToCreate > 0) {
            val requestCredentialsFlow = issuer.requestCredentials(document.documentIdentifier)
            val credConfig = requestCredentialsFlow.getCredentialConfiguration(credentialFormat)

            val secureAreaConfiguration = credConfig.secureAreaConfiguration
            val (secureArea, authKeySettings) = when (secureAreaConfiguration) {
                is SecureAreaConfigurationSoftware -> Pair(
                    secureAreaRepository.getImplementation("SoftwareSecureArea"),
                    SoftwareCreateKeySettings.Builder()
                        .applyConfiguration(secureAreaConfiguration)
                        .build()
                )
                is SecureAreaConfigurationAndroidKeystore -> Pair(
                    secureAreaRepository.getImplementation("AndroidKeystoreSecureArea"),
                    AndroidKeystoreCreateKeySettings.Builder(credConfig.challenge.toByteArray())
                        .applyConfiguration(secureAreaConfiguration)
                        .build()
                )
                is SecureAreaConfigurationCloud -> Pair(
                    secureAreaRepository.getImplementation(secureAreaConfiguration.cloudSecureAreaId),
                    CloudCreateKeySettings.Builder(credConfig.challenge.toByteArray())
                        .applyConfiguration(secureAreaConfiguration)
                        .build()
                )
            }
            DocumentUtil.managedCredentialHelper(
                document,
                credentialDomain,
                { credentialToReplace ->
                    createCredential(
                        credentialToReplace,
                        credentialDomain,
                        secureArea!!,
                        authKeySettings,
                    )
                },
                now,
                numCreds,
                maxUsesPerCredential,
                minValidTimeMillis,
                false
            )
            val credentialRequests = mutableListOf<CredentialRequest>()
            val pendingCredentials = document.getPendingCredentials()
            for (pendingCredential in pendingCredentials) {
                credentialRequests.add(
                    CredentialRequest(
                        if (pendingCredential is DirectAccessCredential) {
                            pendingCredential.attestation
                        } else {
                            (pendingCredential as SecureAreaBoundCredential).getAttestation()
                        }
                    )
                )
            }
            val keysAssertion = if (credConfig.keyAssertionRequired) {
                walletServerProvider.assertionMaker.makeDeviceAssertion { clientId ->
                    AssertionBindingKeys(
                        publicKeys = credentialRequests.map { request ->
                            request.secureAreaBoundKeyAttestation.publicKey
                        },
                        nonce = credConfig.challenge,
                        clientId = clientId,
                        keyStorage = listOf(),
                        userAuthentication = listOf(),
                        issuedAt = Clock.System.now()
                    )
                }
            } else {
                null
            }
            val challenges = requestCredentialsFlow.sendCredentials(
                credentialRequests = credentialRequests,
                keysAssertion = keysAssertion
            )
            if (challenges.isNotEmpty()) {
                val activity = this.activity!!
                if (challenges.size != pendingCredentials.size) {
                    throw IllegalStateException("Unexpected number of possession challenges")
                }
                val possessionProofs = mutableListOf<KeyPossessionProof>()
                withContext(Dispatchers.Main) {
                    for (credData in pendingCredentials.zip(challenges)) {
                        val credential = credData.first as SecureAreaBoundCredential
                        val challenge = credData.second
                        val signature = signWithUnlock(
                            activity = activity,
                            title = activity.resources.getString(R.string.issuance_biometric_prompt_title),
                            subtitle = activity.resources.getString(R.string.issuance_biometric_prompt_subtitle),
                            secureArea = credential.secureArea,
                            alias = credential.alias,
                            algorithm = Algorithm.ES256,
                            messageToSign = challenge.messageToSign
                        )
                        possessionProofs.add(KeyPossessionProof(signature))
                    }
                }
                requestCredentialsFlow.sendPossessionProofs(possessionProofs)
            }
            requestCredentialsFlow.complete()  // noop for local, but important for server-side IA
        }
    }
}

private class TimedChunkFlow<T>(sourceFlow: Flow<T>, period: Duration) {
    private val chunkLock = ReentrantLock()
    private var chunk = mutableListOf<T>()
    @OptIn(FlowPreview::class)
    val resultFlow = flow {
        sourceFlow.collect {
            val localChunk = chunkLock.withLock {
                chunk.add(it)
                chunk
            }
            emit(localChunk)
        }
    }.sample(period).onEach {
        chunkLock.withLock {
            chunk = mutableListOf()
        }
    }
}

fun <T> Flow<T>.timedChunk(periodMs: Duration): Flow<List<T>> = TimedChunkFlow(this, periodMs).resultFlow

// TODO: factor it out to some common utility file
// Must be called on main thread
suspend fun signWithUnlock(
    activity: FragmentActivity,
    title: String,
    subtitle: String,
    secureArea: SecureArea,
    alias: String,
    algorithm: Algorithm,
    messageToSign: ByteString
): ByteString {
    // initially null and updated when catching a KeyLockedException in the while-loop below
    var keyUnlockData: KeyUnlockData? = null
    var remainingPassphraseAttempts = 3
    while (true) {
        try {
            val signature = secureArea.sign(
                alias,
                algorithm,
                messageToSign.toByteArray(),
                keyUnlockData = keyUnlockData
            )

            return ByteString(signature.toCoseEncoded())
        } catch (e: KeyLockedException) {
            when (secureArea) {
                // show Biometric prompt
                is AndroidKeystoreSecureArea -> {
                    val unlockData = AndroidKeystoreKeyUnlockData(alias)
                    val cryptoObject = unlockData.getCryptoObjectForSigning(algorithm)

                    // update KeyUnlockData to be used on the next loop iteration
                    keyUnlockData = unlockData

                    val successfulBiometricResult = showBiometricPrompt(
                        activity = activity,
                        title = title,
                        subtitle = subtitle,
                        cryptoObject = cryptoObject,
                        userAuthenticationTypes = setOf(
                            UserAuthenticationType.BIOMETRIC,
                            UserAuthenticationType.LSKF
                        ),
                        requireConfirmation = false
                    )
                    // if user cancelled or was unable to authenticate, throw IllegalStateException
                    check(successfulBiometricResult) { "[Biometric Unsuccessful]" }
                }

                // show Passphrase prompt
                is SoftwareSecureArea -> {
                    val softwareKeyInfo = secureArea.getKeyInfo(alias)

                    val passphrase = showPassphrasePrompt(
                        activity = activity,
                        constraints = softwareKeyInfo.passphraseConstraints!!,
                        title = title,
                        content = subtitle
                    )
                    // ensure the passphrase is not empty, else throw IllegalStateException
                    check(passphrase != null) { "[Passphrase Unsuccessful]" }
                    // use the passphrase that the user entered to create the KeyUnlockData
                    keyUnlockData = SoftwareKeyUnlockData(passphrase)
                }

                // show Passphrase prompt
                is CloudSecureArea -> {
                    if (keyUnlockData == null) {
                        keyUnlockData = CloudKeyUnlockData(secureArea, alias)
                    }

                    when ((e as CloudKeyLockedException).reason) {
                        CloudKeyLockedException.Reason.WRONG_PASSPHRASE -> {
                            // enforce a maximum number of attempts
                            if (remainingPassphraseAttempts == 0) {
                                throw IllegalStateException("Error! Reached maximum number of Passphrase attempts.")
                            }
                            remainingPassphraseAttempts--

                            val constraints = secureArea.getPassphraseConstraints()
                            val title =
                                if (constraints.requireNumerical)
                                    activity.resources.getString(R.string.passphrase_prompt_csa_pin_title)
                                else
                                    activity.resources.getString(R.string.passphrase_prompt_csa_passphrase_title)
                            val content =
                                if (constraints.requireNumerical) {
                                    activity.resources.getString(R.string.passphrase_prompt_csa_pin_content)
                                } else {
                                    activity.resources.getString(
                                        R.string.passphrase_prompt_csa_passphrase_content
                                    )
                                }
                            val passphrase = showPassphrasePrompt(
                                activity = activity,
                                constraints = constraints,
                                title = title,
                                content = content,
                            )

                            // if passphrase is null then user canceled the prompt
                            if (passphrase == null) {
                                throw UserCanceledPromptException()
                            }
                            (keyUnlockData as CloudKeyUnlockData).passphrase = passphrase
                        }

                        CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED -> {
                            val successfulBiometricResult = showBiometricPrompt(
                                activity = activity,
                                title = activity.resources.getString(R.string.presentation_biometric_prompt_title),
                                subtitle = activity.resources.getString(R.string.presentation_biometric_prompt_subtitle),
                                cryptoObject = (keyUnlockData as CloudKeyUnlockData).cryptoObject,
                                userAuthenticationTypes = setOf(
                                    UserAuthenticationType.BIOMETRIC,
                                    UserAuthenticationType.LSKF
                                ),
                                requireConfirmation = false
                            )
                            // if user cancelled or was unable to authenticate, throw IllegalStateException
                            check(successfulBiometricResult) { "Biometric Unsuccessful" }
                        }
                    }
                }

                // for secure areas not yet implemented
                else -> {
                    throw IllegalStateException("No prompts implemented for Secure Area ${secureArea.displayName}")
                }
            }
        }
    }
}

private val EcCurve.humanReadableName: String
    get() {
        return when (this) {
            EcCurve.P256 -> "P-256"
            EcCurve.P384 -> "P-384"
            EcCurve.P521 -> "P-521"
            EcCurve.BRAINPOOLP256R1 -> "BrainpoolP256r1"
            EcCurve.BRAINPOOLP320R1 -> "BrainpoolP320r1"
            EcCurve.BRAINPOOLP384R1 -> "BrainpoolP384r1"
            EcCurve.BRAINPOOLP512R1 -> "BrainpoolP512r1"
            EcCurve.ED25519 -> "Ed25519"
            EcCurve.X25519 -> "X25519"
            EcCurve.ED448 -> "Ed448"
            EcCurve.X448 -> "X448"
        }
    }

private fun renderKeyPurposes(purposes: Set<KeyPurpose>): String {
    if (purposes.contains(KeyPurpose.AGREE_KEY) && purposes.contains(KeyPurpose.SIGN)) {
        return "Signing and Key Agreement"
    } else if (purposes.contains(KeyPurpose.AGREE_KEY)) {
        return "Key Agreement"
    } else if (purposes.contains(KeyPurpose.SIGN)) {
        return "Signing"
    } else if (purposes.isEmpty()) {
        return "(No purposes set)"
    } else {
        throw IllegalStateException("Unexpected set of purposes")
    }
}

private fun renderUserAuthenticationTypes(types: Set<UserAuthenticationType>): String {
    if (types.contains(UserAuthenticationType.LSKF) && types.contains(UserAuthenticationType.BIOMETRIC)) {
        return "PIN/Passphrase/Pattern or Biometrics"
    } else if (types.contains(UserAuthenticationType.LSKF)) {
        return "PIN/Passphrase/Pattern only"
    } else if (types.contains(UserAuthenticationType.LSKF)) {
        return "Biometrics only"
    } else if (types.isEmpty()) {
        return "None"
    } else {
        throw IllegalStateException("Unexpected set of user authentication types")
    }
}
