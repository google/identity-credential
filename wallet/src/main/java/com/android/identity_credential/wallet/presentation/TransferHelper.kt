package com.android.identity_credential.wallet.presentation

import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.preference.PreferenceManager
import android.widget.Toast
import com.android.identity.android.mdoc.deviceretrieval.DeviceRetrievalHelper
import com.android.identity.cbor.Cbor
import com.android.identity.credential.AuthenticationKey
import com.android.identity.credential.CredentialRequest
import com.android.identity.credential.CredentialStore
import com.android.identity.credential.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.javaX509Certificates
import com.android.identity.issuance.CredentialExtensions.credentialConfiguration
import com.android.identity.issuance.CredentialExtensions.issuingAuthorityIdentifier
import com.android.identity.issuance.CredentialPresentationFormat
import com.android.identity.issuance.IssuingAuthorityRepository
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.util.Timestamp
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.SettingsModel
import com.android.identity_credential.wallet.WalletApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * Transfer Helper provides helper functions for starting to process a presentation request, as well
 * as finishing processing the request to get response bytes to send to requesting party (after user
 * has accepted one or more dialog prompts)
 */
class TransferHelper(
    private val settingsModel: SettingsModel,
    private val credentialStore: CredentialStore,
    private val issuingAuthorityRepository: IssuingAuthorityRepository,
    private val trustManager: TrustManager,
    private val context: Context,
    private val deviceRetrievalHelper: DeviceRetrievalHelper,
    private val onError: (Throwable) -> Unit
) {
    companion object {
        private const val TAG = "TransferHelper"
    }

    /**
     * Builder class returning a new TransferHelper instance with a new deviceRetrievalHelper object.
     */
    class Builder(
        val settingsModel: SettingsModel,
        val credentialStore: CredentialStore,
        val issuingAuthorityRepository: IssuingAuthorityRepository,
        val trustManager: TrustManager,
        val context: Context,
        private var deviceRetrievalHelper: DeviceRetrievalHelper? = null,
        var onError: (Throwable) -> Unit = {},
    ) {
        fun setDeviceRetrievalHelper(deviceRetrievalHelper: DeviceRetrievalHelper) = apply {
            this.deviceRetrievalHelper = deviceRetrievalHelper
        }

        fun build() = TransferHelper(
            settingsModel = settingsModel,
            credentialStore = credentialStore,
            issuingAuthorityRepository = issuingAuthorityRepository,
            trustManager = trustManager,
            context = context,
            deviceRetrievalHelper = deviceRetrievalHelper!!,
            onError = onError,
        )
    }

    /**
     * Start processing the presentation request and return a [PresentationRequestData] object that
     * is used in finishProcessingRequest() to generate response bytes to send to requesting party.
     *
     * @param deviceRequest the request bytes for initiating a Presentation
     * @return a PresentationRequestData object containing data used to finish processing the request
     * and generate response bytes, or null if no credential id could be found.
     */
    fun startProcessingRequest(deviceRequest: ByteArray): PresentationRequestData? {

        // TODO: we currently only look at the first docRequest ... in the future need to process
        //  all of them sequentially.
        val request = DeviceRequestParser(deviceRequest, deviceRetrievalHelper.sessionTranscript).parse()
        val docRequest = request.documentRequests[0]

        // TODO support more formats
        val credentialPresentationFormat: CredentialPresentationFormat =
            CredentialPresentationFormat.MDOC_MSO

        // TODO when selecting a matching credential of the MDOC_MSO format, also use docRequest.docType
        //     to select a credential of the right doctype
        val credentialId: String = findFirstCredentialSatisfyingRequest(
            settingsModel, credentialPresentationFormat, docRequest)
            ?: run {
                onError(IllegalStateException("No matching credentials in wallet"))
                return null
            }

        val credential = credentialStore.lookupCredential(credentialId)!!

        var trustPoint: TrustPoint? = null
        if (docRequest.readerAuthenticated) {
            val result = trustManager.verify(
                docRequest.readerCertificateChain!!.javaX509Certificates,
                customValidators = emptyList()  // not neeeded for reader auth
            )
            if (result.isTrusted && !result.trustPoints.isEmpty()) {
                trustPoint = result.trustPoints.first()
            } else if (result.error != null) {
                Logger.w(TAG, "Error finding trustpoint for reader auth", result.error!!)
            }
        }

        val credentialRequest = MdocUtil.generateCredentialRequest(docRequest!!)
        val requestedDocType: String = docRequest.docType
        return PresentationRequestData(
            credential,
            credentialRequest,
            requestedDocType,
            trustPoint
        )
    }

    /**
     * Finish processing the request and produce response bytes to be sent to requesting party.
     * This is called once the user accepted various prompts (ie. immediately after the consent prompt,
     * + after biometric prompt if required)
     *
     * At minimum, expects 3 arguments generated from [startProcessingRequest] along with a callback
     * for when processing is finished as well as a callback in case the authentication key is locked.
     * In the case of a locked key, this function can be called again with that key which was locked
     * and its corresponding keyUnlockData.
     *
     * @param requestedDocType the type of credential document requested
     * @param credentialId the id of the credential to send data from
     * @param credentialRequest the object containing list of DataElements for the user to approve
     * @param onFinishedProcessing callback when processing finished to give UI a chance to update
     * @param onAuthenticationKeyLocked callback when the authentication key is locked to give UI a
     *                                  chance to prompt user for authentication
     * @param keyUnlockData key unlock data for a specific authenticated key
     * @param authKey a specified authentication key
     */
    suspend fun finishProcessingRequest(
        requestedDocType: String,
        credentialId: String,
        credentialRequest: CredentialRequest,
        onFinishedProcessing: (ByteArray) -> Unit,
        onAuthenticationKeyLocked: (authenticationKey: AuthenticationKey) -> Unit,
        keyUnlockData: KeyUnlockData? = null,
        authKey: AuthenticationKey? = null
    ) {
        val credential = credentialStore.lookupCredential(credentialId)!!

        val encodedDeviceResponse: ByteArray
        val credentialConfiguration = credential.credentialConfiguration
        val now = Timestamp.now()
        val authKeyToUse: AuthenticationKey = authKey
            ?: (credential.findAuthenticationKey(WalletApplication.AUTH_KEY_DOMAIN, now)
                ?: run {
                    onError(IllegalStateException("No valid auth keys, please request more"))
                    return
                })

        val staticAuthData = StaticAuthDataParser(authKeyToUse.issuerProvidedData).parse()
        val issuerAuthCoseSign1 = Cbor.decode(staticAuthData.issuerAuth).asCoseSign1
        val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
        val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)
        val mso = MobileSecurityObjectParser(encodedMso).parse()

        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            credentialRequest,
            credentialConfiguration.staticData,
            staticAuthData
        )

        val deviceResponseGenerator =
            DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)

        // in sep coroutine so that an unexpected error will still allow this function to
        // finish and send potentially empty response
        val result = withContext(Dispatchers.IO) { //<- Offload from UI thread
            addDocumentToResponse(
                deviceResponseGenerator = deviceResponseGenerator,
                docType = mso.docType,
                issuerAuth = staticAuthData.issuerAuth,
                mergedIssuerNamespaces = mergedIssuerNamespaces,
                authKey = authKeyToUse,
                keyUnlockData = keyUnlockData
            )
        }

        if (result != null) {
            onAuthenticationKeyLocked(result)
            return
        }

        onFinishedProcessing(deviceResponseGenerator.generate())
    }

    private suspend fun addDocumentToResponse(
        deviceResponseGenerator: DeviceResponseGenerator,
        docType: String,
        issuerAuth: ByteArray,
        mergedIssuerNamespaces: Map<String, MutableList<ByteArray>>,
        authKey: AuthenticationKey,
        keyUnlockData: KeyUnlockData?
    ) = suspendCancellableCoroutine { continuation ->
        var result: AuthenticationKey?

        try {
            deviceResponseGenerator.addDocument(
                DocumentGenerator(
                    docType,
                    issuerAuth, deviceRetrievalHelper.sessionTranscript
                )
                    .setIssuerNamespaces(mergedIssuerNamespaces)
                    .setDeviceNamespacesSignature(
                        NameSpacedData.Builder().build(),
                        authKey.secureArea,
                        authKey.alias,
                        keyUnlockData,
                        Algorithm.ES256
                    )
                    .generate()
            )
            authKey.increaseUsageCount()
            if (authKey.usageCount > 1) {
                Handler(Looper.getMainLooper()).post {
                    Toast.makeText(
                        context,
                        context.resources.getString(R.string.presentation_authkey_usage_warning),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
            result = null
        } catch (e: KeyLockedException) {
            result = authKey
        }

        continuation.resume(result)
    }

    /**
     * Send response bytes of credential data to requesting party
     * @param deviceResponseBytes response bytes to send to requesting party
     */
    fun sendResponse(deviceResponseBytes: ByteArray) {
        deviceRetrievalHelper.sendDeviceResponse(
            deviceResponseBytes,
            Constants.SESSION_DATA_STATUS_SESSION_TERMINATION
        )
    }

    /**
     * Return a credential identifier which can satisfy the request.
     *
     * If multiple credentials can satisfy the request, preference is given to the currently
     * focused credential in the main pager.
     *
     * @param credentialPresentationFormat the presentation format type for which credentials are queried
     * @param docRequest the docRequest, including the requested DocType.
     * @return credential identifier if found, otherwise null.
     */
    private fun findFirstCredentialSatisfyingRequest(
        settingsModel: SettingsModel,
        credentialPresentationFormat: CredentialPresentationFormat,
        docRequest: DeviceRequestParser.DocumentRequest,
    ): String? {
        // prefer the credential which is on-screen if possible
        val credentialIdFromPager: String? = settingsModel.focusedCardId.value
        if (credentialIdFromPager != null
            && canCredentialSatisfyRequest(credentialIdFromPager, credentialPresentationFormat, docRequest)
        ) {
            return credentialIdFromPager
        }

        return credentialStore.listCredentials().firstOrNull { credentialId ->
            canCredentialSatisfyRequest(credentialId, credentialPresentationFormat, docRequest)
        }
    }

    /**
     * Return whether the passed credential id can satisfy the request
     *
     * @param credentialId id of credential to check
     * @param credentialPresentationFormat the request presentation format for transferring
     * credential data
     * @param docRequest the DocRequest, including the DocType
     * @return whether the specified credential id can satisfy the request
     */
    private fun canCredentialSatisfyRequest(
        credentialId: String,
        credentialPresentationFormat: CredentialPresentationFormat,
        docRequest: DeviceRequestParser.DocumentRequest
    ): Boolean {
        val credential = credentialStore.lookupCredential(credentialId)!!
        val issuingAuthorityIdentifier = credential.issuingAuthorityIdentifier
        val issuer =
            issuingAuthorityRepository.lookupIssuingAuthority(issuingAuthorityIdentifier)
                ?: throw IllegalArgumentException("No issuer with id $issuingAuthorityIdentifier")
        val credentialFormats = issuer.configuration.credentialFormats
        if (!credentialFormats.contains(credentialPresentationFormat)) {
            return false;
        }

        val credConf = credential.credentialConfiguration
        if (credConf.mdocDocType != docRequest.docType) {
            return false
        }

        return true
    }
}