package com.android.identity.appsupport.ui.presentment

import com.android.identity.credential.Credential
import com.android.identity.document.Document
import com.android.identity.mdoc.sessionencryption.SessionEncryption
import com.android.identity.request.Request
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.time.Duration.Companion.seconds

/**
 * A model used for credential presentment.
 *
 * This model implements the entire UX/UI flow related to presentment, including
 *
 * - Allowing the user to cancel at any time, including when the connection is being established.
 * - Querying the user for which document to present, if multiple credentials can satisfy the request.
 * - Showing a consent dialog.
 * - Generating the response and sending it to the verifier, via the selected mechanism.
 * - Support for multiple requests if both sides keep the connection open
 */
class PresentmentModel {
    companion object {
        private const val TAG = "PresentmentModel"
    }

    /**
     * Possible states that the model can be in.
     */
    enum class State {
        /**
         * Presentment is not active.
         */
        IDLE,

        /**
         * Presentment has been started but the mechanism used to communicate with the reader is not yet available.
         */
        CONNECTING,

        /**
         * Presentment is ready, waiting for a [PresentmentSource] to be connected.
         */
        WAITING_FOR_SOURCE,

        /**
         * Presentment is currently underway.
         */
        PROCESSING,

        /**
         * A request has been received and multiple documents can be presented and the user needs to pick one.
         *
         * The UI layer should show a document selection dialog with the documents in [availableDocuments]
         * and call [documentSelected] with the user's choice, if any.
         */
        WAITING_FOR_DOCUMENT_SELECTION,

        /**
         * A request has been received, waiting for the user to provide consent.
         *
         * The UI layer should show a consent prompt with the data in [consentData] and call
         * [consentReviewed] with whether the user consented to the request.
         */
        WAITING_FOR_CONSENT,

        /**
         * Presentment is complete. If something went wrong the [error] property is set.
         */
        COMPLETED,
    }

    private val _state = MutableStateFlow<State>(State.IDLE)
    /**
     * The current state.
     */
    val state = _state.asStateFlow()

    private var _presentmentScope: CoroutineScope? = null
    /**
     * A [CoroutineScope] for the presentment process.
     *
     * Any coroutine launched in this scope will be automatically canceled when presentment completes.
     *
     * This should only be read in states which aren't [State.IDLE] and [State.COMPLETED]. It will throw
     * [IllegalStateException] if this is not the case.
     */
    val presentmentScope: CoroutineScope
        get() {
            check(_presentmentScope != null)
            check(_state.value != State.IDLE && _state.value != State.COMPLETED)
            return _presentmentScope!!
        }

    private var _mechanism: PresentmentMechanism? = null
    /**
     * The mechanism being used to communicate with the credential reader.
     */
    val mechanism: PresentmentMechanism?
        get() = _mechanism

    private var _source: PresentmentSource? = null
    /**
     * The source which provides data to present.
     */
    val source: PresentmentSource?
        get() = _source

    private var _error: Throwable? = null
    /**
     * If presentment fails, this will be set with a [Throwable] with more information about the failure.
     */
    val error: Throwable?
        get() = _error

    /**
     * Resets the model to [State.IDLE].
     */
    fun reset() {
        _mechanism?.close()
        _mechanism = null
        _source = null
        _error = null
        _dismissable.value = true
        _numRequestsServed.value = 0
        _presentmentScope?.cancel(CancellationException("PresentationModel reset"))
        _presentmentScope = null
        _state.value = State.IDLE
    }

    /**
     * Sets the model to [State.CONNECTING].
     */
    fun setConnecting() {
        check(_state.value == State.IDLE)
        _presentmentScope = CoroutineScope(Dispatchers.Main)
        _state.value = State.CONNECTING
    }

    /**
     * Sets the [PresentmentMechanism] to use.
     *
     * This sets the model to [State.WAITING_FOR_SOURCE].
     *
     * @param mechanism the [PresentmentMechanism] to use.
     */
    fun setMechanism(mechanism: PresentmentMechanism) {
        check(_state.value == State.CONNECTING)
        _mechanism = mechanism
        _state.value = State.WAITING_FOR_SOURCE
    }

    /**
     * Sets the [PresentmentSource] to use for presentment.
     *
     * This sets the model to [State.PROCESSING].
     *
     * @param source the [PresentmentSource] to use.
     */
    fun setSource(source: PresentmentSource) {
        check(_state.value == State.WAITING_FOR_SOURCE)
        _source = source
        _state.value = State.PROCESSING

        // OK, now that we got both a mechanism and a source we're off to the races and we can
        // start the presentment flow! Do this in a separate coroutine.
        //
        _presentmentScope!!.launch {
            startPresentmentFlow()
        }
    }

    /**
     * Data to include in the consent prompt.
     *
     * @property document the document being presented
     * @property request the request, including who made the request.
     * @property trustPoint a [TrustPoint] if the requester is trusted, null otherwise
     */
    data class ConsentData(
        val document: Document,
        val request: Request,
        val trustPoint: TrustPoint?
    )

    private var _consentData: ConsentData? = null
    /**
     * The data to show in the consent dialog.
     *
     * This can only be read when in state [State.WAITING_FOR_CONSENT].
     */
    val consentData: ConsentData
        get() {
            check(_state.value == State.WAITING_FOR_CONSENT)
            return _consentData!!
        }

    /**
     * Sets the model to [State.COMPLETED]
     *
     * @param error pass a [Throwable] if the presentation failed, `null` if successful.
     */
    fun setCompleted(error: Throwable? = null) {
        if (_state.value == State.COMPLETED) {
            Logger.w(TAG, "Already completed, ignoring second call")
            return
        }
        _mechanism?.close()
        _mechanism = null
        _error = error
        _state.value = State.COMPLETED
        // TODO: Hack to ensure that [state] collectors (using [presentationScope]) gets called for State.COMPLETED
        _presentmentScope?.launch {
            delay(1.seconds)
            _presentmentScope?.cancel(CancellationException("PresentationModel completed"))
            _presentmentScope = null
        }
    }

    /**
     * Three different ways the close/dismiss button can be triggered.
     *
     * This is used by [MdocPresentmentMechanism] to perform either normal session-termination (normal click),
     * transport-specific session termination (long press), or termination without notifying the other end (double
     * click).
     *
     * @property CLICK the user clicked the button normally.
     * @property LONG_CLICK the user performed a long press on the button.
     * @property DOUBLE_CLICK the user double-clicked the button.
     */
    enum class DismissType {
        CLICK,
        LONG_CLICK,
        DOUBLE_CLICK,
    }

    private var _dismissable = MutableStateFlow<Boolean>(true)
    /**
     * Returns whether the presentment can be dismissed/canceled.
     *
     * If this is true the UI layer should include e.g. a button the user can press to dismiss/cancel and
     * call [dismiss] when the user clicks the button.
     */
    val dismissable = _dismissable.asStateFlow()

    private var _numRequestsServed = MutableStateFlow<Int>(0)
    /**
     * Number of requests served.
     */
    val numRequestsServed = _numRequestsServed.asStateFlow()

    /**
     * Should be called by the UI layer if the user hits the dismiss button.
     *
     * This ends the presentment flow by calling [setCompleted] with the error parameter set to
     * a [PresentmentCanceled] instance.
     *
     * @param dismissType the type of interaction the user had with the dismiss button
     */
    fun dismiss(dismissType: DismissType) {
        val mdocMechanism = mechanism as? MdocPresentmentMechanism
        if (mdocMechanism != null) {
            _presentmentScope!!.launch {
                try {
                    when (dismissType) {
                        DismissType.CLICK -> {
                            mdocMechanism.transport.sendMessage(
                                SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION)
                            )
                            mdocMechanism.transport.close()
                        }
                        DismissType.LONG_CLICK -> {
                            mdocMechanism.transport.sendMessage(byteArrayOf())
                            mdocMechanism.transport.close()
                        }
                        DismissType.DOUBLE_CLICK -> {
                            mdocMechanism.transport.close()
                        }
                    }
                } catch (error: Throwable) {
                    Logger.e(TAG, "Caught exception closing transport", error)
                    error.printStackTrace()
                }
            }
        }
        setCompleted(PresentmentCanceled("The presentment was canceled by the user"))
    }

    private suspend fun startPresentmentFlow() {
        when (mechanism!!) {
            is MdocPresentmentMechanism -> {
                mdocPresentment(
                    documentTypeRepository = source!!.documentTypeRepository,
                    source = source!!,
                    model = this,
                    mechanism = mechanism as MdocPresentmentMechanism,
                    dismissable = _dismissable,
                    numRequestsServed = _numRequestsServed,
                    showCredentialPicker = { credentials ->
                        showCredentialPicker(credentials)
                    },
                    showConsentPrompt = { document, request, trustPoint ->
                        showConsentPrompt(document, request, trustPoint)
                    },
                )
            }
            is DigitalCredentialsPresentmentMechanism -> {
                digitalCredentialsPresentment(
                    documentTypeRepository = source!!.documentTypeRepository,
                    source = source!!,
                    model = this,
                    mechanism = mechanism as DigitalCredentialsPresentmentMechanism,
                    dismissable = _dismissable,
                    showConsentPrompt = { document, request, trustPoint ->
                        showConsentPrompt(document, request, trustPoint)
                    }
                )
            }
            else -> throw IllegalStateException("Unsupported mechanism $mechanism")
        }
    }

    private var documentPickerContinuation: CancellableContinuation<Document?>? = null

    private suspend fun showCredentialPicker(credentials: List<Credential>): Credential? {
        check(_state.value == State.PROCESSING)
        val documents = mutableListOf<Document>()
        val documentIdToCredential = mutableMapOf<String, Credential>()
        for (credential in credentials) {
            documents.add(credential.document)
            documentIdToCredential[credential.document.identifier] = credential
        }
        check(documentIdToCredential.size == credentials.size) { "Credentials must be from distinct documents" }
        _availableDocuments = documents
        _state.value = State.WAITING_FOR_DOCUMENT_SELECTION
        val ret = suspendCancellableCoroutine<Document?> { continuation ->
            documentPickerContinuation = continuation
        }
        _availableDocuments = null
        _state.value = State.PROCESSING
        return documentIdToCredential[ret?.identifier]
    }

    private var _availableDocuments: List<Document>? = null
    /**
     * The list of available documents to pick from.
     *
     * This can only be read when in state [State.WAITING_FOR_DOCUMENT_SELECTION].
     */
    val availableDocuments: List<Document>
        get() {
            check(_state.value == State.WAITING_FOR_DOCUMENT_SELECTION)
            return _availableDocuments!!
        }

    /**
     * The UI layer should call this when a user has selected a document.
     *
     * This can only be called in state [State.WAITING_FOR_DOCUMENT_SELECTION]
     *
     * @param document the selected documented, must be `null` to convey the user did not want to continue
     *   otherwise must be from the [availableDocuments] list.
     */
    fun documentSelected(document: Document?) {
        check(_state.value == State.WAITING_FOR_DOCUMENT_SELECTION)
        documentPickerContinuation!!.resume(document)
    }

    private var consentDataContinuation: CancellableContinuation<Boolean>? = null

    private suspend fun showConsentPrompt(
       document: Document,
       request: Request,
       trustPoint: TrustPoint?
    ): Boolean {
        check(_state.value == State.PROCESSING)
        _consentData = ConsentData(document, request, trustPoint)
        _state.value = State.WAITING_FOR_CONSENT
        val ret = suspendCancellableCoroutine<Boolean> { continuation ->
            consentDataContinuation = continuation
        }
        _consentData = null
        _state.value = State.PROCESSING
        return ret
    }

    /**
     * The UI layer should call this when a user has reviewed the consent data.
     *
     * This can only be called in state [State.WAITING_FOR_CONSENT]
     *
     * @param consentObtained true if consent was obtained, false otherwise.
     */
    fun consentReviewed(consentObtained: Boolean) {
        check(_state.value == State.WAITING_FOR_CONSENT)
        consentDataContinuation!!.resume(consentObtained)
    }
}