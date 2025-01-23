package com.android.identity.testapp

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Vibrator
import androidx.core.content.ContextCompat
import com.android.identity.cbor.DataItem
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.mdoc.nfc.MdocNfcEngagementHelper
import com.android.identity.appsupport.ui.presentment.MdocPresentmentMechanism
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.mdoc.transport.MdocTransportFactory
import com.android.identity.mdoc.transport.MdocTransportOptions
import com.android.identity.nfc.CommandApdu
import com.android.identity.appsupport.ui.presentment.PresentmentModel
import com.android.identity.mdoc.transport.connectionHelper
import com.android.identity.util.AndroidContexts
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class NdefService: HostApduService() {
    companion object {
        private val TAG = "NdefService"

        private var engagement: MdocNfcEngagementHelper? = null
        private var disableEngagementJob: Job? = null
        private var listenForCancellationFromUiJob: Job? = null
        val presentmentModel: PresentmentModel by lazy { PresentmentModel() }
    }


    private fun vibrate(pattern: List<Int>) {
        val vibrator = ContextCompat.getSystemService<Vibrator>(
            AndroidContexts.applicationContext,
            Vibrator::class.java
        )
        vibrator?.vibrate(pattern.map { it.toLong() }.toLongArray(), -1)
    }

    private fun vibrateError() {
        vibrate(listOf(0, 500))
    }

    private fun vibrateSuccess() {
        vibrate(listOf(0, 100, 50, 100))
    }

    override fun onDestroy() {
        Logger.i(TAG, "onDestroy")
        super.onDestroy()
    }

    override fun onCreate() {
        Logger.i(TAG, "onCreate")
        super.onCreate()
        MainActivity.initBouncyCastle()
    }

    private var started = false

    private fun startEngagement() {
        disableEngagementJob?.cancel()
        disableEngagementJob = null
        listenForCancellationFromUiJob?.cancel()
        listenForCancellationFromUiJob = null

        val settingsModel = App.settingsModel

        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val timeStarted = Clock.System.now()

        presentmentModel.reset()
        presentmentModel.setConnecting()

        // The UI consuming [PresentationModel] - for example the [Presentment] composable in this library - may
        // have a cancel button which will trigger COMPLETED state when pressed. Need to listen for that.
        //
        listenForCancellationFromUiJob = presentmentModel.presentmentScope.launch {
            presentmentModel.state
                .collect { state ->
                    if (state == PresentmentModel.State.COMPLETED) {
                        disableEngagementJob?.cancel()
                        disableEngagementJob = null
                    }
                }
        }

        val intent = Intent(applicationContext, NfcPresentmentActivity::class.java)
        intent.addFlags(
            Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_NO_HISTORY or
                    Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                    Intent.FLAG_ACTIVITY_NO_ANIMATION
        )
        applicationContext.startActivity(intent)

        fun negotiatedHandoverPicker(connectionMethods: List<ConnectionMethod>): ConnectionMethod {
            Logger.i(TAG, "Negotiated Handover available methods: $connectionMethods")
            for (prefix in settingsModel.presentmentNegotiatedHandoverPreferredOrder.value) {
                for (connectionMethod in connectionMethods) {
                    if (connectionMethod.toString().startsWith(prefix)) {
                        Logger.i(TAG, "Using method $connectionMethod")
                        return connectionMethod
                    }
                }
            }
            Logger.i(TAG, "Using method ${connectionMethods.first()}")
            return connectionMethods.first()
        }

        val negotiatedHandoverPicker: ((connectionMethods: List<ConnectionMethod>) -> ConnectionMethod)? =
            if (settingsModel.presentmentUseNegotiatedHandover.value) {
                { connectionMethods -> negotiatedHandoverPicker(connectionMethods) }
            } else {
                null
            }

        var staticHandoverConnectionMethods: List<ConnectionMethod>? = null
        if (!settingsModel.presentmentUseNegotiatedHandover.value) {
            staticHandoverConnectionMethods = mutableListOf<ConnectionMethod>()
            val bleUuid = UUID.randomUUID()
            if (settingsModel.presentmentBleCentralClientModeEnabled.value) {
                staticHandoverConnectionMethods.add(
                    ConnectionMethodBle(
                        supportsPeripheralServerMode = false,
                        supportsCentralClientMode = true,
                        peripheralServerModeUuid = null,
                        centralClientModeUuid = bleUuid,
                    )
                )
            }
            if (settingsModel.presentmentBlePeripheralServerModeEnabled.value) {
                staticHandoverConnectionMethods.add(
                    ConnectionMethodBle(
                        supportsPeripheralServerMode = true,
                        supportsCentralClientMode = false,
                        peripheralServerModeUuid = bleUuid,
                        centralClientModeUuid = null,
                    )
                )
            }
        }

        engagement = MdocNfcEngagementHelper(
            eDeviceKey = eDeviceKey.publicKey,
            onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover ->
                vibrateSuccess()
                val duration = Clock.System.now() - timeStarted
                listenOnMethods(
                    connectionMethods = connectionMethods,
                    settingsModel = settingsModel,
                    encodedDeviceEngagement = encodedDeviceEngagement,
                    handover = handover,
                    eDeviceKey = eDeviceKey,
                    engagementDuration = duration
                )
            },
            onError = { error ->
                Logger.w(TAG, "Engagement failed", error)
                vibrateError()
                engagement = null
            },
            staticHandoverMethods = staticHandoverConnectionMethods,
            negotiatedHandoverPicker = negotiatedHandoverPicker
        )
    }

    private fun listenOnMethods(
        connectionMethods: List<ConnectionMethod>,
        settingsModel: TestAppSettingsModel,
        encodedDeviceEngagement: ByteString,
        handover: DataItem,
        eDeviceKey: EcPrivateKey,
        engagementDuration: Duration,
    ) {
        presentmentModel.presentmentScope.launch {
            val transport = connectionMethods.connectionHelper(
                role = MdocTransport.Role.MDOC,
                transportFactory = MdocTransportFactory.Default,
                options = MdocTransportOptions(
                    bleUseL2CAP = settingsModel.readerBleL2CapEnabled.value
                ),
                eDeviceKey = eDeviceKey.publicKey,
                onConnectionMethodsReady = {}
            )
            presentmentModel.setMechanism(
                MdocPresentmentMechanism(
                    transport = transport,
                    eDeviceKey = eDeviceKey,
                    encodedDeviceEngagement = encodedDeviceEngagement,
                    handover = handover,
                    engagementDuration = engagementDuration,
                    allowMultipleRequests = settingsModel.presentmentAllowMultipleRequests.value
                )
            )
            disableEngagementJob?.cancel()
            disableEngagementJob = null
            listenForCancellationFromUiJob?.cancel()
            listenForCancellationFromUiJob = null
        }
    }

    override fun processCommandApdu(encodedCommandApdu: ByteArray, extras: Bundle?): ByteArray? {
        Logger.i(TAG, "processCommandApdu")
        if (!started) {
            started = true
            startEngagement()
        }

        try {
            engagement?.let {
                val commandApdu = CommandApdu.decode(encodedCommandApdu)
                val responseApdu = runBlocking { it.processApdu(commandApdu) }
                return responseApdu.encode()
            }
        } catch (e: Throwable) {
            Logger.e(TAG, "processCommandApdu", e)
            e.printStackTrace()
        }
        return null
    }

    override fun onDeactivated(reason: Int) {
        Logger.i(TAG, "onDeactivated: reason=$reason")
        // If the reader hasn't connected by the time NFC interaction ends, make sure we only
        // wait for a limited amount of time.
        if (presentmentModel.state.value == PresentmentModel.State.CONNECTING) {
            val timeout = 15.seconds
            Logger.i(TAG, "Reader hasn't connected at NFC deactivation time, scheduling $timeout timeout for closing")
            disableEngagementJob = CoroutineScope(Dispatchers.IO).launch {
                delay(timeout)
                if (presentmentModel.state.value == PresentmentModel.State.CONNECTING) {
                    presentmentModel.setCompleted(Error("Reader didn't connect inside $timeout, closing"))
                }
                engagement = null
                disableEngagementJob = null
            }
        }
    }
}