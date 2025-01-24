package com.android.identity.testapp.provisioning

import com.android.identity.cbor.Bstr
import com.android.identity.device.DeviceCheck
import com.android.identity.device.AssertionNonce
import com.android.identity.device.DeviceAttestation
import com.android.identity.flow.handler.FlowDispatcher
import com.android.identity.flow.handler.FlowDispatcherHttp
import com.android.identity.flow.handler.FlowExceptionMap
import com.android.identity.flow.handler.FlowNotifier
import com.android.identity.flow.handler.FlowNotifierPoll
import com.android.identity.flow.handler.FlowPollHttp
import com.android.identity.flow.transport.HttpTransport
import com.android.identity.issuance.ClientAuthentication
import com.android.identity.issuance.IssuingAuthority
import com.android.identity.issuance.IssuingAuthorityException
import com.android.identity.issuance.LandingUrlUnknownException
import com.android.identity.issuance.WalletApplicationCapabilities
import com.android.identity.issuance.WalletServer
import com.android.identity.issuance.WalletServerImpl
import com.android.identity.issuance.register
import com.android.identity.storage.StorageTableSpec
import com.android.identity.testapp.platformSecureAreaProvider
import com.android.identity.testapp.platformStorage
import com.android.identity.util.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.seconds

/**
 * An object used to connect to a remote wallet server.
 */
class WalletServerProvider(
    private val baseUrl: String,
    private val getWalletApplicationCapabilities: suspend () -> WalletApplicationCapabilities,
) {
    private val instanceLock = Mutex()
    private var instance: WalletServer? = null
    private val issuingAuthorityMap = mutableMapOf<String, IssuingAuthority>()

    private var notificationsJob: Job? = null

    companion object {
        private const val TAG = "WalletServerProvider"

        private val RECONNECT_DELAY_INITIAL = 1.seconds
        private val RECONNECT_DELAY_MAX = 30.seconds

        private val serverTableSpec = StorageTableSpec(
            name = "Servers",
            supportPartitions = false,
            supportExpiration = false
        )
    }

    /**
     * Connects to the remote wallet server.
     *
     * This process includes running through the authentication flow to prove to the remote wallet
     * server that the client is in good standing, e.g. that Verified Boot is GREEN, Android patch
     * level is sufficiently fresh, the app signature keys are as expected, and so on.
     *
     * This is usually only called for operations where the wallet actively needs to interact
     * with the wallet server, e.g. when adding a new document or refreshing state. When the
     * call succeeds, the resulting instance is cached and returned immediately in future calls.
     *
     * @return A [WalletServer] which can be used to interact with the remote wallet server.
     * @throws HttpTransport.ConnectionException if unable to connect.
     */
    suspend fun getWalletServer(): WalletServer {
        instanceLock.withLock {
            if (instance == null) {
                Logger.i(TAG, "Creating new WalletServer instance: $baseUrl")
                instance = getWalletServerUnlocked(baseUrl)
                Logger.i(TAG, "Created new WalletServer instance: $baseUrl")
            } else {
                Logger.i(TAG, "Reusing existing WalletServer instance: $baseUrl")
            }
            return instance!!
        }
    }

    /**
     * Connects to the remote wallet server, waiting for the server connection if needed.
     */
    private suspend fun waitForWalletServer(): WalletServer {
        var delay = RECONNECT_DELAY_INITIAL
        while (true) {
            try {
                return getWalletServer()
            } catch (err: HttpTransport.ConnectionException) {
                delay(delay)
                delay *= 2
                if (delay > RECONNECT_DELAY_MAX) {
                    delay = RECONNECT_DELAY_MAX
                }
            }
        }
    }

    /**
     * Gets issuing authority by its id, caching instances. If unable to connect, suspend
     * and wait until connecting is possible.
     */
    suspend fun getIssuingAuthority(issuingAuthorityId: String): IssuingAuthority {
        val instance = waitForWalletServer()
        var delay = RECONNECT_DELAY_INITIAL
        while (true) {
            try {
                instanceLock.withLock {
                    var issuingAuthority = issuingAuthorityMap[issuingAuthorityId]
                    if (issuingAuthority == null) {
                        issuingAuthority = instance.getIssuingAuthority(issuingAuthorityId)
                        issuingAuthorityMap[issuingAuthorityId] = issuingAuthority
                    }
                    return issuingAuthority
                }
            } catch (err: HttpTransport.ConnectionException) {
                delay(delay)
                delay *= 2
                if (delay > RECONNECT_DELAY_MAX) {
                    delay = RECONNECT_DELAY_MAX
                }
            }
        }
    }

    /**
     * Creates an Issuing Authority by the [credentialIssuerUri] and [credentialConfigurationId],
     * caching instances. If unable to connect, suspend and wait until connecting is possible.
     */
    suspend fun createOpenid4VciIssuingAuthorityByUri(
        credentialIssuerUri:String,
        credentialConfigurationId: String
    ): IssuingAuthority {
        // Not allowed per spec, but double-check, so there are no surprises.
        check(credentialIssuerUri.indexOf('#') < 0)
        check(credentialConfigurationId.indexOf('#') < 0)
        val id = "openid4vci#$credentialIssuerUri#$credentialConfigurationId"
        return getIssuingAuthority(id)
    }

    private suspend fun getWalletServerUnlocked(baseUrl: String): WalletServer {
        val dispatcher: FlowDispatcher
        val notifier: FlowNotifier
        val exceptionMapBuilder = FlowExceptionMap.Builder()
        IssuingAuthorityException.register(exceptionMapBuilder)
        LandingUrlUnknownException.register(exceptionMapBuilder)
        val httpClient = WalletHttpTransport(baseUrl)
        val poll = FlowPollHttp(httpClient)
        notifier = FlowNotifierPoll(poll)
        notificationsJob = CoroutineScope(Dispatchers.Main).launch {
            notifier.loop()
        }
        dispatcher = FlowDispatcherHttp(httpClient, exceptionMapBuilder.build())

        // "root" is the entry point for the server, see FlowState annotation on
        // com.android.identity.issuance.wallet.WalletServerState
        val walletServer = WalletServerImpl(
            flowPath = "root",
            flowState = Bstr(byteArrayOf()),
            flowDispatcher = dispatcher,
            flowNotifier = notifier
        )

        val serverTable = platformStorage().getTable(serverTableSpec)
        var serverData = serverTable.get(key = baseUrl)?.let {
            ServerData.fromCbor(it.toByteArray())
        }

        val secureAreaProvider = platformSecureAreaProvider()
        val authentication = walletServer.authenticate()
        val challenge = authentication.requestChallenge(serverData?.clientId ?: "")
        val deviceAttestation: DeviceAttestation?
        if (serverData?.clientId != challenge.clientId) {
            // new client for this host
            val result = DeviceCheck.generateAttestation(
                secureArea = secureAreaProvider.get(),
                clientId = challenge.clientId
            )
            deviceAttestation = result.deviceAttestation
            // TODO: save clientId and deviceAttestationId in storage
            val newServerData = ServerData(challenge.clientId, result.deviceAttestationId)
            if (serverData == null) {
                serverTable.insert(baseUrl, ByteString(newServerData.toCbor()))
            } else {
                serverTable.update(baseUrl, ByteString(newServerData.toCbor()))
            }
            serverData = newServerData
        } else {
            // existing client for this host
            deviceAttestation = null
        }
        authentication.authenticate(ClientAuthentication(
            deviceAttestation,
            DeviceCheck.generateAssertion(
                secureArea = secureAreaProvider.get(),
                deviceAttestationId = serverData.deviceAttestationId,
                assertion = AssertionNonce(challenge.nonce)
            ),
            getWalletApplicationCapabilities()
        ))

        authentication.complete()

        return walletServer
    }
}