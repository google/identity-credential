package com.android.identity.mdoc.transport

import com.android.identity.crypto.EcPublicKey
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.util.Logger
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine

private const val TAG = "connectionHelper"

/**
 * A helper for advertising a number of connections to a remote peer.
 *
 * For each [ConnectionMethod] this creates a [MdocTransport] which is the advertised and opened.
 * The first connection which a remote peer connects to is returned and the other ones are closed.
 *
 * @param role the role to use when creting connections.
 * @param transportFactory the [MdocTransportFactory] used to create [MdocTransport] instances.
 * @param options the [MdocTransportOptions] to use when creating [MdocTransport] instances.
 * @param onConnectionMethodsReady called when all connections methods are advertised. This may contain additional
 * information compared to the original list of methods given, for example it may include the BLE PSM or MAC address.
 * @return the [MdocTransport] a remote peer connected to, will be in [MdocTransport.State.CONNECTING]
 * or [MdocTransport.State.CONNECTED] state.
 */
@OptIn(ExperimentalCoroutinesApi::class)
suspend fun List<ConnectionMethod>.connectionHelper(
    role: MdocTransport.Role,
    transportFactory: MdocTransportFactory,
    options: MdocTransportOptions,
    eDeviceKey: EcPublicKey,
    onConnectionMethodsReady: suspend (advertisedConnectionMethods: List<ConnectionMethod>) -> Unit,
): MdocTransport {
    val transports = mutableListOf<MdocTransport>()
    for (connectionMethod in this) {
        val transport = MdocTransportFactory.Default.createTransport(
            connectionMethod,
            role,
            options
        )
        transport.advertise()
        transports.add(transport)
    }
    // TODO: pick it up after open()...
    onConnectionMethodsReady(ConnectionMethod.combine(transports.map { it.connectionMethod }))

    lateinit var continuation: CancellableContinuation<MdocTransport>
    for (transport in transports) {
        // MdocTransport.open() doesn't return until state is CONNECTED which is much later than
        // when we're seeing a connection attempt (when state is CONNECTING)
        //
        // And we want to switch to PresentationScreen upon seeing CONNECTING .. so call open() in a subroutine
        // and just watch the state variable change.
        //
        CoroutineScope(currentCoroutineContext()).launch {
            try {
                Logger.e(TAG, "opening connection ${transport.connectionMethod}")
                transport.open(eDeviceKey)
            } catch (error: Throwable) {
                Logger.e(TAG, "Caught exception while opening connection ${transport.connectionMethod}", error)
                error.printStackTrace()
            }
        }

        CoroutineScope(currentCoroutineContext()).launch {
            // Wait until state changes to CONNECTED, CONNECTING, FAILED, or CLOSED
            transport.state.first {
                it == MdocTransport.State.CONNECTED ||
                        it == MdocTransport.State.CONNECTING ||
                        it == MdocTransport.State.FAILED ||
                        it == MdocTransport.State.CLOSED
            }
            if (transport.state.value == MdocTransport.State.CONNECTING ||
                transport.state.value == MdocTransport.State.CONNECTED
            ) {
                // Close the transports that didn't get connected
                for (otherTransport in transports) {
                    if (otherTransport != transport) {
                        Logger.i(TAG, "Closing other transport ${otherTransport.connectionMethod}")
                        otherTransport.close()
                    }
                }
                continuation.resume(transport, null)
            }
        }
    }
    return suspendCancellableCoroutine<MdocTransport> { continuation = it }
}