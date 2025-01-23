package com.android.identity.mdoc.transport

import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle

internal actual fun defaultMdocTransportFactoryCreateTransport(
    connectionMethod: ConnectionMethod,
    role: MdocTransport.Role,
    options: MdocTransportOptions
): MdocTransport {
    when (connectionMethod) {
        is ConnectionMethodBle -> {
            if (connectionMethod.supportsCentralClientMode &&
                connectionMethod.supportsPeripheralServerMode) {
                throw IllegalArgumentException(
                    "Only Central Client or Peripheral Server mode is supported at one time, not both"
                )
            } else if (connectionMethod.supportsCentralClientMode) {
                return when (role) {
                    MdocTransport.Role.MDOC -> {
                        BleTransportCentralMdoc(
                            role,
                            options,
                            BleCentralManagerIos(),
                            connectionMethod.centralClientModeUuid!!,
                            connectionMethod.peripheralServerModePsm
                        )
                    }
                    MdocTransport.Role.MDOC_READER -> {
                        BleTransportCentralMdocReader(
                            role,
                            options,
                            BlePeripheralManagerIos(),
                            connectionMethod.centralClientModeUuid!!
                        )
                    }
                }
            } else {
                return when (role) {
                    MdocTransport.Role.MDOC -> {
                        BleTransportPeripheralMdoc(
                            role,
                            options,
                            BlePeripheralManagerIos(),
                            connectionMethod.peripheralServerModeUuid!!
                        )
                    }
                    MdocTransport.Role.MDOC_READER -> {
                        BleTransportPeripheralMdocReader(
                            role,
                            options,
                            BleCentralManagerIos(),
                            connectionMethod.peripheralServerModeUuid!!,
                            connectionMethod.peripheralServerModePsm,
                        )
                    }
                }
            }
        }
        else -> {
            throw IllegalArgumentException("$connectionMethod is not supported")
        }
    }
}
