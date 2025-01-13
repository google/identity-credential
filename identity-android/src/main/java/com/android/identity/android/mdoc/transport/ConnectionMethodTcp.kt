package com.android.identity.android.mdoc.transport

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.nfc.NdefRecord
import com.android.identity.util.Logger

class ConnectionMethodTcp(val host: String, val port: Int) : ConnectionMethod() {

    override fun toDeviceEngagement(): ByteArray {
        val mapBuilder = CborMap.builder()
        mapBuilder.put(OPTION_KEY_HOST, host)
        mapBuilder.put(OPTION_KEY_PORT, port.toLong())
        return Cbor.encode(
            CborArray.builder()
                .add(METHOD_TYPE)
                .add(METHOD_MAX_VERSION)
                .add(mapBuilder.end().build())
                .end()
                .build()
        )
    }

    override fun toNdefRecord(
        auxiliaryReferences: List<String>,
        role: MdocTransport.Role,
        skipUuids: Boolean
    ): Pair<NdefRecord, NdefRecord>? {
        Logger.w(TAG, "toNdefRecord() not yet implemented")
        return null
    }

    override fun equals(other: Any?): Boolean {
        return other is ConnectionMethodTcp && other.host == host && other.port == port
    }

    override fun toString(): String {
        return "tcp:host=$host:port=$port"
    }

    companion object {
        private const val TAG = "ConnectionMethodTcp"

        // NOTE: 18013-5 only allows positive integers, but our codebase also supports negative
        // ones and this way we won't clash with types defined in the standard.
        const val METHOD_TYPE = -10L
        const val METHOD_MAX_VERSION = 1L

        private const val OPTION_KEY_HOST = 0L
        private const val OPTION_KEY_PORT = 1L
        @JvmStatic
        fun fromDeviceEngagementTcp(encodedDeviceRetrievalMethod: ByteArray): ConnectionMethodTcp? {
            val array = Cbor.decode(encodedDeviceRetrievalMethod).asArray
            val type = array[0].asNumber
            val version = array[1].asNumber
            require(type == METHOD_TYPE)
            if (version > METHOD_MAX_VERSION) {
                return null
            }
            val map = array[2]
            val host = map[OPTION_KEY_HOST].asTstr
            val port = map[OPTION_KEY_PORT].asNumber
            return ConnectionMethodTcp(host, port.toInt())
        }
    }
}
