package com.android.identity.mdoc.connectionmethod

import com.android.identity.cbor.Cbor.decode
import com.android.identity.cbor.Cbor.encode
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap

/**
 * Connection method for NFC.
 *
 * @param commandDataFieldMaxLength  the maximum length for the command data field.
 * @param responseDataFieldMaxLength the maximum length of the response data field.
 */
class ConnectionMethodNfc(
    val commandDataFieldMaxLength: Long,
    val responseDataFieldMaxLength: Long
): ConnectionMethod() {
    override fun toString(): String =
        "nfc:cmd_max_length=$commandDataFieldMaxLength:resp_max_length=$responseDataFieldMaxLength"

    override fun toDeviceEngagement(): ByteArray {
        val builder = CborMap.builder()
        builder.put(OPTION_KEY_COMMAND_DATA_FIELD_MAX_LENGTH, commandDataFieldMaxLength)
        builder.put(OPTION_KEY_RESPONSE_DATA_FIELD_MAX_LENGTH, responseDataFieldMaxLength)
        return encode(
            CborArray.builder()
                .add(METHOD_TYPE)
                .add(METHOD_MAX_VERSION)
                .add(builder.end().build())
                .end().build()
        )
    }

    companion object {
        const val METHOD_TYPE = 1L
        const val METHOD_MAX_VERSION = 1L
        private const val OPTION_KEY_COMMAND_DATA_FIELD_MAX_LENGTH = 0L
        private const val OPTION_KEY_RESPONSE_DATA_FIELD_MAX_LENGTH = 1L
        fun fromDeviceEngagementNfc(encodedDeviceRetrievalMethod: ByteArray): ConnectionMethodNfc? {
            val array = decode(encodedDeviceRetrievalMethod)
            val type = array[0].asNumber
            val version = array[1].asNumber
            require(type == METHOD_TYPE)
            if (version > METHOD_MAX_VERSION) {
                return null
            }
            val map = array[2]
            return ConnectionMethodNfc(
                map[OPTION_KEY_COMMAND_DATA_FIELD_MAX_LENGTH].asNumber,
                map[OPTION_KEY_RESPONSE_DATA_FIELD_MAX_LENGTH].asNumber
            )
        }
    }
}