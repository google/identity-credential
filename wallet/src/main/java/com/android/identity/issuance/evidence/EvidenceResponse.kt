package com.android.identity.issuance.evidence

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.annotation.CborSerializable

/**
 * A response to an evidence request.
 */
@CborSerializable
sealed class EvidenceResponse {
    fun toCbor(): ByteArray {
        return Cbor.encode(toDataItem)
    }

    companion object {
        fun fromCbor(encodedValue: ByteArray): EvidenceResponse {
            return fromDataItem(Cbor.decode(encodedValue))
        }
    }
}
