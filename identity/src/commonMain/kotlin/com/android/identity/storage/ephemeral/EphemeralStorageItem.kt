package com.android.identity.storage.ephemeral

import com.android.identity.cbor.annotation.CborSerializable
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString

// TODO: make this class internal, needs a fix for the annotation processor
@CborSerializable
class EphemeralStorageItem(
    val partitionId: String?,
    val key: String,
    var value: ByteString = EphemeralStorageTable.EMPTY,
    var expiration: Instant = Instant.DISTANT_FUTURE
): Comparable<EphemeralStorageItem> {
    override fun compareTo(other: EphemeralStorageItem): Int {
        val c = if (partitionId == null) {
            if (other.partitionId == null) 0 else -1
        } else if (other.partitionId == null) {
            1
        } else {
            partitionId.compareTo(other.partitionId)
        }
        return if (c != 0) c else key.compareTo(other.key)
    }

    fun expired(now: Instant): Boolean {
        return expiration < now
    }

    companion object
}