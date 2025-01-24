package com.android.identity.storage.ephemeral

import com.android.identity.cbor.Bstr
import com.android.identity.storage.base.BaseStorage
import com.android.identity.storage.base.BaseStorageTable
import com.android.identity.storage.StorageTableSpec
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.ByteStringBuilder

class EphemeralStorage(clock: Clock = Clock.System) : BaseStorage(clock) {
    override suspend fun createTable(tableSpec: StorageTableSpec): BaseStorageTable {
        val clockToUse = if (tableSpec.supportExpiration) clock else StoppedClock
        return EphemeralStorageTable(tableSpec, clockToUse)
    }

    suspend fun serialize(): ByteString {
        val out = ByteStringBuilder()
        for (table in enumerateTables()) {
            (table as EphemeralStorageTable).serialize(out)
        }
        return out.toByteString()
    }

    companion object {
        fun deserialize(data: ByteString, clock: Clock = Clock.System): EphemeralStorage {
            var offset = 0
            val bytes = data.toByteArray()
            val tables = mutableListOf<EphemeralStorageTable>()
            while (offset < bytes.size) {
                val (newOffset, table) = EphemeralStorageTable.deserialize(clock, bytes, offset)
                offset = newOffset
                tables.add(table)
            }
            val storage = EphemeralStorage(clock)
            storage.initTables(tables)
            return storage
        }
    }
}