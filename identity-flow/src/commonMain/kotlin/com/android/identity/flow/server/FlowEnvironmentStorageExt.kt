package com.android.identity.flow.server

import com.android.identity.storage.Storage
import com.android.identity.storage.StorageTable
import com.android.identity.storage.StorageTableSpec

suspend fun FlowEnvironment.getTable(tableSpec: StorageTableSpec): StorageTable {
    return getInterface(Storage::class)!!.getTable(tableSpec)
}