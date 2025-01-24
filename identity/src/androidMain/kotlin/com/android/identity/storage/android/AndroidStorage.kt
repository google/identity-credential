package com.android.identity.storage.android

import android.database.sqlite.SQLiteDatabase
import com.android.identity.storage.Storage
import com.android.identity.storage.base.BaseStorage
import com.android.identity.storage.base.BaseStorageTable
import com.android.identity.storage.StorageTableSpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.datetime.Clock
import kotlin.coroutines.CoroutineContext

/**
 * [Storage] implementation based on Android [SQLiteDatabase] API.
 */
class AndroidStorage: BaseStorage {
    private val coroutineContext: CoroutineContext
    private val databaseFactory: () -> SQLiteDatabase
    internal val keySize: Int
    private var database: SQLiteDatabase? = null

    constructor(
        database: SQLiteDatabase,
        clock: Clock = Clock.System,
        coroutineContext: CoroutineContext = Dispatchers.IO,
        keySize: Int = 9
    ): super(clock) {
        this.database = database
        databaseFactory = { throw IllegalStateException("unexpected call") }
        this.coroutineContext = coroutineContext
        this.keySize = keySize
    }

    constructor(
        databasePath: String?,
        clock: Clock = Clock.System,
        coroutineContext: CoroutineContext = Dispatchers.IO,
        keySize: Int = 9
    ): super(clock) {
        databaseFactory = {
            SQLiteDatabase.openOrCreateDatabase(databasePath ?: ":memory:", null)
        }
        this.coroutineContext = coroutineContext
        this.keySize = keySize
    }

    override suspend fun createTable(tableSpec: StorageTableSpec): BaseStorageTable {
        if (database == null) {
            database = databaseFactory()
        }
        val table = AndroidStorageTable(this, tableSpec)
        table.init()
        return table
    }

    internal suspend fun<T> withDatabase(
        block: suspend CoroutineScope.(database: SQLiteDatabase) -> T
    ): T {
        return CoroutineScope(coroutineContext).async {
            block(database!!)
        }.await()
    }
}