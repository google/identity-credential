package com.android.identity.storage.base

import com.android.identity.storage.Storage
import com.android.identity.storage.StorageTable
import com.android.identity.storage.StorageTableSpec
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Base class implementing common functionality for various [Storage] implementations.
 */
abstract class BaseStorage(val clock: Clock): Storage {
    private val lock = Mutex()
    private var schemaTable: BaseStorageTable? = null

    // NB: the key to the tableMap is *lowercased* table name as we want to detect collisions
    // between table names in non-case sensitive manner (some implementations are case-sensitive
    // and others are not). Otherwise we keep original table case for clarity.
    private val tableMap = mutableMapOf<String, TableEntry>()

    override suspend fun getTable(spec: StorageTableSpec): StorageTable {
        if (spec.name.length > MAX_TABLE_NAME_LENGTH) {
            throw IllegalArgumentException("Table name is too long")
        }
        if (!spec.name.matches(safeNameRegex)) {
            throw IllegalArgumentException("Table name contains prohibited characters")
        }
        return lock.withLock {
            ensureTablesLoaded()
            val tableMap = this.tableMap
            val existing = tableMap[spec.name.lowercase()]
            if (existing == null) {
                // Table never existed
                val newTable = createTable(spec)
                tableMap[spec.name.lowercase()] = TableEntry(newTable, spec)
                schemaTable!!.insert(key = spec.name, data = spec.encodeToByteString())
                return@withLock newTable
            }
            if (existing.spec != null && existing.spec !== spec) {
                throw IllegalArgumentException("Multiple table specs for table '${spec.name}'")
            }
            if (existing.table.spec == spec) {
                // Known table with up-to-date schema
                existing.spec = spec
                existing.table
            } else {
                // Known table that needs to be upgraded
                spec.schemaUpgrade(existing.table)
                val upgradedTable = createTable(spec)
                tableMap[spec.name.lowercase()] = TableEntry(upgradedTable, spec)
                schemaTable!!.update(key = spec.name, data = spec.encodeToByteString())
                upgradedTable
            }
        }
    }

    /**
     * API for the derived classes to be able to iterate through all the tables in the storage.
     * This includes a (hidden) schema table defined in [SchemaTableSpec].
     */
    protected suspend fun enumerateTables(): List<BaseStorageTable> {
        return lock.withLock {
            ensureTablesLoaded()
            tableMap.values.map { it.table }
        }
    }

    /**
     * API for the derived classes to be able to initialize newly created [BaseStorage] with
     * the given list of tables. This must includes a (hidden) schema table defined in
     * [SchemaTableSpec].
     */
    protected fun initTables(tables: List<BaseStorageTable>) {
        if (tableMap.isNotEmpty()) {
            throw IllegalStateException("Not an empty Storage")
        }
        for (table in tables) {
            if (table.spec.name == SchemaTableSpec.name) {
                schemaTable = table
            }
            tableMap[table.spec.name.lowercase()] = TableEntry(table)
        }
        if (schemaTable == null && tables.isNotEmpty()) {
            throw IllegalArgumentException("Schema table missing")
        }
    }

    override suspend fun purgeExpired() {
        val tablesToPurge = lock.withLock {
            ensureTablesLoaded()
            tableMap.values.filter { it.table.spec.supportExpiration }.map {it.table} .toList()
        }
        for (table in tablesToPurge) {
            table.purgeExpired()
        }
    }

    private suspend fun ensureTablesLoaded() {
        check(lock.isLocked)
        if (schemaTable == null) {
            val schemaTable = createTable(SchemaTableSpec)
            this.schemaTable = schemaTable
            tableMap[SchemaTableSpec.name.lowercase()] = TableEntry(schemaTable)
            tableMap.putAll(schemaTable.enumerate().map { name ->
                val storedSpec = StorageTableSpec.decodeByteString(schemaTable.get(name)!!)
                check(storedSpec.name == name)
                Pair(name.lowercase(), TableEntry(createTable(storedSpec), null))
            })
        }
    }

    protected abstract suspend fun createTable(tableSpec: StorageTableSpec): BaseStorageTable

    object SchemaTableSpec: StorageTableSpec(
        name = "_SCHEMA",
        supportPartitions = false,
        supportExpiration = false
    ) {
        override suspend fun schemaUpgrade(oldTable: BaseStorageTable) {
            throw IllegalStateException("Schema table can be never upgraded")
        }
    }

    protected object StoppedClock: Clock {
        override fun now(): Instant = Instant.DISTANT_PAST
    }

    private class TableEntry(
        val table: BaseStorageTable,
        // Keep the reference to the spec which was used to instantiate the table to detect
        // duplicate specs for the same name.
        var spec: StorageTableSpec? = null
    )

    companion object {
        private val safeNameRegex = Regex("^[a-zA-Z][a-zA-Z0-9_]*\$")

        const val MAX_KEY_SIZE = 1024
        // NB: MySQL does not allow table names longer than 64 characters and we need 2
        // characters for the prefix. Without prefix we'd have to exclude SQL keywords from
        // valid table names.
        const val MAX_TABLE_NAME_LENGTH = 60
    }
}