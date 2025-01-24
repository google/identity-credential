package com.android.identity_credential.wallet.logging

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.storage.Storage
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.Logger
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString

/**
 * Event Logging facility.
 *
 * This saves events in Cbor format using storageEngine.
 */

private const val TAG = "EventLogger"

private var eventLoggingEnabled = false

class EventLogger(private val storage: Storage) {
    companion object {
        internal val eventTableSpec = StorageTableSpec(
            name = "Events",
            supportExpiration = false,
            supportPartitions = false
        )
    }

    fun startLoggingEvents() {
        eventLoggingEnabled = true
        Logger.i(TAG, "Enabling event logging")
    }

    fun stopLoggingEvents() {
        eventLoggingEnabled = false
        Logger.i(TAG, "Disabling event logging")
    }

    fun isLoggingEnabled(): Boolean {
        return eventLoggingEnabled
    }

    @CborSerializable
    sealed class Requester {
        class Anonymous : Requester() {
            override fun toString() = "Anonymous requester"
        }

        class Unknown : Requester() {
            override fun toString() = "Unknown requester"
        }

        class Named(val name: String) : Requester() {
            override fun toString() = name
        }
    }

    enum class ShareType(val displayName: String) {
        SHARED_IN_PERSON("Shared in-person"),
        SHARED_WITH_APPLICATION("Shared with application"),
        SHARED_WITH_WEBSITE("Shared with website"),
        UNKNOWN("Unknown");

        override fun toString(): String {
            return displayName
        }
    }

    @CborSerializable
    data class RequesterInfo(
        val requester: Requester,
        val shareType: ShareType
    )

    suspend fun addMDocPresentationEntry(
        documentId: String,
        sessionTranscript: ByteArray,
        deviceRequestCbor: ByteArray,
        deviceResponseCbor: ByteArray,
        requesterType: Requester,
        shareType: ShareType
    ) {
        if (!eventLoggingEnabled) {
            Logger.i(TAG, "Logging is disabled")
            return // Exit immediately if logging is disabled
        }

        val timestamp = Clock.System.now()
        val requesterInfo = RequesterInfo(
            requester = requesterType,
            shareType = shareType
        )
        val serializedEntry: ByteArray

        val event = MdocPresentationEvent(
            timestamp = timestamp,
            documentId = documentId,
            sessionTranscript = sessionTranscript,
            deviceRequestCbor = deviceRequestCbor,
            deviceResponseCbor = deviceResponseCbor,
            requesterInfo = requesterInfo
        )
        serializedEntry = event.toCbor()

        storage.getTable(eventTableSpec).insert(key = null, ByteString(serializedEntry))
    }

    suspend fun getEntries(documentId: String): List<Event> {
        val entries = mutableListOf<Event>()
        val table = storage.getTable(eventTableSpec)
        for (key in table.enumerate()) {
            val value = table.get(key)
            if (value != null) {
                try {
                    val event = Event.fromCbor(value.toByteArray())
                    event.id = key
                    when {
                        event is MdocPresentationEvent && event.documentId == documentId -> entries.add(event)
                        event is DocumentUpdateCheckEvent && event.documentId == documentId -> entries.add(event)
                    }
                } catch(e: IllegalStateException) {
                    Logger.w(TAG, "Failed to deserialize event for key: $key", e)
                }
            }
        }
        return entries.sortedBy { event -> event.timestamp }
    }

    suspend fun deleteEntries(entries: List<Event>) {
        val table = storage.getTable(eventTableSpec)
        for (entry in entries) {
            table.delete(entry.id)
            Logger.i(TAG, "Deleted entry with timestamp: ${entry.timestamp}")
        }
    }

    suspend fun deleteEntriesForDocument(documentId: String) {
        val entriesToDelete = getEntries(documentId)
        deleteEntries(entriesToDelete)
        Logger.i(TAG, "Deleted all entries for documentId: $documentId")
    }
}