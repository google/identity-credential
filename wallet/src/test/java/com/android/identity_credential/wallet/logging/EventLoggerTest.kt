package com.android.identity_credential.wallet.logging

import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import kotlin.test.assertTrue


@RunWith(Parameterized::class)
class EventLoggerTest(
    private val requesterType: EventLogger.Requester,
    private val shareType: EventLogger.ShareType
) {

    private lateinit var mockStorage: EphemeralStorage
    private lateinit var activityLogger: EventLogger

    @Before
    fun setUp() {
        mockStorage = EphemeralStorage()
        activityLogger = EventLogger(mockStorage)
    }

    @Test
    fun testLoggingEnabled() {
        activityLogger.startLoggingEvents()
        assertTrue(activityLogger.isLoggingEnabled())
    }

    @Test
    fun testLoggingDisabled() {
        activityLogger.stopLoggingEvents()
        assertFalse(activityLogger.isLoggingEnabled())
    }

    @Test
    fun testAddAndDeleteEntries() = runTest {
        activityLogger.startLoggingEvents()

        activityLogger.addMDocPresentationEntry(
            documentId = "doc123",
            sessionTranscript = "sessionTranscript".toByteArray(),
            deviceRequestCbor = "request data".toByteArray(),
            deviceResponseCbor = "response data".toByteArray(),
            requesterType = requesterType,
            shareType = shareType,
        )

        val entries = activityLogger.getEntries("doc123")
        assertTrue(entries.isNotEmpty(), "Entries should not be empty after adding an event")

        activityLogger.deleteEntries(entries)
        val table = mockStorage.getTable(EventLogger.eventTableSpec)
        assertTrue(table.enumerate().isEmpty(), "Storage should be empty after deleting all entries")
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters
        fun data(): Collection<Array<Any>> {
            val data = mutableListOf<Array<Any>>()
            // Add test cases for Anonymous requester
            data.add(arrayOf(EventLogger.Requester.Anonymous(), EventLogger.ShareType.SHARED_IN_PERSON))
            data.add(arrayOf(EventLogger.Requester.Anonymous(), EventLogger.ShareType.SHARED_WITH_APPLICATION))
            data.add(arrayOf(EventLogger.Requester.Anonymous(), EventLogger.ShareType.SHARED_WITH_WEBSITE))
            data.add(arrayOf(EventLogger.Requester.Anonymous(), EventLogger.ShareType.UNKNOWN))

            // Add test cases for Named requester
            data.add(arrayOf(EventLogger.Requester.Named("Bank of America"), EventLogger.ShareType.SHARED_IN_PERSON))
            data.add(arrayOf(EventLogger.Requester.Named("TSA"), EventLogger.ShareType.SHARED_WITH_APPLICATION))

            // Add test cases for Unknown requester
            data.add(arrayOf(EventLogger.Requester.Unknown(), EventLogger.ShareType.SHARED_WITH_WEBSITE))
            data.add(arrayOf(EventLogger.Requester.Unknown(), EventLogger.ShareType.UNKNOWN))

            return data
        }
    }
}