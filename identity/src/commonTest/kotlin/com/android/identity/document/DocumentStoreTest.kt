/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.document

import com.android.identity.credential.Credential
import com.android.identity.credential.CredentialFactory
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.crypto.EcCurve
import com.android.identity.document.DocumentStore.EventType
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.Storage
import com.android.identity.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Instant;
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DocumentStoreTest {
    private lateinit var storage: Storage
    private lateinit var secureAreaRepository: SecureAreaRepository
    private lateinit var credentialFactory: CredentialFactory

    // This isn't really used, we only use a single domain.
    private val CREDENTIAL_DOMAIN = "domain"

    @BeforeTest
    fun setup() {
        storage = EphemeralStorage()
        secureAreaRepository = SecureAreaRepository.build {
            add(SoftwareSecureArea.create(storage))
        }
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(
            SecureAreaBoundCredential::class
        ) { document, dataItem ->
            SecureAreaBoundCredential(document).apply { deserialize(dataItem) }
        }
        credentialFactory.addCredentialImplementation(
            Credential::class
        ) { document, dataItem ->
            TestCredential(document).apply { deserialize(dataItem) }
        }
    }

    private fun runDocumentTest(testBody: suspend TestScope.(docStore: DocumentStore) -> Unit) {
        runTest {
            val documentStore = DocumentStore(
                storage,
                secureAreaRepository,
                credentialFactory,
                backgroundScope
            )
            documentStore.withLock {
                testBody(documentStore)
            }
        }        
    }
    
    @Test
    fun testListDocuments() = runDocumentTest { documentStore ->
        assertEquals(0, documentStore.listDocuments().size.toLong())
        for (n in 0..9) {
            documentStore.addDocument(documentStore.createDocument("testDoc$n"))
        }
        assertEquals(10, documentStore.listDocuments().size.toLong())
        documentStore.deleteDocument("testDoc1")
        assertEquals(9, documentStore.listDocuments().size.toLong())
        for (n in 0..9) {
            if (n == 1) {
                assertFalse(documentStore.listDocuments().contains("testDoc$n"))
            } else {
                assertTrue(documentStore.listDocuments().contains("testDoc$n"))
            }
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun testEventFlow() = runTest {
        val documentStore = DocumentStore(
            storage,
            secureAreaRepository,
            credentialFactory,
            backgroundScope
        )

        val events = mutableListOf<Pair<EventType, Document>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            documentStore.eventFlow.toList(events)
        }

        val doc0 = documentStore.withLock {
            val doc0 = documentStore.createDocument("doc0")
            doc0.applicationData.setString("foo", "should not be notified")
            documentStore.addDocument(doc0)
            doc0
        }
        // runCurrent() must run outside documentStore.withLock { ... }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_ADDED, doc0), events.last())

        val (doc1, doc2) = documentStore.withLock {
            val doc1 = documentStore.createDocument("doc1")
            val doc2 = documentStore.createDocument("doc2")
            documentStore.addDocument(doc1)
            Pair(doc1, doc2)
        }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_ADDED, doc1), events.last())

        documentStore.withLock { documentStore.addDocument(doc2) }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_ADDED, doc2), events.last())

        documentStore.withLock { doc2.applicationData.setString("foo", "bar") }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_UPDATED, doc2), events.last())

        documentStore.withLock { doc1.applicationData.setString("foo", "bar") }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_UPDATED, doc1), events.last())

        documentStore.withLock { documentStore.deleteDocument("doc0") }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_DELETED, doc0), events.last())

        documentStore.withLock { documentStore.deleteDocument("doc2") }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_DELETED, doc2), events.last())

        documentStore.withLock { documentStore.deleteDocument("doc1") }
        runCurrent()
        assertEquals(Pair(EventType.DOCUMENT_DELETED, doc1), events.last())
    }

    @Test
    fun testCreationDeletion() = runDocumentTest { documentStore ->
        val document = documentStore.createDocument(
            "testDocument"
        )
        documentStore.addDocument(document)
        assertEquals("testDocument", document.name)

        val document2 = documentStore.lookupDocument("testDocument")
        assertNotNull(document2)
        assertEquals("testDocument", document2.name)

        assertNull(documentStore.lookupDocument("nonExistingDocument"))

        documentStore.deleteDocument("testDocument")
        assertNull(documentStore.lookupDocument("testDocument"))
    }

    /* Validates that the same instance is returned for the same document name. This
     * relies on Document.equals() not being overridden.
     */
    @Test
    fun testCaching() = runDocumentTest { documentStore ->
        val a = documentStore.createDocument("a")
        documentStore.addDocument(a)
        val b = documentStore.createDocument("b")
        documentStore.addDocument(b)
        assertEquals(a, documentStore.lookupDocument("a"))
        assertEquals(a, documentStore.lookupDocument("a"))
        assertEquals(b, documentStore.lookupDocument("b"))
        assertEquals(b, documentStore.lookupDocument("b"))
        documentStore.deleteDocument("a")
        assertNull(documentStore.lookupDocument("a"))
        val a_prime = documentStore.createDocument("a")
        documentStore.addDocument(a_prime)
        assertEquals(a_prime, documentStore.lookupDocument("a"))
        assertEquals(a_prime, documentStore.lookupDocument("a"))
        assertNotEquals(a_prime, a)
        assertEquals(b, documentStore.lookupDocument("b"))
    }

    @Test
    fun testNameSpacedData() = runDocumentTest { documentStore ->
        val document = documentStore.createDocument("testDocument")
        documentStore.addDocument(document)
        val nameSpacedData = NameSpacedData.Builder()
            .putEntryString("ns1", "foo1", "bar1")
            .putEntryString("ns1", "foo2", "bar2")
            .putEntryString("ns1", "foo3", "bar3")
            .putEntryString("ns2", "bar1", "foo1")
            .putEntryString("ns2", "bar2", "foo2")
            .build()
        document.applicationData.setNameSpacedData("documentData", nameSpacedData)
        val loadedDocument = documentStore.lookupDocument("testDocument")
        assertNotNull(loadedDocument)
        assertEquals("testDocument", loadedDocument!!.name)

        // We check that NameSpacedData is preserved across loads by simply comparing the
        // encoded data.
        assertEquals(
            document.applicationData.getNameSpacedData("documentData").toDataItem(),
            loadedDocument.applicationData.getNameSpacedData("documentData").toDataItem()
        )
    }

    @Test
    fun testCredentialUsage() = runDocumentTest { documentStore ->
        val document = documentStore.createDocument("testDocument")
        documentStore.addDocument(document)
        val timeBeforeValidity = Instant.fromEpochMilliseconds(40)
        val timeValidityBegin = Instant.fromEpochMilliseconds(50)
        val timeDuringValidity = Instant.fromEpochMilliseconds(100)
        val timeValidityEnd = Instant.fromEpochMilliseconds(150)
        val timeAfterValidity = Instant.fromEpochMilliseconds(200)

        // By default, we don't have any credentials nor any pending credentials.
        assertEquals(0, document.certifiedCredentials.size.toLong())
        assertEquals(0, document.pendingCredentials.size.toLong())
        assertEquals(0, document.credentialCounter)

        // Since none are certified or even pending yet, we can't present anything.
        assertNull(document.findCredential(CREDENTIAL_DOMAIN, timeDuringValidity))

        // Create ten credentials...
        for (n in 0..9) {
            val credential = TestCredential(
                document,
                null,
                CREDENTIAL_DOMAIN
            )
        }
        assertEquals(0, document.certifiedCredentials.size.toLong())
        assertEquals(10, document.pendingCredentials.size.toLong())
        assertEquals(10, document.credentialCounter)

        // ... and certify all of them
        var n = 0
        for (pendingCredential in document.pendingCredentials) {
            val issuerProvidedAuthenticationData = byteArrayOf(1, 2, n.toByte())
            pendingCredential.certify(
                issuerProvidedAuthenticationData,
                timeValidityBegin,
                timeValidityEnd
            )
            assertEquals(n.toLong(), pendingCredential.credentialCounter)
            n += 1
        }
        assertEquals(10, document.certifiedCredentials.size.toLong())
        assertEquals(0, document.pendingCredentials.size.toLong())

        // If at a time before anything is valid, should not be able to present
        assertNull(document.findCredential(CREDENTIAL_DOMAIN, timeBeforeValidity))

        // Ditto for right after
        assertNull(document.findCredential(CREDENTIAL_DOMAIN, timeAfterValidity))

        // Check we're able to present at a time when the credentials are valid
        var credential = document.findCredential(CREDENTIAL_DOMAIN, timeDuringValidity)
        assertNotNull(credential)
        assertEquals(0, credential!!.usageCount.toLong())

        // B/c of how findCredential(CREDENTIAL_DOMAIN) we know we get the first credential. Match
        // up with expected issuer signed data as per above.
        assertEquals(0.toByte().toLong(), credential.issuerProvidedData[2].toLong())
        assertEquals(0, credential.usageCount.toLong())
        credential.increaseUsageCount()
        assertEquals(1, credential.usageCount.toLong())

        // Simulate nine more presentations, all of them should now be used up
        n = 0
        while (n < 9) {
            credential = document.findCredential(CREDENTIAL_DOMAIN, timeDuringValidity)
            assertNotNull(credential)

            // B/c of how findCredential(CREDENTIAL_DOMAIN) we know we get the credentials after
            // the first one in order. Match up with expected issuer signed data as per above.
            assertEquals(
                (n + 1).toByte().toLong(), credential!!.issuerProvidedData[2].toLong()
            )
            credential.increaseUsageCount()
            n++
        }

        // All ten credentials should now have a use count of 1.
        for (credential in document.certifiedCredentials) {
            assertEquals(1, credential.usageCount.toLong())
        }

        // Simulate ten more presentations
        n = 0
        while (n < 10) {
            credential = document.findCredential(CREDENTIAL_DOMAIN, timeDuringValidity)
            assertNotNull(credential)
            credential!!.increaseUsageCount()
            n++
        }

        // All ten credentials should now have a use count of 2.
        for (credential in document.certifiedCredentials) {
            assertEquals(2, credential.usageCount.toLong())
        }

        val secureArea = secureAreaRepository.getImplementation(SoftwareSecureArea.IDENTIFIER)!!

        // Create and certify five replacements
        n = 0
        while (n < 5) {
            SecureAreaBoundCredential(
                document,
                null,
                CREDENTIAL_DOMAIN,
                secureArea
            ).generateKey(CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256))
            n++
        }
        assertEquals(10, document.certifiedCredentials.size.toLong())
        assertEquals(5, document.pendingCredentials.size.toLong())
        assertEquals(15, document.credentialCounter)
        n = 10
        for (pendingCredential in document.pendingCredentials) {
            pendingCredential.certify(
                ByteArray(0),
                timeValidityBegin,
                timeValidityEnd
            )
            assertEquals(n.toLong(), pendingCredential.credentialCounter)
            n++
        }
        assertEquals(15, document.certifiedCredentials.size.toLong())
        assertEquals(0, document.pendingCredentials.size.toLong())

        // Simulate ten presentations and check we get the newly created ones
        n = 0
        while (n < 10) {
            credential = document.findCredential(CREDENTIAL_DOMAIN, timeDuringValidity)
            assertNotNull(credential)
            assertEquals(0, credential!!.issuerProvidedData.size.toLong())
            credential.increaseUsageCount()
            n++
        }

        // All fifteen credentials should now have a use count of 2.
        for (credential in document.certifiedCredentials) {
            assertEquals(2, credential.usageCount.toLong())
        }

        // Simulate 15 more presentations
        n = 0
        while (n < 15) {
            credential = document.findCredential(CREDENTIAL_DOMAIN, timeDuringValidity)
            assertNotNull(credential)
            credential!!.increaseUsageCount()
            n++
        }

        // All fifteen credentials should now have a use count of 3. This shows that
        // we're hitting the credentials evenly (both old and new).
        for (credential in document.certifiedCredentials) {
            assertEquals(3, credential.usageCount.toLong())
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun testCredentialPersistence() = runTest {
        val documentStore = DocumentStore(
            storage,
            secureAreaRepository,
            credentialFactory,
            backgroundScope
        )
        val (pending, certified) = documentStore.withLock {
            var n: Int
            val timeValidityBegin = Instant.fromEpochMilliseconds(50)
            val timeValidityEnd = Instant.fromEpochMilliseconds(150)
            val document = documentStore.createDocument("testDocument")
            documentStore.addDocument(document)
            assertEquals(0, document.certifiedCredentials.size.toLong())
            assertEquals(0, document.pendingCredentials.size.toLong())

            val secureArea = secureAreaRepository.getImplementation(SoftwareSecureArea.IDENTIFIER)!!

            // Create ten pending credentials and certify four of them
            n = 0
            while (n < 4) {
                SecureAreaBoundCredential(
                    document,
                    null,
                    CREDENTIAL_DOMAIN,
                    secureArea,
                ).generateKey(
                    CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
                )
                n++
            }
            assertEquals(0, document.certifiedCredentials.size.toLong())
            assertEquals(4, document.pendingCredentials.size.toLong())
            n = 0
            for (credential in document.pendingCredentials) {
                // Because we check that we serialize things correctly below, make sure
                // the data and validity times vary for each credential...
                credential.certify(
                    byteArrayOf(1, 2, n.toByte()),
                    Instant.fromEpochMilliseconds(timeValidityBegin.toEpochMilliseconds() + n),
                    Instant.fromEpochMilliseconds(timeValidityEnd.toEpochMilliseconds() + 2 * n)
                )
                for (m in 0 until n) {
                    credential.increaseUsageCount()
                }
                assertEquals(n.toLong(), credential.usageCount.toLong())
                n++
            }
            assertEquals(4, document.certifiedCredentials.size.toLong())
            assertEquals(0, document.pendingCredentials.size.toLong())
            n = 0
            while (n < 6) {
                SecureAreaBoundCredential(
                    document,
                    null,
                    CREDENTIAL_DOMAIN,
                    secureArea
                ).generateKey(
                    CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
                )
                n++
            }
            assertEquals(4, document.certifiedCredentials.size.toLong())
            assertEquals(6, document.pendingCredentials.size.toLong())
            Pair(document.pendingCredentials, document.certifiedCredentials)
        }
        runCurrent()
        val documentStore2 = DocumentStore(
            storage,
            secureAreaRepository,
            credentialFactory,
        )
        documentStore2.withLock {
            val document2 = documentStore2.lookupDocument("testDocument")
            assertNotNull(document2)
            assertEquals(4, document2.certifiedCredentials.size.toLong())
            assertEquals(6, document2.pendingCredentials.size.toLong())

            // Now check that what we loaded matches what we created in-memory just above. We
            // use the fact that the order of the credentials are preserved across save/load.
            val it1 = certified.iterator()
            val it2 = document2.certifiedCredentials.iterator()
            var n = 0
            while (n < 4) {
                val doc1 = it1.next() as SecureAreaBoundCredential
                val doc2 = it2.next() as SecureAreaBoundCredential
                assertEquals(doc1.identifier, doc2.identifier)
                assertEquals(doc1.alias, doc2.alias)
                assertEquals(doc1.validFrom, doc2.validFrom)
                assertEquals(doc1.validUntil, doc2.validUntil)
                assertEquals(doc1.usageCount.toLong(), doc2.usageCount.toLong())
                assertContentEquals(doc1.issuerProvidedData, doc2.issuerProvidedData)
                assertEquals(doc1.getAttestation(), doc2.getAttestation())
                n++
            }
            val itp1 = pending.iterator()
            val itp2 = document2.pendingCredentials.iterator()
            n = 0
            while (n < 6) {
                val doc1 = itp1.next() as SecureAreaBoundCredential
                val doc2 = itp2.next() as SecureAreaBoundCredential
                assertEquals(doc1.identifier, doc2.identifier)
                assertEquals(doc1.alias, doc2.alias)
                assertEquals(doc1.getAttestation(), doc2.getAttestation())
                n++
            }
        }
    }

    @Test
    fun testCredentialValidity() = runDocumentTest { documentStore ->
        val document = documentStore.createDocument("testDocument")
        documentStore.addDocument(document)

        // We want to check the behavior for when the holder has a birthday and the issuer
        // carefully sends half the MSOs to be used before the birthday (with age_in_years set to
        // 17) and half the MSOs for after the birthday (with age_in_years set to 18).
        //
        // The validity periods are carefully set so the MSOs for 17 are have validUntil set to
        // to the holders birthday and the MSOs for 18 are set so validFrom starts at the birthday.
        //
        val timeValidityBegin = Instant.fromEpochMilliseconds(50)
        val timeOfUseBeforeBirthday = Instant.fromEpochMilliseconds(80)
        val timeOfBirthday = Instant.fromEpochMilliseconds(100)
        val timeOfUseAfterBirthday = Instant.fromEpochMilliseconds(120)
        val timeValidityEnd = Instant.fromEpochMilliseconds(150)

        val secureArea = secureAreaRepository.getImplementation(SoftwareSecureArea.IDENTIFIER)!!

        // Create and certify ten credentials. Put age_in_years as the issuer provided data so we can
        // check it below.
        var n = 0
        while (n < 10) {
            var pendingCredential = SecureAreaBoundCredential(
                document,
                null,
                CREDENTIAL_DOMAIN,
                secureArea
            )
            pendingCredential.generateKey(
                CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256),
            )
            n++
        }
        assertEquals(10, document.pendingCredentials.size.toLong())
        n = 0
        for (pendingCredential in document.pendingCredentials) {
            if (n < 5) {
                pendingCredential.certify(byteArrayOf(17), timeValidityBegin, timeOfBirthday)
            } else {
                pendingCredential.certify(byteArrayOf(18), timeOfBirthday, timeValidityEnd)
            }
            n++
        }

        // Simulate ten presentations before the birthday
        n = 0
        while (n < 10) {
            val credential =
                document.findCredential(CREDENTIAL_DOMAIN, timeOfUseBeforeBirthday)
            assertNotNull(credential)
            // Check we got a credential with age 17.
            assertEquals(
                17.toByte().toLong(), credential!!.issuerProvidedData[0].toLong()
            )
            credential.increaseUsageCount()
            n++
        }

        // Simulate twenty presentations after the birthday
        n = 0
        while (n < 20) {
            val credential =
                document.findCredential(CREDENTIAL_DOMAIN, timeOfUseAfterBirthday)
            assertNotNull(credential)
            // Check we got a credential with age 18.
            assertEquals(
                18.toByte().toLong(), credential!!.issuerProvidedData[0].toLong()
            )
            credential.increaseUsageCount()
            n++
        }

        // Examine the credentials. The first five should have use count 2, the
        // latter five use count 4.
        n = 0
        for (credential in document.certifiedCredentials) {
            if (n++ < 5) {
                assertEquals(2, credential.usageCount.toLong())
            } else {
                assertEquals(4, credential.usageCount.toLong())
            }
        }
    }

    @Test
    fun testApplicationData() = runDocumentTest { documentStore ->
        val document = documentStore.createDocument("testDocument")
        documentStore.addDocument(document)
        val appData = document.applicationData
        assertFalse(appData.keyExists("key1"))
        assertFailsWith(IllegalArgumentException::class) { appData.getData("key1") }
        assertFalse(appData.keyExists("key2"))
        assertFailsWith(IllegalArgumentException::class) { appData.getData("key2") }
        appData.setString("key1", "value1")
        assertEquals("value1", document.applicationData.getString("key1"))
        appData.setString("key2", "value2")
        assertEquals("value2", document.applicationData.getString("key2"))
        appData.setData("key3", byteArrayOf(1, 2, 3, 4))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), document.applicationData.getData("key3"))
        appData.setData("key2", null as ByteArray?)
        assertFalse(document.applicationData.keyExists("key2"))
        assertFailsWith(IllegalArgumentException::class) {
            document.applicationData.getData(
                "key2"
            )
        }

        // Load the document again and check that data is still there
        val loadedDocument = documentStore.lookupDocument("testDocument")
        assertNotNull(loadedDocument)
        assertEquals("testDocument", loadedDocument!!.name)
        assertEquals(
            "value1", loadedDocument.applicationData
                .getString("key1")
        )
        assertFalse(loadedDocument.applicationData.keyExists("key2"))
        assertFailsWith(IllegalArgumentException::class) {
            loadedDocument.applicationData.getData(
                "key2"
            )
        }
        assertContentEquals(
            byteArrayOf(1, 2, 3, 4), loadedDocument.applicationData
                .getData("key3")
        )
    }

    @Test
    fun testCredentialApplicationData() = runDocumentTest { documentStore ->
        var document: Document? = documentStore.createDocument("testDocument")
        documentStore.addDocument(document!!)
        val secureArea = secureAreaRepository.getImplementation(SoftwareSecureArea.IDENTIFIER)!!
        for (n in 0..9) {
            val pendingCredential = SecureAreaBoundCredential(
                document,
                null,
                CREDENTIAL_DOMAIN,
                secureArea,
            )
            pendingCredential.generateKey(
                CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
            )
            val value = "bar$n"
            val pendingAppData = pendingCredential.applicationData
            pendingAppData.setString("foo", value)
            pendingAppData.setData("bar", ByteArray(0))
            assertEquals(value, pendingAppData.getString("foo"))
            assertEquals(0, pendingAppData.getData("bar").size.toLong())
            assertFalse(pendingAppData.keyExists("non-existent"))
            assertFailsWith(IllegalArgumentException::class) { pendingAppData.getString("non-existent") }
        }
        assertEquals(10, document.pendingCredentials.size.toLong())
        assertEquals(0, document.certifiedCredentials.size.toLong())

        // Check that it's persisted to disk.
        document = documentStore.lookupDocument("testDocument")
        assertEquals(10, document!!.pendingCredentials.size.toLong())
        var n = 0
        for (pendingCredential in document.pendingCredentials) {
            val value = "bar${n++}"
            val pendingAppData = pendingCredential.applicationData
            assertEquals(value, pendingAppData.getString("foo"))
            assertEquals(0, pendingAppData.getData("bar").size.toLong())
            assertFalse(pendingAppData.keyExists("non-existent"))
            assertFailsWith(IllegalArgumentException::class) { pendingAppData.getString("non-existent") }
        }

        // Certify and check that data carries over from pending Credential
        // to Credential
        n = 0
        for (credential in document.pendingCredentials) {
            val value = "bar${n++}"
            val pendingAppData = credential.applicationData
            assertEquals(value, pendingAppData.getString("foo"))
            assertEquals(0, pendingAppData.getData("bar").size.toLong())
            assertFalse(pendingAppData.keyExists("non-existent"))
            assertFailsWith(IllegalArgumentException::class) { pendingAppData.getString("non-existent") }
            credential.certify(
                byteArrayOf(0, n.toByte()),
                Instant.fromEpochMilliseconds(100),
                Instant.fromEpochMilliseconds(200)
            )
            val appData = credential.applicationData
            assertEquals(value, appData.getString("foo"))
            assertEquals(0, appData.getData("bar").size.toLong())
            assertFalse(appData.keyExists("non-existent"))
            assertFailsWith(IllegalArgumentException::class) { appData.getString("non-existent") }
        }

        // Check it's persisted to disk.
        n = 0
        for (credential in document.certifiedCredentials) {
            val value = "bar${n++}"
            val appData = credential.applicationData
            assertEquals(value, appData.getString("foo"))
            assertEquals(0, appData.getData("bar").size.toLong())
            assertFalse(appData.keyExists("non-existent"))
            assertFailsWith(IllegalArgumentException::class) { appData.getString("non-existent") }
        }
    }

    @Test
    fun testCredentialReplacement() = runDocumentTest { documentStore ->
        val document = documentStore.createDocument("testDocument")
        documentStore.addDocument(document)
        assertEquals(0, document.certifiedCredentials.size.toLong())
        assertEquals(0, document.pendingCredentials.size.toLong())
        val secureArea = secureAreaRepository.getImplementation(SoftwareSecureArea.IDENTIFIER)!!
        for (n in 0..9) {
            val pendingCredential = SecureAreaBoundCredential(
                document,
                null,
                CREDENTIAL_DOMAIN,
                secureArea,
            )
            pendingCredential.generateKey(
                CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
            )
            pendingCredential.certify(
                byteArrayOf(0, n.toByte()),
                Instant.fromEpochMilliseconds(100),
                Instant.fromEpochMilliseconds(200)
            )
        }
        assertEquals(0, document.pendingCredentials.size.toLong())
        assertEquals(10, document.certifiedCredentials.size.toLong())

        // Now replace the fifth credential
        val credToReplace = document.certifiedCredentials[5] as SecureAreaBoundCredential
        assertContentEquals(byteArrayOf(0, 5), credToReplace.issuerProvidedData)
        val pendingCredential = SecureAreaBoundCredential(
            document,
            credToReplace,
            CREDENTIAL_DOMAIN,
            secureArea,
        )
        pendingCredential.generateKey(
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        // ... it's not replaced until certify() is called
        assertEquals(1, document.pendingCredentials.size.toLong())
        assertEquals(10, document.certifiedCredentials.size.toLong())
        pendingCredential.certify(
            byteArrayOf(1, 0),
            Instant.fromEpochMilliseconds(100),
            Instant.fromEpochMilliseconds(200)
        )
        // ... now it should be gone.
        assertEquals(0, document.pendingCredentials.size.toLong())
        assertEquals(10, document.certifiedCredentials.size.toLong())

        // Check that it was indeed the fifth credential that was replaced inspecting issuer-provided data.
        // We rely on some implementation details on how ordering works... also cross-reference
        // with data passed into certify() functions above.
        var count = 0
        for (credential in document.certifiedCredentials) {
            val expectedData = arrayOf(
                byteArrayOf(0, 0),
                byteArrayOf(0, 1),
                byteArrayOf(0, 2),
                byteArrayOf(0, 3),
                byteArrayOf(0, 4),
                byteArrayOf(0, 6),
                byteArrayOf(0, 7),
                byteArrayOf(0, 8),
                byteArrayOf(0, 9),
                byteArrayOf(1, 0)
            )
            assertContentEquals(expectedData[count++], credential.issuerProvidedData)
        }

        // Test the case where the replacement credential is prematurely deleted. The credential
        // being replaced should no longer reference it has a replacement...
        val toBeReplaced = document.certifiedCredentials[0]
        var replacement = SecureAreaBoundCredential(
            document,
            toBeReplaced as SecureAreaBoundCredential,
            CREDENTIAL_DOMAIN,
            secureArea
        )
        replacement.generateKey(
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        assertEquals(toBeReplaced, replacement.replacementFor)
        assertEquals(replacement, toBeReplaced.replacement)
        replacement.delete()
        assertNull(toBeReplaced.replacement)

        // Similarly, test the case where the credential to be replaced is prematurely deleted.
        // The replacement credential should no longer indicate it's a replacement credential.
        replacement = SecureAreaBoundCredential(
            document,
            toBeReplaced,
            CREDENTIAL_DOMAIN,
            secureArea,
        )
        replacement.generateKey(
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        assertEquals(toBeReplaced, replacement.replacementFor)
        assertEquals(replacement, toBeReplaced.replacement)
        toBeReplaced.delete()
        assertNull(replacement.replacementFor)
    }

    class TestCredential: Credential {
        constructor(document: Document, asReplacementFor: Credential?, domain: String)
            : super(document, asReplacementFor, domain) {
                addToDocument()
            }

        constructor(document: Document) : super(document)
    }
}
