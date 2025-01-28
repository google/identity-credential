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

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborMap
import com.android.identity.credential.Credential
import com.android.identity.credential.CredentialFactory
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.NoRecordStorageException
import com.android.identity.storage.StorageEngine
import com.android.identity.storage.StorageTable
import com.android.identity.util.ApplicationData
import com.android.identity.util.Logger
import com.android.identity.util.SimpleApplicationData
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString

/**
 * This class represents a document created in [DocumentStore].
 *
 * Documents in this store are identified by a name which must be unique
 * per document.
 *
 * Arbitrary data can be stored in documents using the [ApplicationData] returned
 * by [.getApplicationData] which supports key/value pairs with typed values
 * including raw blobs, strings, booleans, numbers, and [NameSpacedData].
 * This data is persisted for the life-time of the document.
 *
 * One typical use of [ApplicationData] is for using it to store the alias
 * of a [SecureArea] key used for communicating with the Issuing Authority
 * issuing data for the document and and proving - via the attestation on the key - that
 * the device is in a known good state (e.g. verified boot is enabled, the OS is at a
 * sufficiently recent patch level, it's communicating with the expected Android
 * application, etc).
 *
 * Each document may have a number of *Credentials*
 * associated with it. These credentials are intended to be used in ways specified by the
 * underlying document format but the general idea is that they are created on
 * the device and then sent to the issuer for certification. The issuer then returns
 * some format-specific data related to the credential.
 *
 * Using Mobile Driving License and MDOCs according
 * to [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) as an example,
 * the credential plays the role of *DeviceKey* and the issuer-signed
 * data includes the *Mobile Security Object* which includes the
 * credential and is signed by the issuer. This is used for anti-cloning and to return data signed
 * by the device. The way it works in this API is that the application can create an [MdocCredential]
 * (using [MdocCredential.create]) tied to a [Document]. With this in hand, the application can use
 * [MdocCredential.attestation] and send the attestation
 * to the issuer for certification. The issuer will then craft document-format
 * specific data (for ISO/IEC 18013-5:2021 it will be a signed MSO which references
 * the public part of the newly created credential) and send it back
 * to the app. The application can then call
 * [Credential.certify] which would add any issuer provided authentication data to the
 * credential and make it ready for use in presentation. To retrieve all credentials
 * which still require certification, use [pendingCredentials], and to retrieve all
 * certified credentials, use [certifiedCredentials].
 *
 * At document presentation time the application first receives the request
 * from a remote reader using a specific document presentation protocol, such
 * as ISO/IEC 18013-5:2021. The details of the document-specific request includes
 * enough information (for example, the *DocType* if using ISO/IEC 18013-5:2021)
 * for the application to locate a suitable [Document] from a [DocumentStore].
 * See [DocumentRequest] for more information about how to generate the response for
 * the remote reader given a [Document] instance.
 *
 * There is nothing mDL/MDOC specific about this type, it can be used for any kind
 * of document regardless of format, presentation, or issuance protocol used.
 *
 * Most [DocumentStore], [Document], and [Credential] APIs require caller to first
 * obtain a [DocumentStore] lock by running the code that accesses these APIs inside
 * [DocumentStore.withLock] (or a convenience shortcut [Document.withLock]). Note that
 * there is a single lock for all documents and credentials in a [DocumentStore]
 * instance and only a single coroutine can hold the lock at the same time.
 *
 * @param name the name of the document which can be used with [DocumentStore].
 * @param storageEngine the [StorageEngine] to use for storing/retrieving documents.
 * @param secureAreaRepository the repository of configured [SecureArea] that can
 * be used.
 * @param store the [DocumentStore] which holds this document.
 * @param credentialFactory the [CredentialFactory] to use for retrieving serialized credentials
 * associated with documents.
 */
class Document private constructor(
    val name: String,
    private val storageTable: StorageTable,
    val secureAreaRepository: SecureAreaRepository,
    private val store: DocumentStore,
    private val credentialFactory: CredentialFactory
) {
    private var addedToStore = false
    private var deleted = false

    internal suspend fun addToStore() {
        checkLocked()
        addedToStore = true
        saveDocument(true)
    }

    /**
     * Convenience method to call [DocumentStore.withLock] for the [DocumentStore]
     * that this document came from.
     */
    suspend fun<T> withLock(block: suspend () -> T): T = store.withLock(block)

    /**
     * Application specific data.
     *
     * Use this object to store additional data an application may want to associate
     * with the credential. Setters and associated getters are
     * enumerated in the [ApplicationData] interface.
     */
    private var _applicationData = SimpleApplicationData { requestSave() }
    val applicationData: ApplicationData
        get() {
            checkLocked()
            return _applicationData
        }

    /**
     * Credentials which still need to be certified
     */
    private var _pendingCredentials = mutableListOf<Credential>()
    val pendingCredentials: List<Credential>
        // Return shallow copy b/c backing field may get modified if certify() or delete() is called.
        get() {
            checkLocked()
            return _pendingCredentials.toList()
        }

    /**
     * Certified credentials.
     */
    private var _certifiedCredentials = mutableListOf<Credential>()
    val certifiedCredentials: List<Credential>
        // Return shallow copy b/c backing field may get modified if certify() or delete() is called.
        get() {
            checkLocked()
            return _certifiedCredentials.toList()
        }

    /**
     * Credential counter.
     *
     * This is a number which starts at 0 and is increased by one for every credential created.
     */
    var credentialCounter: Long = 0
        private set

    fun checkLocked() {
        store.checkLocked()
    }

    internal fun requestSave() {
        if (!addedToStore) {
            return
        }
        // TODO: batch it a bit
        store.coroutineScope.launch {
            store.withLock {
                try {
                    saveDocument(false)
                } catch (err: NoRecordStorageException) {
                    // Document was removed or never added to the store?
                    if (deleted || !addedToStore) {
                        Logger.i(TAG,
                            "Attempt to save a document '$name' that was not added to the store or was deleted")
                    } else {
                        Logger.e(TAG, "Consistency error: document '$name' does not exist anymore")
                    }
                }
            }
        }
    }

    internal suspend fun saveDocument(initialSave: Boolean) {
        checkLocked()
        if (!addedToStore) {
            return
        }
        val t0 = Clock.System.now()
        val mapBuilder = CborMap.builder().apply {
            put("applicationData", _applicationData.encodeAsCbor())
            val pendingCredentialsArrayBuilder = putArray("pendingCredentials")
            for (pendingCredential in _pendingCredentials) {
                pendingCredentialsArrayBuilder.add(pendingCredential.toCbor())
            }
            val certifiedCredentialsArrayBuilder = putArray("certifiedCredentials")
            for (certifiedCredential in _certifiedCredentials) {
                certifiedCredentialsArrayBuilder.add(certifiedCredential.toCbor())
            }
            put("credentialCounter", credentialCounter)
        }
        val bytes = ByteString(Cbor.encode(mapBuilder.end().build()))
        if (initialSave) {
            storageTable.insert(name, bytes)
        } else {
            storageTable.update(name, bytes)
        }
        val t1 = Clock.System.now()

        // Saving a document is a costly affair (often more than 100ms) so log when we're doing
        // this so application developers are aware. This is to deter applications from storing
        // ephemeral data in the ApplicationData instances of the document and our associated
        // credentials.
        val durationMillis = t1.toEpochMilliseconds() - t0.toEpochMilliseconds()
        Logger.i(TAG, "Saved document '$name' to disk in $durationMillis msec")
        if (!initialSave) {
            store.emitOnDocumentChanged(this)
        }
    }

    private suspend fun loadDocument(): Boolean {
        checkLocked()
        val data = storageTable.get(name) ?: return false
        val map = Cbor.decode(data.toByteArray())

        _applicationData = SimpleApplicationData
            .decodeFromCbor(map["applicationData"].asBstr) {
                requestSave()
            }

        _pendingCredentials = ArrayList()
        for (item in map["pendingCredentials"].asArray) {
            _pendingCredentials.add(credentialFactory.createCredential(this, item))
        }
        _certifiedCredentials = ArrayList()
        for (item in map["certifiedCredentials"].asArray) {
            _certifiedCredentials.add(credentialFactory.createCredential(this, item))
        }
        credentialCounter = map["credentialCounter"].asNumber
        addedToStore = true
        return true
    }

    internal suspend fun deleteDocument() {
        checkLocked()
        _pendingCredentials.clear()
        _certifiedCredentials.clear()
        storageTable.delete(name)
        deleted = true
    }

    /**
     * Finds a suitable certified credential to use.
     *
     * @param domain The domain to pick the credential from.
     * @param now Pass current time to ensure that the selected slot's validity period or
     * `null` to not consider validity times.
     * @return A credential which can be used for signing or `null` if none was found.
     */
    fun findCredential(
        domain: String,
        now: Instant?
    ): Credential? {
        checkLocked()
        var candidate: Credential? = null
        _certifiedCredentials.filter {
            it.domain == domain && (
                    now == null || (now >= it.validFrom && now <= it.validUntil)
                    )
        }.forEach { credential ->
            // If we already have a candidate, prefer this one if its usage count is lower
            candidate?.let { candidateCredential ->
                if (credential.usageCount < candidateCredential.usageCount) {
                    candidate = credential
                }
            } ?: run {
                candidate = credential
            }

        }
        return candidate
    }

    // Adds a newly created [Credential] to the document, returns the assigned credential counter
    internal fun addCredential(
        credential: Credential,
    ) : Long {
        checkLocked()
        val assignedCounter = credentialCounter++
        _pendingCredentials.add(credential)
        return assignedCounter
    }

    /**
     * Goes through all credentials and deletes the ones which are invalidated.
     */
    suspend fun deleteInvalidatedCredentials() {
        checkLocked()
        for (pendingCredential in pendingCredentials) {
            deleteIfInvalidated(pendingCredential, "pending credential")
        }
        for (credential in certifiedCredentials) {
            deleteIfInvalidated(credential)
        }
    }

    private suspend fun deleteIfInvalidated(credential: Credential, credentialType: String = "credential") {
        checkLocked()
        try {
            if (credential.isInvalidated()) {
                Logger.i(TAG, "Deleting invalidated $credentialType ${credential.identifier}")
                credential.delete()
            }
        } catch (err: IllegalArgumentException) {
            // TODO: watch this and figure out what causes this state (race condition?)
            // Once we are in this state, there is no other good way to recover. It is important
            // that secure area implementations do not use IllegalArgumentException for transient
            // errors (like server connections).
            Logger.e(TAG, "Error accessing $credentialType ${credential.identifier}, deleting it", err)
            credential.delete()
        }
    }

    /**
     * Returns whether a usable credential exists at a given point in time.
     *
     * @param at the point in time to check for.
     * @returns `true` if an usable credential exists for the given time, `false` otherwise
     */
    fun hasUsableCredential(at: Instant = Clock.System.now()): Boolean {
        checkLocked()
        val credentials = certifiedCredentials
        if (credentials.isEmpty()) {
            return false
        }
        for (credential in credentials) {
            if (at >= credential.validFrom && at < credential.validUntil) {
                return true
            }
        }
        return false
    }

    data class UsableCredentialResult(
        val numCredentials: Int,
        val numCredentialsAvailable: Int
    )

    /**
     * Returns whether an usable credential exists at a given point in time.
     *
     * @param at the point in time to check for.
     * @returns `true` if an usable credential exists for the given time, `false` otherwise
     */
    fun countUsableCredentials(at: Instant = Clock.System.now()): UsableCredentialResult {
        checkLocked()
        val credentials = certifiedCredentials
        if (credentials.isEmpty()) {
            return UsableCredentialResult(0, 0)
        }
        var numCredentials = 0
        var numCredentialsAvailable = 0
        for (credential in credentials) {
            numCredentials++
            val validFrom = credential.validFrom
            val validUntil = credential.validUntil
            if (at >= validFrom && at < validUntil) {
                if (credential.usageCount == 0) {
                    numCredentialsAvailable++
                }
            }
        }
        return UsableCredentialResult(numCredentials, numCredentialsAvailable)
    }

    internal suspend fun removeCredential(credential: Credential) {
        checkLocked()
        val listToModify = if (credential.isCertified) _certifiedCredentials
            else _pendingCredentials
        check(listToModify.remove(credential)) { "Error removing credential" }

        if (credential.replacementForIdentifier != null) {
            for (cred in _certifiedCredentials) {
                if (cred.identifier == credential.replacementForIdentifier) {
                    cred.replacementIdentifier = null
                    break
                }
            }
        }

        if (credential.replacementIdentifier != null) {
            for (pendingCred in _pendingCredentials) {
                if (pendingCred.identifier == credential.replacementIdentifier) {
                    pendingCred.replacementForIdentifier = null
                    break
                }
            }
        }
        saveDocument(false)
    }

    /**
     * Certifies the credential. Should only be called by [Credential.certify]
     *
     * @param credential The credential to certify.
     */
    internal suspend fun certifyPendingCredential(
        credential: Credential
    ): Credential {
        checkLocked()
        check(_pendingCredentials.remove(credential)) { "Error removing credential from pending list" }
        _certifiedCredentials.add(credential)
        saveDocument(false)
        return credential
    }

    companion object {
        private const val TAG = "Document"

        // Called by DocumentStore.createDocument().
        internal suspend fun create(
            storageTable: StorageTable,
            secureAreaRepository: SecureAreaRepository,
            name: String,
            store: DocumentStore,
            credentialFactory: CredentialFactory
        ): Document =
            Document(name, storageTable, secureAreaRepository, store, credentialFactory).apply {
                saveDocument(true)
            }

        // Called by DocumentStore.lookupDocument().
        internal suspend fun lookup(
            storageTable: StorageTable,
            secureAreaRepository: SecureAreaRepository,
            name: String,
            store: DocumentStore,
            credentialFactory: CredentialFactory
        ): Document? = Document(name, storageTable, secureAreaRepository, store, credentialFactory).run {
            try {
                checkLocked()
                if (!loadDocument()) {
                    return null
                }
            } catch (err: Exception) {
                Logger.e(TAG, "Error loading document $name, ignoring it", err)
                // TODO: delete it from storage?
                return null
            }
            return this
        }
    }
}