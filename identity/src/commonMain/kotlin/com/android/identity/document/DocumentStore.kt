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

import com.android.identity.credential.CredentialFactory
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.Storage
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Class for storing real-world identity documents.
 *
 * This class is designed for storing real-world identity documents such as
 * Mobile Driving Licenses (mDL) as specified in ISO/IEC 18013-5:2021. It is however
 * not tied to that specific document format and is designed to hold any kind of
 * document, regardless of format, presentation-, or issuance-protocol used.
 *
 * This code relies on a Secure Area for keys and this dependency is abstracted
 * by the [SecureArea] interface and allows the use of different [SecureArea]
 * implementations for *Authentication Keys*) associated with documents stored
 * in the Document Store.
 *
 * It is guaranteed that once a document is created with [createDocument],
 * each subsequent call to [lookupDocument] will return the same
 * [Document] instance.
 *
 * For more details about documents stored in a [DocumentStore] see the
 * [Document] class.
 *
 * @property storage the [Storage] to use for storing/retrieving documents.
 * @property secureAreaRepository the repository of configured [SecureArea] that can
 * be used.
 * @property credentialFactory the [CredentialFactory] to use for retrieving serialized credentials
 * associated with documents.
 */
class DocumentStore(
    val storage: Storage,
    internal val secureAreaRepository: SecureAreaRepository,
    internal val credentialFactory: CredentialFactory,
    internal val documentMetadataFactory: DocumentMetadataFactory
) {
    // Use a cache so the same instance is returned by multiple lookupDocument() calls.
    // Cache is protected by the lock. Once the document is loaded it is never evicted.
    private val lock = Mutex()
    private val documentCache = mutableMapOf<String, Document>()

    /**
     * Creates a new document.
     *
     * If a document with the given identifier already exists, it will be deleted prior to
     * creating the document.
     *
     * @return A newly created document.
     */
    suspend fun createDocument(
        metadataInitializer: suspend (metadata: DocumentMetadata) -> Unit = {}
    ): Document {
        val document = Document.create(this)
        document.metadata = documentMetadataFactory(document.identifier,null, document::saveMetadata)
        metadataInitializer(document.metadata)
        lock.withLock {
            documentCache[document.identifier] = document
        }
        emitOnDocumentAdded(document.identifier)
        return document
    }

    /**
     * Looks up a document in the store.
     *
     * @param name the identifier of the document.
     * @return the document or `null` if not found.
     */
    suspend fun lookupDocument(name: String): Document? {
        return lock.withLock {
            documentCache.getOrPut(name) {
                Document.lookup(this, name) ?: return@withLock null
            }
        }
    }

    /**
     * Lists all documents in the store.
     *
     * @return list of all the document names in the store.
     */
    suspend fun listDocuments(): List<String> {
        // right now lock is not required
        return Document.enumerate(this)
    }

    /**
     * Deletes a document.
     *
     * If the document doesn't exist this does nothing.
     *
     * @param name the identifier of the document.
     */
    suspend fun deleteDocument(name: String) {
        lookupDocument(name)?.let { document ->
            document.deleteDocument()
            documentCache.remove(name)
        }
    }

    private val _eventFlow = MutableSharedFlow<DocumentEvent>()

    /**
     * A [SharedFlow] which can be used to listen for when credentials are added and removed
     * from the store as well as when credentials in the store have been updated.
     */
    val eventFlow
        get() = _eventFlow.asSharedFlow()


    private suspend fun emitOnDocumentAdded(documentId: String) {
        _eventFlow.emit(DocumentAdded(documentId))
    }

    internal suspend fun emitOnDocumentDeleted(documentId: String) {
        _eventFlow.emit(DocumentDeleted(documentId))
    }

    internal suspend fun emitOnDocumentChanged(documentId: String) {
        _eventFlow.emit(DocumentUpdated(documentId))
    }

    companion object {
        const val TAG = "DocumentStore"
    }
}