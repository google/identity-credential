package com.android.identity.appsupport.ui.digitalcredentials

import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository

/**
 * An interface for interacting with the W3C Digital Credentials API provider
 * on the platform, if available.
 */
interface DigitalCredentials {

    /**
     * Returns whether this API is available on the platform.
     */
    val available: Boolean

    /**
     * Registers all credentials in the given [DocumentStore] with the platform.
     *
     * This also watches the store and updates the registration as documents and credentials
     * are added and removed.
     *
     * @param documentStore the [DocumentStore] to export credentials from.
     * @param documentTypeRepository a [DocumentTypeRepository].
     * @param onCredentialRequest will be invoked during credential presentation if a credential
     *   is selected for presentation.
     */
    suspend fun startExportingCredentials(
        documentStore: DocumentStore,
        documentTypeRepository: DocumentTypeRepository,
    )

    /**
     * Stops exporting credentials.
     *
     * @param documentStore the [DocumentStore] passed to [startExportingCredentials]
     */
    suspend fun stopExportingCredentials(documentStore: DocumentStore)

    /**
     * The default implementation of the [DigitalCredentials] API on the platform.
     */
    object Default: DigitalCredentials {
        override val available: Boolean
            get() = defaultAvailable

        override suspend fun startExportingCredentials(
            documentStore: DocumentStore,
            documentTypeRepository: DocumentTypeRepository,
        ) = defaultStartExportingCredentials(documentStore, documentTypeRepository)

        override suspend fun stopExportingCredentials(documentStore: DocumentStore) =
            defaultStopExportingCredentials(documentStore)
    }
}

internal expect val defaultAvailable: Boolean

internal expect suspend fun defaultStartExportingCredentials(
    documentStore: DocumentStore,
    documentTypeRepository: DocumentTypeRepository,
)

internal expect suspend fun defaultStopExportingCredentials(
    documentStore: DocumentStore,
)