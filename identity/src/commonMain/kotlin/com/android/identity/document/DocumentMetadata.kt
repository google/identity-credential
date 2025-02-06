package com.android.identity.document

import kotlinx.io.bytestring.ByteString

/**
 * An object that is associated with every [Document] in the [DocumentStore]; it is referenced by
 * [Document.metadata] field.
 *
 * An application should implement this interface and use it to store application-specific data.
 * A factory function for [DocumentMetadata] is passed as a parameter to [DocumentStore]
 * constructor. An application must implement at least the members in this interface but
 * should be free to add other application-specific data it may want to associate with
 * the document (e.g. which issuer this document came from).
 *
 * Each [Document] has an associated [DocumentMetadata] instance. This instance stays the same
 * for the lifetime of the [Document]. Its state should be saved to the persistent storage
 * every time it changes (see `saveFn` parameter to [DocumentMetadataFactory]), so that it can
 * be loaded in the future.
 *
 * Several fields (such as [displayName]) are predefined, so that common high-level utilities
 * in the UI layer such as can display something meaningful to the end user. Text strings are
 * presented to the user as-is, so they should be short and may need to be localized.
 */
interface DocumentMetadata {
    /** Whether the document is provisioned, i.e. issuer is ready to provide credentials. */
    val provisioned: Boolean

    /** User-facing name if this specific [Document] instance, e.g. "John's Passport". */
    val displayName: String?

    /** User-facing name of this document type, e.g. "Utopia Passport". */
    val typeDisplayName: String?

    /**
     * An image that represents this document to the user in the UI. Generally, the aspect
     * ration of 1.586 is expected (based on ID-1 from the ISO/IEC 7810). PNG format is expected
     * and transparency is supported. */
    val cardArt: ByteString?

    /**
     * An image that represents the issuer of the document in the UI, e.g. passport office logo.
     * PNG format is expected, transparency is supported and square aspect ration is preferred.
     */
    val issuerLogo: ByteString?

    // TODO: remove this?
    val nameSpacedData: NameSpacedData
        get() = emptyNamespacedData

    /**
     * Called when the document that this [DocumentMetadata] associated with is deleted.
     */
    suspend fun documentDeleted()

    companion object {
        internal val emptyNamespacedData = NameSpacedData.Builder().build()
    }
}

/**
 * Function that creates an instance of [DocumentMetadata].
 *
 * - `documentId` is [Document.identifier] for which [DocumentMetadata] is created
 * - `data` is data saved by the previously-existing [DocumentMetadata] for this document
 * - `saveFn` is a function that saves the state of this [DocumentMetadata] instance to the
 *    persistent storage
 *
 * There are two scenarios when [DocumentMetadata] is created.
 *
 * The first scenario is when a new [Document] is created using [DocumentStore.createDocument].
 * In this case, `data` is `null`. Once [DocumentMetadata] is created, it is initialized using
 * function passed to [DocumentStore.createDocument] method.
 *
 * The second scenario is when a previously-existing [Document] is loaded from the storage. In this
 * case `data` is equal to the byte string that was last saved by the previously-existing
 * [DocumentMetadata] for this document. If no data was saved, `data` is set to the empty byte
 * string.
 *
 * When the state of the [DocumentMetadata] instance changes, it should call `saveFn` and
 * save its state to the persistent storage, so it can be loaded in the future, however exact
 * timing of `saveFn` call is entirely up to the application.
 *
 * Additionally, every time `saveFn` is called, a [DocumentUpdated] event is emitted on
 * [DocumentStore.eventFlow].
 */
typealias DocumentMetadataFactory = suspend (
    documentId: String,
    data: ByteString?,
    saveFn: suspend (data: ByteString) -> Unit
) -> DocumentMetadata