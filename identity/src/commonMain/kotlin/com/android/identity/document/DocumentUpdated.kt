package com.android.identity.document

import com.android.identity.credential.Credential

/**
 * A document in the [DocumentStore] was updated.
 *
 * This includes changes to [DocumentMetadata] persistent state or to a [Credential] that
 * belongs to the [Document].
 */
class DocumentUpdated(documentId: String): DocumentEvent(documentId) {
    override fun equals(other: Any?) =
        other === this || (other is DocumentUpdated && other.documentId == documentId)

    override fun hashCode(): Int = documentId.hashCode() + 3
}