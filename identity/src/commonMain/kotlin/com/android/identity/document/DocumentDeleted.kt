package com.android.identity.document

/**
 * A document was deleted from the [DocumentStore].
 */
class DocumentDeleted(documentId: String): DocumentEvent(documentId) {
    override fun equals(other: Any?) =
        other === this || (other is DocumentDeleted && other.documentId == documentId)

    override fun hashCode(): Int = documentId.hashCode() + 2
}