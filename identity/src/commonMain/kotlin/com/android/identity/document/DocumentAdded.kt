package com.android.identity.document

/**
 * A document was added to the [DocumentStore].
 */
class DocumentAdded(documentId: String): DocumentEvent(documentId) {
    override fun equals(other: Any?) =
        other === this || (other is DocumentAdded && other.documentId == documentId)

    override fun hashCode(): Int = documentId.hashCode() + 1
}
