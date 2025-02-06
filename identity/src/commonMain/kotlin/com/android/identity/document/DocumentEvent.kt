package com.android.identity.document

/**
 * Event describing a change in a [Document] in the [DocumentStore] or [DocumentStore] itself.
 *
 * Collect [DocumentStore.eventFlow] to listen to the events.
 */
sealed class DocumentEvent(val documentId: String) {
    override fun toString(): String {
        return "${this::class.simpleName}($documentId)"
    }
}