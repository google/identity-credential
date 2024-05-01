package com.android.identity.issuance

/**
 * Issuer-specified configuration used when registering a new document.
 */
data class RegistrationConfiguration(
    /**
     * The identifier to be used in all future communications to refer
     * to the document. This is guaranteed to be unique among all documents
     * issued by the issuer.
     */
    val documentId: String,
    // TODO: include challenge/nonces for setting up E2EE encryption.
)
