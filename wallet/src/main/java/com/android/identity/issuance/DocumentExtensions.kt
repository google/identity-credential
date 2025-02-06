package com.android.identity.issuance

import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.document.Document

/**
 * A set of extensions on the [Document] type for working with the [IssuingAuthority]
 * and related classes.
 */
object DocumentExtensions {
    const val TAG = "DocumentExtensions"

    val Document.walletDocumentMetadata: WalletDocumentMetadata
        get() = metadata as WalletDocumentMetadata

    /** The identifier for the [IssuingAuthority] the credential belongs to */
    val Document.issuingAuthorityIdentifier: String
        get() = walletDocumentMetadata.issuingAuthorityIdentifier

    /**
     * The identifier for the credential, as assigned by the issuer
     *
     * This is the _credentialId_ value used in [IssuingAuthority] when communicating
     * with the issuing authority.
     */
    val Document.documentIdentifier: String
        get() = walletDocumentMetadata.documentIdentifier

    /** The slot in the Direct Access applet this document uses */
    val Document.documentSlot: Int
        get() = walletDocumentMetadata.documentSlot

    /** Returns whether or not the document has any [DirectAccessCredential]s associated with it */
    suspend fun Document.hasDirectAccessCredentials(): Boolean {
        for (credential in getCredentials()) {
            if (credential is DirectAccessCredential) {
                return true
            }
        }
        return false
    }

    /**
     * The number of times a [DocumentConfiguration] has been downloaded from the issuer.
     */
    val Document.numDocumentConfigurationsDownloaded: Long
        get() = walletDocumentMetadata.numDocumentConfigurationsDownloaded

    /** The most recent [DocumentConfiguration] received from the issuer */
    val Document.documentConfiguration: DocumentConfiguration
        get() = walletDocumentMetadata.documentConfiguration

    /** The most recent [IssuingAuthorityConfiguration] received from the issuer */
    val Document.issuingAuthorityConfiguration: IssuingAuthorityConfiguration
        get() = walletDocumentMetadata.issuingAuthorityConfiguration

    /**
     * The most recent [DocumentState] received from the issuer.
     *
     * This doesn't ping the issuer so the information may be stale. Applications can consult
     * the [DocumentState.timestamp] field to figure out the age of the state and use
     * [WalletDocumentMetadata.refreshState] to refresh it directly from the issuer server.
     */
    val Document.state: DocumentState?
        get() = walletDocumentMetadata.state
}
