package com.android.identity.issuance


import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.document.Document
import com.android.identity.issuance.remote.WalletServerProvider

/**
 * A set of extensions on the [Document] type for working with the [IssuingAuthority]
 * and related classes.
 */
object DocumentExtensions {
    const val TAG = "DocumentExtensions"

    /** The identifier for the [IssuingAuthority] the credential belongs to */
    var Document.issuingAuthorityIdentifier: String
        get() = applicationData.getString("issuingAuthorityIdentifier")
        set(value) { applicationData.setString("issuingAuthorityIdentifier", value) }

    /**
     * The identifier for the credential, as assigned by the issuer
     *
     * This is the _credentialId_ value used in [IssuingAuthority] when communicating
     * with the issuing authority.
     */
    var Document.documentIdentifier: String
        get() = applicationData.getString("credentialIdentifier")
        set(value) { applicationData.setString("credentialIdentifier", value) }

    /** The slot in the Direct Access applet this document uses */
    var Document.documentSlot: Int
        get() = applicationData.getNumber("documentSlot").toInt()
        set(value) { applicationData.setNumber("documentSlot", value.toLong()) }

    /** Returns whether or not the document has any [DirectAccessCredential]s associated with it */
    val Document.hasDirectAccessCredentials: Boolean
        get() {
            for (credential in (pendingCredentials + certifiedCredentials)) {
                if (credential is DirectAccessCredential) {
                    return true
                }
            }
            return false
        }

    /**
     * The number of times a [DocumentConfiguration] has been downloaded from the issuer.
     */
    var Document.numDocumentConfigurationsDownloaded: Long
        get() {
            if (!applicationData.keyExists("numDocumentConfigurationsDownloaded")) {
                return 0
            }
            return applicationData.getNumber("numDocumentConfigurationsDownloaded")
        }
        set(value) { applicationData.setNumber("numDocumentConfigurationsDownloaded", value) }

    /** The most recent [DocumentConfiguration] received from the issuer */
    var Document.documentConfiguration: DocumentConfiguration
        get() = DocumentConfiguration.fromCbor(applicationData.getData("documentConfiguration"))
        set(value) { applicationData.setData("documentConfiguration", value.toCbor()) }

    /** The most recent [IssuingAuthorityConfiguration] received from the issuer */
    var Document.issuingAuthorityConfiguration: IssuingAuthorityConfiguration
        get() = IssuingAuthorityConfiguration.fromCbor(applicationData.getData("issuingAuthorityConfiguration"))
        set(value) { applicationData.setData("issuingAuthorityConfiguration", value.toCbor()) }

    /**
     * The most recent [DocumentState] received from the issuer.
     *
     * This doesn't ping the issuer so the information may be stale. Applications can consult
     * the [DocumentState.timestamp] field to figure out the age of the state and use
     * [Document.refreshState] to refresh it directly from the issuer server.
     */
    var Document.state: DocumentState
        get() = DocumentState.fromCbor(applicationData.getData("credentialState"))
        set(value) { applicationData.setData("credentialState", value.toCbor()) }

    /**
     * Gets the document state from the Issuer and updates the [.state] property with the value.
     *
     * Unlike reading from the [.state] property, this performs network I/O to communicate
     * with the issuer.
     *
     * If the document doesn't exist (for example it could have been deleted recently) the
     * condition in [Document.state] is set to [DocumentCondition.NO_SUCH_DOCUMENT].
     *
     * @param walletServerProvider the wallet server provider.
     */
    suspend fun Document.refreshState(walletServerProvider: WalletServerProvider) {
        val issuer = walletServerProvider.getIssuingAuthority(issuingAuthorityIdentifier)
        this.state = issuer.getState(documentIdentifier)
    }
}
