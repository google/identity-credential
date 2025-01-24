package com.android.identity.issuance

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.issuance.evidence.DirectAccessDocumentConfiguration

/**
 * The configuration data for a specific document.
 *
 * This is made available by the issuer after identifying and proofing the application and
 * the data in here may contain data specific to the application.
 */
@CborSerializable
data class DocumentConfiguration(
    /**
     * Display-name for the document e.g. "Erika's Driving License".
     */
    val displayName: String,

    /**
     * Display-name for the type e.g. "Driving License".
     */
    val typeDisplayName: String,

    /**
     * Card-art for the document.
     *
     * This should resemble a physical card and be the same aspect ratio (3 3⁄8 in × 2 1⁄8 in,
     * see also ISO/IEC 7810 ID-1).
     */
    val cardArt: ByteArray,

    /**
     * If `true`, require that the user authenticates to view document information.
     *
     * The authentication required will be the same as from one of the credentials
     * in the document e.g. LSKF/Biometric or passphrase.
     */
    val requireUserAuthenticationToViewDocument: Boolean,

    /**
     * If not null, credentials of type [MdocCredential] are available and this
     * object contains more information and data related to this.
     */
    val mdocConfiguration: MdocDocumentConfiguration?,

    /**
     * If not null, credentials of type [SdJwtVcCredential] are available and this
     * object contains more information and data related to this.
     */
    val sdJwtVcDocumentConfiguration: SdJwtVcDocumentConfiguration?,

    /**
     * If not null, credentials of type [DirectAccessCredential] are available and this
     * object contains more information and data related to this.
     */
    val directAccessConfiguration: DirectAccessDocumentConfiguration?,

    ) {
    companion object
}
