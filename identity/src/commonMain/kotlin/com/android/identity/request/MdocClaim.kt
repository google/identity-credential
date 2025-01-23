package com.android.identity.request

import com.android.identity.documenttype.DocumentAttribute

/**
 * Claims for ISO mdoc credentials.
 *
 * @param namespaceName the mdoc namespace.
 * @param dataElementName the data element name.
 * @param intentToRetain the intentToRetain value.
 */
data class MdocClaim(
    override val displayName: String,
    override val attribute: DocumentAttribute?,
    val namespaceName: String,
    val dataElementName: String,
    val intentToRetain: Boolean
) : Claim(displayName, attribute) {
    companion object {
    }
}