package com.android.identity.request

import com.android.identity.documenttype.DocumentAttribute

/**
 * Claims for VC credentials.
 *
 * @param claimName the claim name.
 */
data class VcClaim(
    override val displayName: String,
    override val attribute: DocumentAttribute?,
    val claimName: String
) : Claim(displayName, attribute) {
    companion object {
    }
}