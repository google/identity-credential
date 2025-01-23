package com.android.identity.request

import com.android.identity.documenttype.DocumentAttribute

/**
 * Base class used for representing claims in a request.
 *
 * @param displayName the text to display in consent prompt for the claim.
 * @param attribute a [DocumentAttribute], if the claim is for a well-known attribute.
 */
sealed class Claim(
    open val displayName: String,
    open val attribute: DocumentAttribute?
)