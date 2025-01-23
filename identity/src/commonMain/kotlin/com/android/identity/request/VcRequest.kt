package com.android.identity.request

/**
 * A request for a W3C Verifiable Credential.
 *
 * @property vct the Verifiable Credential Type.
 */
data class VcRequest(
    override val requester: Requester,
    override val claims: List<VcClaim>,
    val vct: String
): Request(requester, claims)
