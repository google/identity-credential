package com.android.identity.request

/**
 * A request for an ISO mdoc.
 *
 * @property docType the ISO mdoc document type.
 */
data class MdocRequest(
    override val requester: Requester,
    override val claims: List<MdocClaim>,
    val docType: String,
): Request(requester, claims)
