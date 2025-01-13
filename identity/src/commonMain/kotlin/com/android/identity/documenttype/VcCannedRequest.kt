package com.android.identity.documenttype

/**
 * A class representing a request for claims.
 *
 * @param vct the verifiable credential type, as defined in section 3.2.2.1.1.
 * "Verifiable Credential Type - vct Claim" of IETF
 * [SD-JWT-based Verifiable Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-05)
 * @param claimsToRequest the claims to request.
 */
data class VcCannedRequest(
    val vct: String,
    val claimsToRequest: List<DocumentAttribute>
)
