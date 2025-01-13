package com.android.identity.request

/**
 * Base class used for representing requests.
 *
 * This is an abstraction for representing credential requests in a format independent of
 * the encoding / protocol (e.g. ISO/EC 18013-5:2021 `DeviceRequest`, OpenID4VP, etc) that
 * was used to encode the request. Multiple formats are supported including ISO mdoc and
 * W3C Verifiable Credentials.
 *
 * @property requester the entity making the request.
 * @property claims the claims being requested.
 */
sealed class Request(
    open val requester: Requester,
    open val claims: List<Claim>
)