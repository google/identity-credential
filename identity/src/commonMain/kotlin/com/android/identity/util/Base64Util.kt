package com.android.identity.util

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Extension to encode a [ByteArray] to a URL-safe base64 encoding without padding
 * as defined in Section 5 of RFC 4648.
 */
@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.toBase64Url(): String = Base64.UrlSafe.encode(this).trimEnd('=')

/**
 * Extension to decode a [ByteArray] from a URL-safe base64 encoded string
 * as defined in Section 5 of RFC 4648.
 *
 * This works for both strings with or without padding.
 */
@OptIn(ExperimentalEncodingApi::class)
fun String.fromBase64Url(): ByteArray = Base64.UrlSafe.decode(this)
