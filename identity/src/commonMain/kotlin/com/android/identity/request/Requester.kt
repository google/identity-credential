package com.android.identity.request

import com.android.identity.crypto.X509CertChain

/**
 * Details about the entity requesting data.
 *
 * @property certChain if the requester signed the request and provided a certificate chain.
 * @property appId if the requester is a local application, for example `com.example.app` or `<teamId>.<bundleId>`.
 * @property websiteOrigin set if the verifier is a website, for example https://gov.example.com
 */
data class Requester(
    val certChain: X509CertChain? = null,
    val appId: String? = null,
    val websiteOrigin: String? = null
)