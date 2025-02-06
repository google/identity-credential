package com.android.identity.testapp

import com.android.identity.appsupport.ui.presentment.PresentmentSource
import com.android.identity.credential.Credential
import com.android.identity.document.Document
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.request.MdocRequest
import com.android.identity.request.Request
import com.android.identity.request.VcRequest
import com.android.identity.trustmanagement.TrustPoint
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class TestAppPresentmentSource(
    val app: App
): PresentmentSource {

    override val documentTypeRepository: DocumentTypeRepository
        get() = app.documentTypeRepository

    override fun findTrustPoint(request: Request): TrustPoint? {
        return when (request) {
            is MdocRequest -> {
                request.requester.certChain?.let {
                    val trustResult = app.readerTrustManager.verify(it.certificates)
                    if (trustResult.isTrusted) {
                        trustResult.trustPoints[0]
                    } else {
                        null
                    }
                }
            }
            is VcRequest -> null
        }
    }

    override suspend fun selectCredentialForPresentment(
        request: Request,
        preSelectedDocument: Document?
    ): List<Credential> {
        when (request) {
            is MdocRequest -> return mdocFindCredentialsForRequest(app, request, preSelectedDocument)
            is VcRequest -> TODO()
        }

    }

    override fun shouldShowConsentPrompt(
        credential: Credential,
        request: Request,
    ): Boolean {
        return app.settingsModel.presentmentShowConsentPrompt.value
    }
}

private suspend fun mdocFindCredentialsForRequest(
    app: App,
    request: MdocRequest,
    preSelectedDocument: Document?
): List<Credential> {
    val now = Clock.System.now()
    val result = mutableListOf<Credential>()

    if (preSelectedDocument != null) {
        val credential = mdocFindCredentialInDocument(app, request, now, preSelectedDocument)
        if (credential != null) {
            result.add(credential)
            return result
        }
    }

    for (documentName in app.documentStore.listDocuments()) {
        val document = app.documentStore.lookupDocument(documentName) ?: continue
        val credential = mdocFindCredentialInDocument(app, request, now, document)
        if (credential != null) {
            result.add(credential)
        }
    }
    return result
}

private suspend fun mdocFindCredentialInDocument(
    app: App,
    request: MdocRequest,
    now: Instant,
    document: Document,
): Credential? {
    val domain = if (app.settingsModel.presentmentRequireAuthentication.value) {
        TestAppUtils.MDOC_CREDENTIAL_DOMAIN_AUTH
    } else {
        TestAppUtils.MDOC_CREDENTIAL_DOMAIN_NO_AUTH
    }
    for (credential in document.getCertifiedCredentials()) {
        if (credential is MdocCredential && credential.docType == request.docType) {
            val credential = document.findCredential(
                domain = domain,
                now = now
            )
            if (credential != null) {
                return credential
            }
        }
    }
    return null
}