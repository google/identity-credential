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
    val settingsModel: TestAppSettingsModel
): PresentmentSource {

    override val documentTypeRepository: DocumentTypeRepository
        get() = TestAppUtils.documentTypeRepository

    override fun findTrustPoint(request: Request): TrustPoint? {
        return when (request) {
            is MdocRequest -> {
                request.requester.certChain?.let {
                    val trustResult = TestAppUtils.readerTrustManager.verify(it.certificates)
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

    override fun selectCredentialForPresentment(
        request: Request,
        preSelectedDocument: Document?
    ): List<Credential> {
        when (request) {
            is MdocRequest -> return mdocFindCredentialsForRequest(request, preSelectedDocument)
            is VcRequest -> TODO()
        }

    }

    override fun shouldShowConsentPrompt(
        credential: Credential,
        request: Request,
    ): Boolean {
        return settingsModel.presentmentShowConsentPrompt.value
    }
}

private fun mdocFindCredentialsForRequest(
    request: MdocRequest,
    preSelectedDocument: Document?
): List<Credential> {
    val now = Clock.System.now()
    val result = mutableListOf<Credential>()

    if (preSelectedDocument != null) {
        val credential = mdocFindCredentialInDocument(request, now, preSelectedDocument)
        if (credential != null) {
            result.add(credential)
            return result
        }
    }

    for (documentName in TestAppUtils.documentStore.listDocuments()) {
        val document = TestAppUtils.documentStore.lookupDocument(documentName) ?: continue
        val credential = mdocFindCredentialInDocument(request, now, document)
        if (credential != null) {
            result.add(credential)
        }
    }
    return result
}

private fun mdocFindCredentialInDocument(
    request: MdocRequest,
    now: Instant,
    document: Document,
): Credential? {
    for (credential in document.certifiedCredentials) {
        if (credential is MdocCredential && credential.docType == request.docType) {
            val credential = document.findCredential(
                domain = TestAppUtils.MDOC_AUTH_KEY_DOMAIN,
                now = now
            )
            if (credential != null) {
                return credential
            }
        }
    }
    return null
}