package com.android.identity.appsupport.ui.presentment

import com.android.identity.credential.Credential
import com.android.identity.document.Document
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.request.Request
import com.android.identity.trustmanagement.TrustPoint

/**
 * An interface used for the application to provide data and policy for credential presentment.
 */
interface PresentmentSource {

    /**
     * The [DocumentTypeRepository] to look up metadata for incoming requests.
     */
    val documentTypeRepository: DocumentTypeRepository

    /**
     * Finds a [TrustPoint] for a requester.
     *
     * @param request The request.
     * @return a [TrustPoint] or `null` if none could be found.
     */
    fun findTrustPoint(
        request: Request
    ): TrustPoint?

    /**
     * Selects one or more credentials eligible for presentment for a request.
     *
     * One example where [preSelectedDocument] is non-`null` if when using the W3C Digital Credentials
     * on Android where the operating system displays a document picker prior to invoking the
     * application.
     *
     * The credentials returned must be for distinct documents.
     *
     * @param request the request.
     * @param preSelectedDocument if not `null`, a [Document] preselected by the user.
     * @return zero, one, or more [Credential] instances eligible for presentment.
     */
    fun selectCredentialForPresentment(
        request: Request,
        preSelectedDocument: Document?
    ): List<Credential>

    /**
     * Function to determine if the consent prompt should be shown.
     *
     * @param credential the credential being presented.
     * @param request the request.
     * @return `true` if the consent prompt should be shown, `false` otherwise
     */
    fun shouldShowConsentPrompt(
        credential: Credential,
        request: Request,
    ): Boolean
}