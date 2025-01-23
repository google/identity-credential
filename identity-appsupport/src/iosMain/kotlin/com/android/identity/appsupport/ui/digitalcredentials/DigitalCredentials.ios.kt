package com.android.identity.appsupport.ui.digitalcredentials

import com.android.identity.credential.Credential
import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository
import kotlinx.io.bytestring.ByteString

internal actual val defaultAvailable = false

internal actual suspend fun defaultStartExportingCredentials(
    documentStore: DocumentStore,
    documentTypeRepository: DocumentTypeRepository,
) {
    throw NotImplementedError("DigitalCredentials is not available on iOS")
}

internal actual suspend fun defaultStopExportingCredentials(
    documentStore: DocumentStore,
) {
    throw NotImplementedError("DigitalCredentials is not available on iOS")
}
