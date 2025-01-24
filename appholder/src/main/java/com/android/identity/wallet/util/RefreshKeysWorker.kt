package com.android.identity.wallet.util

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.android.identity.wallet.document.DocumentManager

class RefreshKeysWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    private val documentManager = DocumentManager.getInstance(context)
    private val provisioningUtil = ProvisioningUtil.getInstance(context)

    override fun doWork(): Result {
        documentManager.getDocuments().forEach { documentInformation ->
            val document = documentManager.getDocumentByName(documentInformation.docName)
            document?.let { provisioningUtil.refreshMdocCredentials(it, documentInformation.docType) }
        }
        return Result.success()
    }
}