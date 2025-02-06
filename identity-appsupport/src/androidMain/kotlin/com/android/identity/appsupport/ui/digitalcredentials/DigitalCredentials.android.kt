package com.android.identity.appsupport.ui.digitalcredentials

import android.graphics.BitmapFactory
import com.android.identity.appsupport.credman.IdentityCredentialEntry
import com.android.identity.appsupport.credman.IdentityCredentialField
import com.android.identity.appsupport.credman.IdentityCredentialRegistry
import com.android.identity.cbor.Cbor
import com.android.identity.document.Document
import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.AndroidContexts
import com.android.identity.util.Logger
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString

private const val TAG = "DigitalCredentials"

private class RegistrationData (
    val documentStore: DocumentStore,
    val documentTypeRepository: DocumentTypeRepository,
    val listeningJob: Job,
)

private val credmanIdTableSpec = StorageTableSpec(
    name = "CredmanIdMapping",
    supportPartitions = false,
    supportExpiration = false
)

private val exportedStores = mutableMapOf<DocumentStore, RegistrationData>()

private fun getDataElementDisplayName(
    documentTypeRepository: DocumentTypeRepository,
    docTypeName: String,
    nameSpaceName: String,
    dataElementName: String
): String {
    val credType = documentTypeRepository.getDocumentTypeForMdoc(docTypeName)
    if (credType != null) {
        val mdocDataElement = credType.mdocDocumentType!!
            .namespaces[nameSpaceName]?.dataElements?.get(dataElementName)
        if (mdocDataElement != null) {
            return mdocDataElement.attribute.displayName
        }
    }
    return dataElementName
}

private suspend fun updateCredman() {
    var idCount = 0
    val entries = mutableListOf<IdentityCredentialEntry>()
    val context = AndroidContexts.applicationContext
    val appInfo = context.applicationInfo
    val appName = if (appInfo.labelRes != 0) {
        context.getString(appInfo.labelRes)
    } else {
        appInfo.nonLocalizedLabel.toString()
    }
    for ((_, regData) in exportedStores) {
        val credmanIdTable = regData.documentStore.storage.getTable(credmanIdTableSpec)
        credmanIdTable.deleteAll()
        for (documentId in regData.documentStore.listDocuments()) {
            val document = regData.documentStore.lookupDocument(documentId) ?: continue
            val mdocCredential = (document.getCertifiedCredentials().find { it is MdocCredential }
                ?: continue) as MdocCredential
            val credentialType =
                regData.documentTypeRepository.getDocumentTypeForMdoc(mdocCredential.docType)

            val fields = mutableListOf<IdentityCredentialField>()
            fields.add(
                IdentityCredentialField(
                    name = "doctype",
                    value = mdocCredential.docType,
                    displayName = "Document Type",
                    displayValue = mdocCredential.docType
                )
            )

            val documentMetadata = document.metadata
            val cardArt = documentMetadata.cardArt!!.toByteArray()
            val nameSpacedData = documentMetadata.nameSpacedData
            val displayName = documentMetadata.displayName!!

            Logger.i(TAG, "exporting $displayName as $idCount")

            nameSpacedData.nameSpaceNames.map { nameSpaceName ->
                nameSpacedData.getDataElementNames(nameSpaceName).map { dataElementName ->
                    val fieldName = nameSpaceName + "." + dataElementName
                    val valueCbor = nameSpacedData.getDataElement(nameSpaceName, dataElementName)

                    val mdocDataElement = credentialType?.mdocDocumentType?.namespaces
                        ?.get(nameSpaceName)?.dataElements?.get(dataElementName)
                    val valueString = mdocDataElement
                        ?.renderValue(Cbor.decode(valueCbor))
                        ?: Cbor.toDiagnostics(valueCbor)

                    val dataElementDisplayName = getDataElementDisplayName(
                        regData.documentTypeRepository,
                        mdocCredential.docType,
                        nameSpaceName,
                        dataElementName
                    )
                    fields.add(
                        IdentityCredentialField(
                            name = fieldName,
                            value = valueString,
                            displayName = dataElementDisplayName,
                            displayValue = valueString
                        )
                    )
                }
            }

            val options = BitmapFactory.Options()
            options.inMutable = true
            val credBitmap = BitmapFactory.decodeByteArray(
                cardArt,
                0,
                cardArt.size,
                options
            )

            credmanIdTable.insert(idCount.toString(), document.identifier.encodeToByteString())
            entries.add(
                IdentityCredentialEntry(
                    id = (idCount++).toLong(),
                    format = "mdoc",
                    title = displayName,
                    subtitle = appName,
                    icon = credBitmap,
                    fields = fields.toList(),
                    disclaimer = null,
                    warning = null,
                )
            )
        }
    }

    val registry = IdentityCredentialRegistry(entries)
    val client = IdentityCredentialManager.Companion.getClient(context)
    client.registerCredentials(registry.toRegistrationRequest(context))
        .addOnSuccessListener { Logger.i(TAG, "CredMan registry succeeded") }
        .addOnFailureListener { Logger.i(TAG, "CredMan registry failed $it") }
}

internal actual val defaultAvailable = true

internal actual suspend fun defaultStartExportingCredentials(
    documentStore: DocumentStore,
    documentTypeRepository: DocumentTypeRepository,
) {
    val listeningJob = CoroutineScope(Dispatchers.IO).launch {
        documentStore.eventFlow
            .onEach { event ->
                Logger.i(TAG, "DocumentStore event ${event::class.simpleName} ${event.documentId}")
                try {
                    updateCredman()
                } catch (e: Throwable) {
                    currentCoroutineContext().ensureActive()
                    Logger.w(TAG, "Exception while updating Credman", e)
                    e.printStackTrace()
                }
            }
    }
    exportedStores.put(documentStore, RegistrationData(
        documentStore = documentStore,
        documentTypeRepository = documentTypeRepository,
        listeningJob = listeningJob,
    ))
    updateCredman()
}

internal actual suspend fun defaultStopExportingCredentials(
    documentStore: DocumentStore,
) {
    val registrationData = exportedStores.remove(documentStore)
    if (registrationData == null) {
        return
    }
    registrationData.listeningJob.cancel()
    updateCredman()
}

suspend fun DocumentStore.lookupForCredmanId(
    credmanId: Long
): Document? {
    val credmanIdTable = storage.getTable(credmanIdTableSpec)
    val documentId = credmanIdTable.get(credmanId.toString())
    if (documentId != null) {
        return lookupDocument(documentId.decodeToString())
    }
    return null
}

