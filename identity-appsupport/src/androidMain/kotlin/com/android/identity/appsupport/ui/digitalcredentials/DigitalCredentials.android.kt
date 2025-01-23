package com.android.identity.appsupport.ui.digitalcredentials

import android.graphics.BitmapFactory
import com.android.identity.appsupport.credman.IdentityCredentialEntry
import com.android.identity.appsupport.credman.IdentityCredentialField
import com.android.identity.appsupport.credman.IdentityCredentialRegistry
import com.android.identity.cbor.Cbor
import com.android.identity.credential.Credential
import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.util.AndroidContexts
import com.android.identity.util.Logger
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

private const val TAG = "DigitalCredentials"

private class RegistrationData (
    val documentStore: DocumentStore,
    val documentTypeRepository: DocumentTypeRepository,
    val listeningJob: Job,
    var mapIdToCredential: Map<Int, Credential>
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
        val mapIdToCredential = mutableMapOf<Int, Credential>()
        for (documentId in regData.documentStore.listDocuments()) {
            val document = regData.documentStore.lookupDocument(documentId) ?: continue
            val mdocCredential = (document.certifiedCredentials.find { it is MdocCredential }
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

            val cardArt = document.applicationData.getData("cardArt")
            val nameSpacedData = document.applicationData.getNameSpacedData("documentData")
            val displayName = document.applicationData.getString("displayName")

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

            mapIdToCredential[idCount] = mdocCredential
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
        regData.mapIdToCredential = mapIdToCredential
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
        // This ensure we process both flows sequentially, that is, that calls modifying our
        // model (addDocument, removeDocument, updateDocument) doesn't happen at
        // the same time...
        //
        runBlocking {
            documentStore.eventFlow
                .onEach { (eventType, document) ->
                    Logger.i(TAG, "DocumentStore event $eventType ${document.name}")
                    try {
                        updateCredman()
                    } catch (e: Throwable) {
                        Logger.w(TAG, "Exception while updating Credman", e)
                        e.printStackTrace()
                    }
                }
        }
    }
    exportedStores.put(documentStore, RegistrationData(
        documentStore,
        documentTypeRepository,
        listeningJob,
        mapOf()
    ))
    updateCredman()
}

internal actual suspend fun defaultStopExportingCredentials(
    documentStore: DocumentStore,
) {
    val registrationData = exportedStores.get(documentStore)
    if (registrationData == null) {
        return
    }
    registrationData.listeningJob.cancel()
    updateCredman()
}

fun DigitalCredentials.Default.getCredentialForId(id: Int): Credential? {
    for ((_, regData) in exportedStores) {
        val credential = regData.mapIdToCredential[id]
        if (credential != null) {
            return credential
        }
    }
    return null
}