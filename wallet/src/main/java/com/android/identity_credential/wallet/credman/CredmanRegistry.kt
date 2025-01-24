package com.android.identity_credential.wallet.credman

import android.content.Context
import android.graphics.BitmapFactory
import com.android.identity.cbor.Cbor
import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.R
import com.android.mdl.app.credman.IdentityCredentialEntry
import com.android.mdl.app.credman.IdentityCredentialField
import com.android.mdl.app.credman.IdentityCredentialRegistry
import com.google.android.gms.identitycredentials.IdentityCredentialManager

private const val TAG = "CredmanRegistry"

object CredmanRegistry {

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

    suspend fun registerCredentials(
        context: Context,
        documentStore: DocumentStore,
        documentTypeRepository: DocumentTypeRepository
    ) {
        var idCount = 0L
        val entries = mutableListOf<IdentityCredentialEntry>()
        for (documentId in documentStore.listDocuments()) {

            val document = documentStore.lookupDocument(documentId) ?: continue
            val docConf = document.documentConfiguration
            if (docConf.mdocConfiguration == null) {
                return
            }
            val mdocConf = docConf.mdocConfiguration!!

            val credentialType = documentTypeRepository.getDocumentTypeForMdoc(mdocConf.docType)

            val fields = mutableListOf<IdentityCredentialField>()
            fields.add(
                IdentityCredentialField(
                    name = "doctype",
                    value = mdocConf.docType,
                    displayName = "Document Type",
                    displayValue = mdocConf.docType
                )
            )

            val nameSpacedData = mdocConf.staticData
            nameSpacedData.nameSpaceNames.map { nameSpaceName ->
                nameSpacedData.getDataElementNames(nameSpaceName).map { dataElementName ->
                    val fieldName = nameSpaceName + "." + dataElementName
                    val valueCbor = nameSpacedData.getDataElement(nameSpaceName, dataElementName)

                    val mdocDataElement = credentialType?.mdocDocumentType?.namespaces
                        ?.get(nameSpaceName)?.dataElements?.get(dataElementName)
                    val valueString = mdocDataElement
                        ?.renderValue(
                            value = Cbor.decode(valueCbor),
                            trueFalseStrings = Pair(
                                context.resources.getString(R.string.document_details_boolean_false_value),
                                context.resources.getString(R.string.document_details_boolean_true_value)
                            )
                        )
                        ?: Cbor.toDiagnostics(valueCbor)

                    val dataElementDisplayName = getDataElementDisplayName(
                        documentTypeRepository,
                        mdocConf.docType,
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
                docConf.cardArt,
                0,
                docConf.cardArt.size,
                options
            )

            Logger.i(TAG, "Adding document ${docConf.displayName}")
            entries.add(
                IdentityCredentialEntry(
                    id = idCount++,
                    format = "mdoc",
                    title = docConf.displayName,
                    subtitle = context.getString(R.string.app_name),
                    icon = credBitmap,
                    fields = fields.toList(),
                    disclaimer = null,
                    warning = null,
                )
            )
        }
        val registry = IdentityCredentialRegistry(entries)
        val client = IdentityCredentialManager.Companion.getClient(context)
        client.registerCredentials(registry.toRegistrationRequest(context))
            .addOnSuccessListener { Logger.i(TAG, "CredMan registry succeeded") }
            .addOnFailureListener { Logger.i(TAG, "CredMan registry failed $it") }

    }
}