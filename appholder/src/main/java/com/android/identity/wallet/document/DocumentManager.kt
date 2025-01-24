package com.android.identity.wallet.document

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import com.android.identity.android.direct_access.DirectAccess
import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.cbor.Cbor
import com.android.identity.document.Document
import com.android.identity.document.NameSpacedData
import com.android.identity.documenttype.DocumentAttributeType
import com.android.identity.wallet.HolderApp
import com.android.identity.wallet.R
import com.android.identity.wallet.selfsigned.SelfSignedDocumentData
import com.android.identity.wallet.util.Field
import com.android.identity.wallet.util.FormatUtil
import com.android.identity.wallet.util.ProvisioningUtil
import com.android.identity.wallet.util.ProvisioningUtil.Companion.toDocumentInformation
import com.android.identity.wallet.util.log
import com.android.identity.wallet.util.logError
import com.android.mdl.app.credman.IdentityCredentialEntry
import com.android.mdl.app.credman.IdentityCredentialField
import com.android.mdl.app.credman.IdentityCredentialRegistry
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import java.io.ByteArrayOutputStream
import java.util.Locale

class DocumentManager private constructor(private val context: Context) {
    val client = IdentityCredentialManager.Companion.getClient(context)
    companion object {
        private const val TAG = "DocumentManager"

        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: DocumentManager? = null

        fun getInstance(context: Context) =
            instance ?: synchronized(this) {
                instance ?: DocumentManager(context).also { instance = it }
            }
    }

    fun getDocumentInformation(documentName: String): DocumentInformation? {
        val documentStore = ProvisioningUtil.getInstance(context).documentStore
        val document = documentStore.lookupDocument(documentName)
        return document.toDocumentInformation()
    }

    fun getDocumentByName(documentName: String): Document? {
        val documentInfo = getDocumentInformation(documentName)
        documentInfo?.let {
            val documentStore = ProvisioningUtil.getInstance(context).documentStore
            return documentStore.lookupDocument(documentName)
        }
        return null
    }

    fun getDataElementDisplayName(docTypeName : String,
                                  nameSpaceName : String,
                                  dataElementName : String): String {
        val credType = HolderApp.documentTypeRepositoryInstance.getDocumentTypeForMdoc(docTypeName)
        if (credType != null) {
            val mdocDataElement = credType.mdocDocumentType!!
                .namespaces[nameSpaceName]?.dataElements?.get(dataElementName)
            if (mdocDataElement != null) {
                return mdocDataElement.attribute.displayName
            }
        }
        return dataElementName
    }

    fun registerDocuments() {
        val documentStore = ProvisioningUtil.getInstance(context).documentStore
        var idCount = 0L
        val entries = documentStore.listDocuments().map { documentId ->
            val document = documentStore.lookupDocument(documentId)!!
            val documentInformation = document.toDocumentInformation()!!

            val fields = mutableListOf<IdentityCredentialField>()
            fields.add(IdentityCredentialField(
                name = "doctype",
                value = documentInformation.docType,
                displayName = "Document Type",
                displayValue = documentInformation.docType
            ))

            val nameSpacedData = document.applicationData.getNameSpacedData("documentData")
            nameSpacedData.nameSpaceNames.map {nameSpaceName ->
                nameSpacedData.getDataElementNames(nameSpaceName).map {dataElementName ->
                    val fieldName = nameSpaceName + "." + dataElementName
                    val valueCbor = nameSpacedData.getDataElement(nameSpaceName, dataElementName)
                    var valueString = Cbor.toDiagnostics(valueCbor)
                    // Workaround for Credman not supporting images yet
                    if (dataElementName.equals("portrait") || dataElementName.equals("signature_usual_mark")) {
                        valueString = String.format(Locale.US, "%d bytes", valueCbor.size)
                    }
                    val dataElementDisplayName = getDataElementDisplayName(documentInformation.docType, nameSpaceName, dataElementName)
                    fields.add(IdentityCredentialField(
                        name = fieldName,
                        value = valueString,
                        displayName = dataElementDisplayName,
                        displayValue = valueString
                    ))
                    log("Adding field $fieldName ('$dataElementDisplayName') with value '$valueString'")
                }
            }

            log("Adding document ${documentInformation.userVisibleName}")
            IdentityCredentialEntry(
                id = idCount++,
                format = "mdoc",
                title = documentInformation.userVisibleName,
                subtitle = context.getString(R.string.app_name),
                icon = BitmapFactory.decodeResource(context.resources, R.drawable.driving_license_bg),
                fields = fields.toList(),
                disclaimer = null,
                warning = null,
            )
        }
        val registry = IdentityCredentialRegistry(entries)
        client.registerCredentials(registry.toRegistrationRequest(context))
            .addOnSuccessListener { log("CredMan registry succeeded") }
            .addOnFailureListener { logError("CredMan registry failed $it") }
    }

    fun getDocuments(): List<DocumentInformation> {
        val documentStore = ProvisioningUtil.getInstance(context).documentStore
        return documentStore.listDocuments().mapNotNull { documentName ->
            val document = documentStore.lookupDocument(documentName)
            document.toDocumentInformation()
        }
    }


    fun deleteDocumentByName(documentName: String) {
        val documentInformation = getDocumentInformation(documentName)
        var documentHasDirectAccessCreds = false
        var documentSlot = 0
        documentInformation?.let {
            val documentStore = ProvisioningUtil.getInstance(context).documentStore
            documentStore.lookupDocument(documentName)?.let {
                val certifiedCredentials = it.certifiedCredentials
                val pendingCredentials = it.pendingCredentials
                for (credential in (pendingCredentials + certifiedCredentials)) {
                    if (credential is DirectAccessCredential) {
                        documentHasDirectAccessCreds = true
                        documentSlot = credential.documentSlot
                        break
                    }
                }
            }
            documentStore.deleteDocument(documentName)
        }
        if (documentHasDirectAccessCreds) {
            DirectAccess.clearDocumentSlot(documentSlot)
        }
        registerDocuments()
    }

    fun createSelfSignedDocument(documentData: SelfSignedDocumentData) {
        val docName = getUniqueDocumentName(documentData)
        documentData.provisionInfo.docName = docName
        try {
            provisionSelfSignedDocument(documentData)
        } catch (e: Exception) {
            throw IllegalStateException("Error creating self signed document", e)
        }
        registerDocuments()
    }

    private fun getUniqueDocumentName(
        documentData: SelfSignedDocumentData,
        docName: String = documentData.provisionInfo.docName,
        count: Int = 1
    ): String {
        val store = ProvisioningUtil.getInstance(context).documentStore
        store.listDocuments().forEach { name ->
            if (name == docName) {
                return getUniqueDocumentName(documentData, "$docName ($count)", count + 1)
            }
        }
        return docName
    }

    private fun provisionSelfSignedDocument(documentData: SelfSignedDocumentData) {
        val builder = NameSpacedData.Builder()

        for (field in documentData.fields.filter { it.parentId == null }) {
            when (field.fieldType) {
                is DocumentAttributeType.Date, DocumentAttributeType.DateTime -> {
                    val date = UnicodeString(field.getValueString())
                    date.setTag(1004)
                    builder.putEntry(
                        field.namespace!!,
                        field.name,
                        FormatUtil.cborEncode(date)
                    )
                }

                is DocumentAttributeType.Number -> {
                    builder.putEntryNumber(
                        field.namespace!!,
                        field.name,
                        field.getValueLong()
                    )
                }

                is DocumentAttributeType.Boolean -> {
                    builder.putEntryBoolean(
                        field.namespace!!,
                        field.name,
                        field.getValueBoolean()
                    )
                }

                is DocumentAttributeType.Picture -> {
                    val bitmap = field.getValueBitmap()
                    val baos = ByteArrayOutputStream()
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 50, baos)
                    val bytes = baos.toByteArray()
                    builder.putEntryByteString(field.namespace!!, field.name, bytes)
                }

                is DocumentAttributeType.IntegerOptions -> {
                    if (field.hasValue()) {
                        builder.putEntryNumber(
                            field.namespace!!,
                            field.name,
                            field.getValueLong()
                        )
                    }
                }

                is DocumentAttributeType.ComplexType -> {

                    val dataItem = when (field.isArray) {
                        true -> {
                            createArrayDataItem(field, documentData)
                        }

                        false -> {
                            createMapDataItem(field, documentData)
                        }
                    }
                    builder.putEntry(
                        field.namespace!!,
                        field.name,
                        FormatUtil.cborEncode(dataItem)
                    )
                }

                else -> {

                    builder.putEntryString(
                        field.namespace!!,
                        field.name,
                        field.getValueString()
                    )
                }
            }
        }
        ProvisioningUtil.getInstance(context)
            .provisionSelfSigned(builder.build(), documentData.provisionInfo)
    }

    private fun createArrayDataItem(field: Field, documentData: SelfSignedDocumentData): DataItem {
        val childFields = documentData.fields.filter { it.parentId == field.id }
        val childDataItems = mutableListOf<DataItem>()

        val fieldsPerItem = childFields.distinctBy { it.name }.count()
        val itemCount = childFields.count() / fieldsPerItem

        for (i in 0 until itemCount) {
            childDataItems.add(
                createMapDataItem(
                    childFields.subList(
                        i * fieldsPerItem,
                        (i + 1) * fieldsPerItem
                    ), documentData
                )
            )
        }

        val arrayBuilder = CborBuilder().addArray()
        for (childDataItem in childDataItems) {
            arrayBuilder.add(childDataItem)
        }
        return arrayBuilder.end().build()[0]
    }


    private fun createMapDataItem(field: Field, documentData: SelfSignedDocumentData): DataItem {
        val childFields = documentData.fields.filter { it.parentId == field.id }
        return createMapDataItem(childFields, documentData)
    }

    private fun createMapDataItem(
        fields: List<Field>,
        documentData: SelfSignedDocumentData
    ): DataItem {
        val mapBuilder = CborBuilder().addMap()
        for (field in fields) {
            when (field.fieldType) {
                is DocumentAttributeType.Date, DocumentAttributeType.DateTime -> {
                    val date = UnicodeString(field.getValueString())
                    date.setTag(1004)
                    mapBuilder.put(
                        UnicodeString(field.name),
                        date
                    )
                }

                is DocumentAttributeType.Boolean -> {
                    mapBuilder.put(
                        field.name,
                        field.getValueBoolean()
                    )
                }

                is DocumentAttributeType.Picture -> {
                    val bitmap = field.getValueBitmap()
                    val baos = ByteArrayOutputStream()
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 50, baos)
                    val bytes = baos.toByteArray()
                    mapBuilder.put(field.name, bytes)
                }

                is DocumentAttributeType.IntegerOptions,
                is DocumentAttributeType.Number -> {
                    if (field.value != "") {
                        mapBuilder.put(
                            field.name,
                            field.getValueLong()
                        )
                    }
                }

                is DocumentAttributeType.ComplexType -> {
                    val dataItem = when (field.isArray) {
                        true -> {
                            createArrayDataItem(field, documentData)
                        }

                        false -> {
                            createMapDataItem(field, documentData)
                        }
                    }
                    mapBuilder.put(UnicodeString(field.name), dataItem)
                }

                else -> {
                    mapBuilder.put(field.name, field.value as String)
                }
            }
        }

        return mapBuilder.end().build()[0]
    }

    fun refreshCredentials(documentName: String) {
        val documentInformation = requireNotNull(getDocumentInformation(documentName))
        val document = requireNotNull(getDocumentByName(documentName))
        ProvisioningUtil.getInstance(context).refreshMdocCredentials(document, documentInformation.docType)
        ProvisioningUtil.getInstance(context).refreshDaCredentials(document, documentInformation.docType, 0)
    }
}
