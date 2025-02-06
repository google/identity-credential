package com.android.identity_credential.wallet

import android.content.Context
import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.DiagnosticOption
import com.android.identity.credential.Credential
import com.android.identity.document.Document
import com.android.identity.documenttype.DocumentAttribute
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.MdocDocumentType
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.jpeg2k.Jpeg2kConverter
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.sdjwt.SdJwtVerifiableCredential
import com.android.identity.sdjwt.credential.KeyBoundSdJwtVcCredential
import com.android.identity.sdjwt.credential.KeylessSdJwtVcCredential
import com.android.identity.sdjwt.credential.SdJwtVcCredential
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

private const val TAG = "ViewDocumentData"

/**
 * A class containing human-readable information (mainly PII) about a document.
 *
 * This data is intended to be display to the user, not used in presentations
 * or sent to external parties.
 *
 * @param typeName human readable type name of the document, e.g. "Driving License".
 * @param attributes key/value pairs with data in the document
 */
data class DocumentDetails(
    val attributes: Map<String, AttributeDisplayInfo>
)

private data class VisitNamespaceResult(
    val keysAndValues: Map<String, AttributeDisplayInfo>
)

private fun visitNamespace(
    context: Context,
    mdocDocumentType: MdocDocumentType?,
    namespaceName: String,
    listOfEncodedIssuerSignedItemBytes: List<ByteArray>,
): VisitNamespaceResult {
    val keysAndValues: MutableMap<String, AttributeDisplayInfo> = LinkedHashMap()
    for (encodedIssuerSignedItemBytes in listOfEncodedIssuerSignedItemBytes) {
        val issuerSignedItemBytes = Cbor.decode(encodedIssuerSignedItemBytes)
        val issuerSignedItem = issuerSignedItemBytes.asTaggedEncodedCbor
        val elementIdentifier = issuerSignedItem["elementIdentifier"].asTstr
        val elementValue = issuerSignedItem["elementValue"]
        val encodedElementValue = Cbor.encode(elementValue)

        val mdocDataElement = mdocDocumentType?.namespaces?.get(namespaceName)?.dataElements?.get(elementIdentifier)

        val elementName = mdocDataElement?.attribute?.displayName ?: elementIdentifier
        var attributeDisplayInfo: AttributeDisplayInfo? = null

        if (mdocDataElement != null) {
            attributeDisplayInfo = if (isImageAttribute(namespaceName, mdocDataElement.attribute)) {
                Jpeg2kConverter.decodeByteArray(context, elementValue.asBstr)?.let {
                    AttributeDisplayInfoImage(elementName, it)
                }
            } else if (namespaceName == DrivingLicense.MDL_NAMESPACE &&
                mdocDataElement.attribute.identifier == "driving_privileges") {
                val htmlDisplayValue = createDrivingPrivilegesHtml(encodedElementValue)
                AttributeDisplayInfoHtml(elementName, htmlDisplayValue)
            } else {
                AttributeDisplayInfoPlainText(
                    elementName,
                    mdocDataElement.renderValue(
                        value = Cbor.decode(encodedElementValue),
                        trueFalseStrings = Pair(
                            context.resources.getString(R.string.document_details_boolean_false_value),
                            context.resources.getString(R.string.document_details_boolean_true_value),
                        )
                    )
                )
            }
        }

        if (attributeDisplayInfo == null) {
            attributeDisplayInfo = AttributeDisplayInfoPlainText(
                elementName,
                Cbor.toDiagnostics(
                    encodedElementValue,
                    setOf(DiagnosticOption.BSTR_PRINT_LENGTH)
                )
            )
        }

        keysAndValues[elementIdentifier] = attributeDisplayInfo
    }
    return VisitNamespaceResult(keysAndValues)
}

private fun isImageAttribute(namespaceName: String, attribute: DocumentAttribute): Boolean {
    if (namespaceName == DrivingLicense.MDL_NAMESPACE) {
        return when (attribute.identifier) {
            "portrait", "signature_usual_mark" -> true
            else -> false
        }
    }
    if (namespaceName == PhotoID.PHOTO_ID_NAMESPACE) {
        return when (attribute.identifier) {
            "portrait" -> true
            else -> false
        }
    }
    return false
}

/**
 * Creates a string with HTML that renders the Driving Privileges field in a more human-readable
 * format.
 *
 * TODO: We should consider moving this to MdocDataElement.renderValue(), with a parameter to switch
 * between text/plain and text/html.
 *
 * @param encodedElementValue The CBOR-encoded value of the driving_privileges element.
 */
fun createDrivingPrivilegesHtml(encodedElementValue: ByteArray): String {
    val decodedValue = Cbor.decode(encodedElementValue).asArray
    val htmlDisplayValue = buildString {
        for (categoryMap in decodedValue) {
            val categoryCode =
                categoryMap.getOrNull("vehicle_category_code")?.asTstr ?: "Unspecified"
            // The current HTML -> AnnotatedString parser only handles a subset of HTML.
            // Because of that, we'll do indentation using spaces.
            val vehicleIndent = "&nbsp;".repeat(4)
            append("<div>${vehicleIndent}Vehicle class: $categoryCode</div>")
            val indent = "&nbsp;".repeat(8)
            categoryMap.getOrNull("issue_date")?.asDateString?.let { append("<div>${indent}Issued: $it</div>") }
            categoryMap.getOrNull("expiry_date")?.asDateString?.let { append("<div>${indent}Expires: $it</div>") }
        }
    }
    return htmlDisplayValue
}

suspend fun Document.renderDocumentDetails(
    context: Context,
    documentTypeRepository: DocumentTypeRepository
): DocumentDetails {
    // TODO: maybe use DocumentConfiguration instead of pulling data out of a certified credential.

    val certifiedCredentials = getCertifiedCredentials()

    if (certifiedCredentials.isEmpty()) {
        return DocumentDetails(mapOf())
    }
    return when (val credential = certifiedCredentials[0]) {
        is MdocCredential -> {
            renderDocumentDetailsForMdoc(context, documentTypeRepository, credential)
        }
        is KeyBoundSdJwtVcCredential -> {
            renderDocumentDetailsForSdJwt(documentTypeRepository, credential)
        }
        is KeylessSdJwtVcCredential -> {
            renderDocumentDetailsForSdJwt(documentTypeRepository, credential)
        }
        is DirectAccessCredential -> {
            return renderDocumentDetailsForMdoc(context, documentTypeRepository, credential)
        }
        else -> {
            return DocumentDetails(mapOf())
        }
    }
}

private fun Document.renderDocumentDetailsForMdoc(
    context: Context,
    documentTypeRepository: DocumentTypeRepository,
    credential: Credential
): DocumentDetails {

    assert(((credential is MdocCredential) or (credential is DirectAccessCredential))
    ) { "Credential must be either MdocCredential or DirectAccessCredential" }
    val documentData = StaticAuthDataParser(credential.issuerProvidedData).parse()
    val issuerAuthCoseSign1 = Cbor.decode(documentData.issuerAuth).asCoseSign1
    val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
    val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)

    val mso = MobileSecurityObjectParser(encodedMso).parse()

    val documentType = documentTypeRepository.getDocumentTypeForMdoc(mso.docType)
    val kvPairs = mutableMapOf<String, AttributeDisplayInfo>()
    for (namespaceName in mso.valueDigestNamespaces) {
        val digestIdMapping = documentData.digestIdMapping[namespaceName] ?: listOf()
        val result = visitNamespace(
            context,
            documentType?.mdocDocumentType,
            namespaceName,
            digestIdMapping
        )
        kvPairs += result.keysAndValues
    }

    return DocumentDetails(kvPairs)
}

private fun Document.renderDocumentDetailsForSdJwt(
    documentTypeRepository: DocumentTypeRepository,
    credential: SdJwtVcCredential
): DocumentDetails {
    val kvPairs = mutableMapOf<String, AttributeDisplayInfo>()

    val vcType = documentTypeRepository.getDocumentTypeForVc(credential.vct)?.vcDocumentType

    val sdJwt = SdJwtVerifiableCredential.fromString(
        String(credential.issuerProvidedData, Charsets.US_ASCII))

    for (disclosure in sdJwt.disclosures) {
        val content = if (disclosure.value is JsonPrimitive) {
            disclosure.value.jsonPrimitive.content
        } else {
            disclosure.value.toString()
        }
        val claimName = disclosure.key
        val displayName = vcType
            ?.claims
            ?.get(claimName)
            ?.displayName
            ?: claimName

        kvPairs[claimName] = AttributeDisplayInfoPlainText(displayName, content)
    }

    return DocumentDetails(kvPairs)
}
