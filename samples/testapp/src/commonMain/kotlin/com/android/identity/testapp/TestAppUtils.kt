package com.android.identity.testapp

import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.Tstr
import com.android.identity.cbor.toDataItem
import com.android.identity.cose.Cose
import com.android.identity.cose.CoseLabel
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.document.DocumentStore
import com.android.identity.document.NameSpacedData
import com.android.identity.documenttype.DocumentCannedRequest
import com.android.identity.documenttype.DocumentType
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.request.DeviceRequestGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyPurpose
import com.android.identity.util.Logger
import identitycredential.samples.testapp.generated.resources.Res
import identitycredential.samples.testapp.generated.resources.driving_license_card_art
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import org.jetbrains.compose.resources.ExperimentalResourceApi
import org.jetbrains.compose.resources.getDrawableResourceBytes
import org.jetbrains.compose.resources.getSystemResourceEnvironment
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.collections.iterator
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours

object TestAppUtils {
    private const val TAG = "TestAppUtils"

    const val MDOC_CREDENTIAL_DOMAIN_AUTH = "mdoc_credential_domain_auth"
    const val MDOC_CREDENTIAL_DOMAIN_NO_AUTH = "mdoc_credential_domain_no_auth"

    fun generateEncodedDeviceRequest(
        request: DocumentCannedRequest,
        encodedSessionTranscript: ByteArray,
        readerKey: EcPrivateKey,
        readerCert: X509Cert,
        readerRootCert: X509Cert,
    ): ByteArray {
        val mdocRequest = request.mdocRequest!!
        val itemsToRequest = mutableMapOf<String, MutableMap<String, Boolean>>()
        for (ns in mdocRequest.namespacesToRequest) {
            for ((de, intentToRetain) in ns.dataElementsToRequest) {
                itemsToRequest.getOrPut(ns.namespace) { mutableMapOf() }
                    .put(de.attribute.identifier, intentToRetain)
            }
        }

        val deviceRequestGenerator = DeviceRequestGenerator(encodedSessionTranscript)
        deviceRequestGenerator.addDocumentRequest(
            docType = mdocRequest.docType,
            itemsToRequest = itemsToRequest,
            requestInfo = null,
            readerKey = readerKey,
            signatureAlgorithm = readerKey.curve.defaultSigningAlgorithm,
            readerKeyCertificateChain = X509CertChain(listOf(readerCert, readerRootCert)),
        )
        return deviceRequestGenerator.generate()
    }

    fun generateEncodedSessionTranscript(
        encodedDeviceEngagement: ByteArray,
        handover: DataItem,
        eReaderKey: EcPublicKey
    ): ByteArray {
        val encodedEReaderKey = Cbor.encode(eReaderKey.toCoseKey().toDataItem())
        return Cbor.encode(
            CborArray.builder()
                .add(Tagged(24, Bstr(encodedDeviceEngagement)))
                .add(Tagged(24, Bstr(encodedEReaderKey)))
                .add(handover)
                .end()
                .build()
        )
    }


    val provisionedDocumentTypes = listOf(
        DrivingLicense.getDocumentType(),
        PhotoID.getDocumentType(),
        EUPersonalID.getDocumentType()
    )

    suspend fun provisionDocuments(
        documentStore: DocumentStore,
        dsKey: EcPrivateKey,
        dsCert: X509Cert
    ) {
        if (documentStore.listDocuments().size >= 4) {
            // Assume documents are provisioned
            // TODO: do we want a more granular check
            return
        }
        provisionDocument(
            documentStore,
            dsKey,
            dsCert,
            DrivingLicense.getDocumentType(),
            "Erika",
            "Erika's Driving License"
        )
        provisionDocument(
            documentStore,
            dsKey,
            dsCert,
            PhotoID.getDocumentType(),
            "Erika",
            "Erika's Photo ID"
        )
        provisionDocument(
            documentStore,
            dsKey,
            dsCert,
            PhotoID.getDocumentType(),
            "Erika #2",
            "Erika's Photo ID #2"
        )
        provisionDocument(
            documentStore,
            dsKey,
            dsCert,
            EUPersonalID.getDocumentType(),
            "Erika",
            "Erika's Personal ID"
        )
    }

    // TODO: also provision SD-JWT credentials, if applicable
    @OptIn(ExperimentalResourceApi::class)
    private suspend fun provisionDocument(
        documentStore: DocumentStore,
        dsKey: EcPrivateKey,
        dsCert: X509Cert,
        documentType: DocumentType,
        givenNameOverride: String,
        displayName: String,
    ) {
        val nsdBuilder = NameSpacedData.Builder()
        for ((nsName, ns) in documentType.mdocDocumentType?.namespaces!!) {
            for ((deName, de) in ns.dataElements) {
                val sampleValue = de.attribute.sampleValue
                if (sampleValue != null) {
                    if (deName.startsWith("given_name")) {
                        nsdBuilder.putEntry(nsName, deName, Cbor.encode(Tstr(givenNameOverride)))
                    } else {
                        nsdBuilder.putEntry(nsName, deName, Cbor.encode(sampleValue))
                    }
                } else {
                    Logger.w(TAG, "No sample value for data element $deName")
                }
            }
        }
        val documentData = nsdBuilder.build()

        val cardArt = getDrawableResourceBytes(
            getSystemResourceEnvironment(),
            Res.drawable.driving_license_card_art
        )

        val document = documentStore.createDocument {
            val metadata = it as TestDocumentMetadata
            metadata.initialize(
                displayName = displayName,
                typeDisplayName = documentType.displayName,
                cardArt = ByteString(cardArt),
                nameSpacedData = documentData
            )
        }

        val overrides: MutableMap<String, Map<String, ByteArray>> = HashMap()
        val exceptions: MutableMap<String, List<String>> = HashMap()

        // Create authentication keys...
        for (domain in listOf(MDOC_CREDENTIAL_DOMAIN_AUTH, MDOC_CREDENTIAL_DOMAIN_NO_AUTH)) {
            val userAuthenticationRequired = (domain == MDOC_CREDENTIAL_DOMAIN_AUTH)

            val now = Clock.System.now()
            val timeSigned = now - 1.hours
            val timeValidityBegin =  now - 1.hours
            val timeValidityEnd = now + 24.hours
            val secureArea = platformSecureAreaProvider().get()

            val mdocCredential = MdocCredential.create(
                document = document,
                asReplacementForIdentifier = null,
                domain = domain,
                secureArea = secureArea,
                docType = documentType.mdocDocumentType!!.docType,
                createKeySettings = platformCreateKeySettings(
                    challenge = "Challenge".encodeToByteString(),
                    keyPurposes = setOf(KeyPurpose.AGREE_KEY, KeyPurpose.SIGN),
                    userAuthenticationRequired = userAuthenticationRequired
                )
            )

            // Generate an MSO and issuer-signed data for this authentication key.
            val msoGenerator = MobileSecurityObjectGenerator(
                "SHA-256",
                documentType.mdocDocumentType!!.docType,
                mdocCredential.getAttestation().publicKey
            )
            msoGenerator.setValidityInfo(timeSigned, timeValidityBegin, timeValidityEnd, null)
            val issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
                documentData,
                Random,
                16,
                overrides
            )
            for (nameSpaceName in issuerNameSpaces.keys) {
                val digests = MdocUtil.calculateDigestsForNameSpace(
                    nameSpaceName,
                    issuerNameSpaces,
                    Algorithm.SHA256
                )
                msoGenerator.addDigestIdsForNamespace(nameSpaceName, digests)
            }

            val mso = msoGenerator.generate()
            val taggedEncodedMso = Cbor.encode(Tagged(24, Bstr(mso)))

            // IssuerAuth is a COSE_Sign1 where payload is MobileSecurityObjectBytes
            //
            // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
            //
            val protectedHeaders = mapOf<CoseLabel, DataItem>(
                Pair(
                    CoseNumberLabel(Cose.COSE_LABEL_ALG),
                    Algorithm.ES256.coseAlgorithmIdentifier.toDataItem()
                )
            )
            val unprotectedHeaders = mapOf<CoseLabel, DataItem>(
                Pair(
                    CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                    X509CertChain(listOf(dsCert)).toDataItem()
                )
            )
            val encodedIssuerAuth = Cbor.encode(
                Cose.coseSign1Sign(
                    dsKey,
                    taggedEncodedMso,
                    true,
                    Algorithm.ES256,
                    protectedHeaders,
                    unprotectedHeaders
                ).toDataItem()
            )
            val issuerProvidedAuthenticationData = StaticAuthDataGenerator(
                MdocUtil.stripIssuerNameSpaces(issuerNameSpaces, exceptions),
                encodedIssuerAuth
            ).generate()

            // Now that we have issuer-provided authentication data we certify the authentication key.
            mdocCredential.certify(
                issuerProvidedAuthenticationData,
                timeValidityBegin,
                timeValidityEnd
            )

        }
    }

}