package com.android.identity.testapp

import com.android.identity.asn1.ASN1Integer
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
import com.android.identity.credential.CredentialFactory
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.X500Name
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.document.DocumentStore
import com.android.identity.document.NameSpacedData
import com.android.identity.documenttype.DocumentType
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.DocumentCannedRequest
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.request.DeviceRequestGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.securearea.software.SoftwareCreateKeySettings
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.storage.StorageEngine
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Logger
import identitycredential.samples.testapp.generated.resources.Res
import identitycredential.samples.testapp.generated.resources.driving_license_card_art
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
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

    const val MDOC_AUTH_KEY_DOMAIN = "mdoc_auth_key_domain"

    fun generateEncodedDeviceRequest(
        request: DocumentCannedRequest,
        encodedSessionTranscript: ByteArray
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

    private lateinit var documentData: NameSpacedData
    lateinit var documentStore: DocumentStore

    private val storageEngine: StorageEngine
    private val secureArea: SecureArea
    private val secureAreaRepository: SecureAreaRepository
    private val credentialFactory: CredentialFactory
    val documentTypeRepository: DocumentTypeRepository

    val provisionedDocumentTypes = listOf(
        DrivingLicense.getDocumentType(),
        PhotoID.getDocumentType(),
        EUPersonalID.getDocumentType()
    )

    private val certsValidFrom = LocalDate.parse("2024-12-01").atStartOfDayIn(TimeZone.UTC)
    private val certsValidUntil = LocalDate.parse("2034-12-01").atStartOfDayIn(TimeZone.UTC)

    private lateinit var dsKey: EcPrivateKey
    lateinit var dsKeyPub: EcPublicKey
    lateinit var dsCert: X509Cert

    private lateinit var iacaKey: EcPrivateKey
    lateinit var iacaKeyPub: EcPublicKey
    lateinit var iacaCert: X509Cert

    private lateinit var readerKey: EcPrivateKey
    lateinit var readerKeyPub: EcPublicKey
    lateinit var readerCert: X509Cert

    private lateinit var readerRootKey: EcPrivateKey
    lateinit var readerRootKeyPub: EcPublicKey
    lateinit var readerRootCert: X509Cert

    lateinit var issuerTrustManager: TrustManager
    lateinit var readerTrustManager: TrustManager

    init {
        storageEngine = EphemeralStorageEngine()
        secureAreaRepository = SecureAreaRepository()
        secureArea = SoftwareSecureArea(storageEngine)
        secureAreaRepository.addImplementation(secureArea)
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(MdocCredential::class) {
                document, dataItem -> MdocCredential(document, dataItem)
        }
        generateKeysAndCerts()
        generateTrustManagers()
        provisionDocuments()
        documentTypeRepository = DocumentTypeRepository()
        documentTypeRepository.addDocumentType(DrivingLicense.getDocumentType())
        documentTypeRepository.addDocumentType(PhotoID.getDocumentType())
        documentTypeRepository.addDocumentType(EUPersonalID.getDocumentType())
    }

    private fun generateKeysAndCerts() {
        iacaKeyPub = EcPublicKey.fromPem(
            """
                -----BEGIN PUBLIC KEY-----
                MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+
                wih+L79b7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH
                5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                -----END PUBLIC KEY-----
            """.trimIndent().trim(),
            EcCurve.P384
        )
        iacaKey = EcPrivateKey.fromPem(
            """
                -----BEGIN PRIVATE KEY-----
                MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                -----END PRIVATE KEY-----
            """.trimIndent().trim(),
            iacaKeyPub
        )
        iacaCert = MdocUtil.generateIacaCertificate(
            iacaKey = iacaKey,
            subject = X500Name.fromName("C=ZZ,CN=OWF Identity Credential TEST IACA"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
            issuerAltNameUrl = "https://github.com/openwallet-foundation-labs/identity-credential",
            crlUrl = "https://github.com/openwallet-foundation-labs/identity-credential"
        )

        dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
        dsKeyPub = dsKey.publicKey
        dsCert = MdocUtil.generateDsCertificate(
            iacaCert = iacaCert,
            iacaKey = iacaKey,
            dsKey = dsKeyPub,
            subject = X500Name.fromName("C=ZZ,CN=OWF Identity Credential TEST DS"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
        )

        readerRootKeyPub = EcPublicKey.fromPem(
            """
                -----BEGIN PUBLIC KEY-----
                MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+
                wih+L79b7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH
                5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                -----END PUBLIC KEY-----
            """.trimIndent().trim(),
            EcCurve.P384
        )
        readerRootKey = EcPrivateKey.fromPem(
            """
                -----BEGIN PRIVATE KEY-----
                MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                -----END PRIVATE KEY-----
            """.trimIndent().trim(),
            readerRootKeyPub
        )
        readerRootCert = MdocUtil.generateReaderRootCertificate(
            readerRootKey = iacaKey,
            subject = X500Name.fromName("CN=OWF IC TestApp Reader Root"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
        )

        readerKey = Crypto.createEcPrivateKey(EcCurve.P256)
        readerKeyPub = readerKey.publicKey
        readerCert = MdocUtil.generateReaderCertificate(
            readerRootCert = readerRootCert,
            readerRootKey = readerRootKey,
            readerKey = readerKeyPub,
            subject = X500Name.fromName("CN=OWF IC TestApp Reader Cert"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
        )
    }

    @OptIn(ExperimentalResourceApi::class)
    private fun generateTrustManagers() {
        issuerTrustManager = TrustManager()
        issuerTrustManager.addTrustPoint(
            TrustPoint(
                certificate = iacaCert,
                displayName = "OWF IC TestApp Issuer",
                displayIcon = null
            )
        )

        readerTrustManager = TrustManager()
        readerTrustManager.addTrustPoint(
            TrustPoint(
                certificate = readerRootCert,
                displayName = "OWF IC TestApp",
                displayIcon = runBlocking { Res.readBytes("files/utopia-brewery.png") }
            )
        )
    }

    private fun provisionDocuments() {
        documentStore = DocumentStore(
            storageEngine,
            secureAreaRepository,
            credentialFactory
        )

        provisionDocument(
            "testDrivingLicense",
            DrivingLicense.getDocumentType(),
            "Erika",
            "Erika's Driving License"
        )
        // Create two PhotoID instances
        provisionDocument(
            "testPhotoID",
            PhotoID.getDocumentType(),
            "Erika",
            "Erika's Photo ID"
        )
        provisionDocument(
            "testPhotoID2",
            PhotoID.getDocumentType(),
            "Erika #2",
            "Erika's Photo ID #2"
        )
        provisionDocument(
            "testEUPersonalID",
            EUPersonalID.getDocumentType(),
            "Erika",
            "Erika's Personal ID"
        )
    }

    // TODO: also provision SD-JWT credentials, if applicable
    @OptIn(ExperimentalResourceApi::class)
    private fun provisionDocument(
        documentId: String,
        documentType: DocumentType,
        givenNameOverride: String,
        displayName: String,
    ) {
        val document = documentStore.createDocument(documentId)

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
        documentData = nsdBuilder.build()

        // TODO: move ApplicationData for `documentData`, `cardArt`, `displayName` to real
        //  fields on Document.
        //
        document.applicationData.setNameSpacedData("documentData", documentData)
        val overrides: MutableMap<String, Map<String, ByteArray>> = HashMap()
        val exceptions: MutableMap<String, List<String>> = HashMap()

        runBlocking {
            val cardArt = getDrawableResourceBytes(
                getSystemResourceEnvironment(),
                Res.drawable.driving_license_card_art
            )
            document.applicationData.setData("cardArt", cardArt)
        }
        document.applicationData.setString("displayName", displayName)
        document.applicationData.setString("displayType", documentType.displayName)

        // Create an authentication key... make sure the authKey used supports both
        // mdoc ECDSA and MAC authentication.
        val now = Clock.System.now()
        val timeSigned = now - 1.hours
        val timeValidityBegin =  now - 1.hours
        val timeValidityEnd = now + 24.hours
        val mdocCredential = MdocCredential(
            document = document,
            asReplacementFor = null,
            domain = MDOC_AUTH_KEY_DOMAIN,
            secureArea = secureArea,
            createKeySettings = SoftwareCreateKeySettings.Builder()
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .build(),
            docType = documentType.mdocDocumentType!!.docType
        )

        // Generate an MSO and issuer-signed data for this authentication key.
        val msoGenerator = MobileSecurityObjectGenerator(
            "SHA-256",
            documentType.mdocDocumentType!!.docType,
            mdocCredential.attestation.publicKey
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
                X509CertChain(listOf(dsCert, iacaCert)).toDataItem()
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

        documentStore.addDocument(document)
    }

}