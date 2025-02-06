/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.mdoc.response

import com.android.identity.asn1.ASN1Integer
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.Tstr
import com.android.identity.cbor.toDataItem
import com.android.identity.cose.Cose
import com.android.identity.cose.CoseLabel
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.credential.CredentialFactory
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.document.Document
import com.android.identity.document.DocumentRequest
import com.android.identity.document.DocumentRequest.DataElement
import com.android.identity.document.DocumentStore
import com.android.identity.document.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.X500Name
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.securearea.software.SoftwareCreateKeySettings
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.Storage
import com.android.identity.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceResponseGeneratorTest {
    private lateinit var storage: Storage
    private lateinit var secureAreaRepository: SecureAreaRepository
    private lateinit var credentialFactory: CredentialFactory

    private lateinit  var mdocCredential: MdocCredential
    private lateinit  var document: Document
    private lateinit  var timeSigned: Instant
    private lateinit  var timeValidityBegin: Instant
    private lateinit  var timeValidityEnd: Instant
    private lateinit  var dsKey: EcPrivateKey
    private lateinit  var dsCert: X509Cert

    @BeforeTest
    fun setup() {
        storage = EphemeralStorage()
        secureAreaRepository = SecureAreaRepository.build {
            add(SoftwareSecureArea.create(storage))
        }
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(MdocCredential::class) {
            document -> MdocCredential(document)
        }
    }

    // This isn't really used, we only use a single domain.
    private val AUTH_KEY_DOMAIN = "domain"
    private val MDOC_CREDENTIAL_IDENTIFIER = "MdocCredential"

    private suspend fun provisionDocument() {
        val documentStore = DocumentStore(
            storage,
            secureAreaRepository,
            credentialFactory,
            TestDocumentMetadata::create
        )

        // Create the document...
        document = documentStore.createDocument()
        val nameSpacedData = NameSpacedData.Builder()
            .putEntryString("ns1", "foo1", "bar1")
            .putEntryString("ns1", "foo2", "bar2")
            .putEntryString("ns1", "foo3", "bar3")
            .putEntryString("ns2", "bar1", "foo1")
            .putEntryString("ns2", "bar2", "foo2")
            .build()
        document.testMetadata.setNameSpacedData(nameSpacedData)
        val overrides: MutableMap<String, Map<String, ByteArray>> = HashMap()
        val overridesForNs1: MutableMap<String, ByteArray> = HashMap()
        overridesForNs1["foo3"] = Cbor.encode(Tstr("bar3_override"))
        overrides["ns1"] = overridesForNs1
        val exceptions: MutableMap<String, List<String>> = HashMap()
        exceptions["ns1"] = mutableListOf("foo3")
        exceptions["ns2"] = mutableListOf("bar2")

        // Create an authentication key... make sure the authKey used supports both
        // mdoc ECDSA and MAC authentication.
        val nowSeconds = Clock.System.now().epochSeconds
        timeSigned = Instant.fromEpochSeconds(nowSeconds)
        timeValidityBegin = Instant.fromEpochSeconds(nowSeconds + 3600)
        timeValidityEnd = Instant.fromEpochSeconds(nowSeconds + 10 * 86400)
        mdocCredential = MdocCredential.create(
            document,
            null,
            AUTH_KEY_DOMAIN,
            secureAreaRepository.getImplementation(SoftwareSecureArea.IDENTIFIER)!!,
            "org.iso.18013.5.1.mDL",
            SoftwareCreateKeySettings.Builder()
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .build()
        )
        assertFalse(mdocCredential.isCertified)

        // Generate an MSO and issuer-signed data for this authentication key.
        val msoGenerator = MobileSecurityObjectGenerator(
            "SHA-256",
            DOC_TYPE,
            mdocCredential.getAttestation().publicKey
        )
        msoGenerator.setValidityInfo(timeSigned, timeValidityBegin, timeValidityEnd, null)
        val issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
            nameSpacedData,
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
        val validFrom = Clock.System.now()
        val validUntil = Instant.fromEpochMilliseconds(
            validFrom.toEpochMilliseconds() + 5L * 365 * 24 * 60 * 60 * 1000
        )
        dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
        dsCert = X509Cert.Builder(
            publicKey = dsKey.publicKey,
            signingKey = dsKey,
            signatureAlgorithm = Algorithm.ES256,
            serialNumber = ASN1Integer(1),
            subject = X500Name.fromName("CN=State of Utopia DS Key"),
            issuer = X500Name.fromName("CN=State of Utopia DS Key"),
            validFrom = validFrom,
            validUntil = validUntil
        ).build()
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

    @Test
    fun testDocumentGeneratorEcdsa() = runTest {
        provisionDocument()

        // OK, now do the request... request a strict subset of the data in the document
        // and also request data not in the document.
        val dataElements = listOf(
            DataElement("ns1", "foo1", false, false),
            DataElement("ns1", "foo2", false, false),
            DataElement("ns1", "foo3", false, false),
            DataElement("ns2", "bar1", false, false),
            DataElement("ns2", "does_not_exist", false, false),
            DataElement("ns_does_not_exist", "boo", false, false)
        )
        val request = DocumentRequest(dataElements)
        val encodedSessionTranscript = Cbor.encode(Tstr("Doesn't matter"))

        val staticAuthData = StaticAuthDataParser(mdocCredential.issuerProvidedData)
            .parse()
        val mergedIssuerNamespaces: Map<String, List<ByteArray>> =
            MdocUtil.mergeIssuerNamesSpaces(
                request,
                document.testMetadata.nameSpacedData,
                staticAuthData
            )
        val deviceResponseGenerator = DeviceResponseGenerator(0)
        deviceResponseGenerator.addDocument(
            DocumentGenerator(DOC_TYPE, staticAuthData.issuerAuth, encodedSessionTranscript)
                .setIssuerNamespaces(mergedIssuerNamespaces)
                .setDeviceNamespacesSignature(
                    NameSpacedData.Builder().build(),
                    mdocCredential.secureArea,
                    mdocCredential.alias,
                    null,
                    Algorithm.ES256
                )
                .generate()
        )
        val encodedDeviceResponse = deviceResponseGenerator.generate()

        // To verify, parse the response...
        val parser = DeviceResponseParser(
            encodedDeviceResponse,
            encodedSessionTranscript
        )
        val deviceResponse = parser.parse()
        assertEquals(1, deviceResponse.documents.size.toLong())
        val doc = deviceResponse.documents[0]

        // Check the MSO was properly signed.
        assertEquals(1, doc.issuerCertificateChain.certificates.size.toLong())
        assertEquals(dsCert, doc.issuerCertificateChain.certificates[0])
        assertEquals(DOC_TYPE, doc.docType)
        assertEquals(timeSigned, doc.validityInfoSigned)
        assertEquals(timeValidityBegin, doc.validityInfoValidFrom)
        assertEquals(timeValidityEnd, doc.validityInfoValidUntil)
        assertNull(doc.validityInfoExpectedUpdate)

        // Check DeviceSigned data
        assertEquals(0, doc.deviceNamespaces.size.toLong())
        // Check the key which signed DeviceSigned was the expected one.
        assertEquals(mdocCredential.getAttestation().publicKey, doc.deviceKey)
        // Check DeviceSigned was correctly authenticated.
        assertTrue(doc.deviceSignedAuthenticated)
        assertTrue(doc.deviceSignedAuthenticatedViaSignature)

        // Check IssuerSigned data didn't have any digest failures (meaning all the hashes were correct).
        assertEquals(0, doc.numIssuerEntryDigestMatchFailures.toLong())
        // Check IssuerSigned data was correctly authenticated.
        assertTrue(doc.issuerSignedAuthenticated)

        // Check Issuer Signed data
        assertEquals(2, doc.issuerNamespaces.size.toLong())
        assertEquals("ns1", doc.issuerNamespaces[0])
        assertEquals(3, doc.getIssuerEntryNames("ns1").size.toLong())
        assertEquals("bar1", doc.getIssuerEntryString("ns1", "foo1"))
        assertEquals("bar2", doc.getIssuerEntryString("ns1", "foo2"))
        assertEquals("bar3_override", doc.getIssuerEntryString("ns1", "foo3"))
        assertEquals("ns2", doc.issuerNamespaces[1])
        assertEquals(1, doc.getIssuerEntryNames("ns2").size.toLong())
        assertEquals("foo1", doc.getIssuerEntryString("ns2", "bar1"))
    }

    @Test
    fun testDocumentGeneratorMac() = runTest {
        provisionDocument()

        // Also check that Mac authentication works. This requires creating an ephemeral
        // reader key... we generate a new response, parse it, and check that the
        // DeviceSigned part is as expected.
        val dataElements = listOf(
            DataElement("ns1", "foo1", false, false),
            DataElement("ns1", "foo2", false, false),
            DataElement("ns1", "foo3", false, false),
            DataElement("ns2", "bar1", false, false),
            DataElement("ns2", "does_not_exist", false, false),
            DataElement("ns_does_not_exist", "boo", false, false)
        )
        val request = DocumentRequest(dataElements)
        val encodedSessionTranscript = Cbor.encode(Tstr("Doesn't matter"))
        val staticAuthData = StaticAuthDataParser(mdocCredential.issuerProvidedData)
            .parse()
        val eReaderKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val mergedIssuerNamespaces: Map<String, List<ByteArray>> = MdocUtil.mergeIssuerNamesSpaces(
            request,
            document.testMetadata.nameSpacedData,
            staticAuthData
        )
        val deviceResponseGenerator = DeviceResponseGenerator(0)
        deviceResponseGenerator.addDocument(
            DocumentGenerator(DOC_TYPE, staticAuthData.issuerAuth, encodedSessionTranscript)
                .setIssuerNamespaces(mergedIssuerNamespaces)
                .setDeviceNamespacesMac(
                    NameSpacedData.Builder().build(),
                    mdocCredential.secureArea,
                    mdocCredential.alias,
                    null,
                    eReaderKey.publicKey
                )
                .generate()
        )
        val encodedDeviceResponse = deviceResponseGenerator.generate()

        val parser = DeviceResponseParser(
            encodedDeviceResponse,
            encodedSessionTranscript
        )
        parser.setEphemeralReaderKey(eReaderKey)
        val deviceResponse = parser.parse()
        assertEquals(1, deviceResponse.documents.size.toLong())
        val doc = deviceResponse.documents[0]
        assertTrue(doc.deviceSignedAuthenticated)
        assertFalse(doc.deviceSignedAuthenticatedViaSignature)
    }

    @Test
    fun testDeviceSigned() = runTest {
        provisionDocument()

        val dataElements = listOf(
            DataElement("ns1", "foo1", false, false),
            DataElement("ns1", "foo2", false, false),
            DataElement("ns1", "foo3", false, false),
            DataElement("ns2", "bar1", false, false),
            DataElement("ns2", "does_not_exist", false, false),
            DataElement("ns_does_not_exist", "boo", false, false)
        )
        val eReaderKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val request = DocumentRequest(dataElements)
        val encodedSessionTranscript = Cbor.encode(Tstr("Doesn't matter"))
        val staticAuthData = StaticAuthDataParser(mdocCredential.issuerProvidedData)
            .parse()
        val mergedIssuerNamespaces: Map<String, List<ByteArray>> = MdocUtil.mergeIssuerNamesSpaces(
            request,
            document.testMetadata.nameSpacedData,
            staticAuthData
        )

        // Check that DeviceSigned works.
        val deviceSignedData = NameSpacedData.Builder()
            .putEntryString("ns1", "foo1", "bar1_override")
            .putEntryString("ns3", "baz1", "bah1")
            .putEntryString("ns4", "baz2", "bah2")
            .putEntryString("ns4", "baz3", "bah3")
            .build()
        val deviceResponseGenerator = DeviceResponseGenerator(0)
        deviceResponseGenerator.addDocument(
            DocumentGenerator(DOC_TYPE, staticAuthData.issuerAuth, encodedSessionTranscript)
                .setIssuerNamespaces(mergedIssuerNamespaces)
                .setDeviceNamespacesSignature(
                    deviceSignedData,
                    mdocCredential.secureArea,
                    mdocCredential.alias,
                    null,
                    Algorithm.ES256
                )
                .generate()
        )
        val encodedDeviceResponse = deviceResponseGenerator.generate()

        val parser = DeviceResponseParser(
            encodedDeviceResponse,
            encodedSessionTranscript
        )
        parser.setEphemeralReaderKey(eReaderKey)
        val deviceResponse = parser.parse()
        assertEquals(1, deviceResponse.documents.size.toLong())
        val doc = deviceResponse.documents[0]
        assertTrue(doc.deviceSignedAuthenticated)
        assertTrue(doc.deviceSignedAuthenticatedViaSignature)
        // Check all Issuer Signed data is still there
        assertEquals(2, doc.issuerNamespaces.size.toLong())
        assertEquals("ns1", doc.issuerNamespaces[0])
        assertEquals(3, doc.getIssuerEntryNames("ns1").size.toLong())
        assertEquals("bar1", doc.getIssuerEntryString("ns1", "foo1"))
        assertEquals("bar2", doc.getIssuerEntryString("ns1", "foo2"))
        assertEquals("bar3_override", doc.getIssuerEntryString("ns1", "foo3"))
        assertEquals("ns2", doc.issuerNamespaces[1])
        assertEquals(1, doc.getIssuerEntryNames("ns2").size.toLong())
        assertEquals("foo1", doc.getIssuerEntryString("ns2", "bar1"))
        // Check all Device Signed data is there
        assertEquals(3, doc.deviceNamespaces.size.toLong())
        assertEquals("ns1", doc.deviceNamespaces[0])
        assertEquals(1, doc.getDeviceEntryNames("ns1").size.toLong())
        assertEquals("bar1_override", doc.getDeviceEntryString("ns1", "foo1"))
        assertEquals("ns3", doc.deviceNamespaces[1])
        assertEquals(1, doc.getDeviceEntryNames("ns3").size.toLong())
        assertEquals("bah1", doc.getDeviceEntryString("ns3", "baz1"))
        assertEquals("ns4", doc.deviceNamespaces[2])
        assertEquals(2, doc.getDeviceEntryNames("ns4").size.toLong())
        assertEquals("bah2", doc.getDeviceEntryString("ns4", "baz2"))
        assertEquals("bah3", doc.getDeviceEntryString("ns4", "baz3"))
    }

    @Test
    fun testDeviceSignedOnly() = runTest {
        provisionDocument()

        val encodedSessionTranscript = Cbor.encode(Tstr("Doesn't matter"))
        val staticAuthData = StaticAuthDataParser(mdocCredential.issuerProvidedData)
            .parse()

        // Check that DeviceSigned works.
        val deviceSignedData = NameSpacedData.Builder()
            .putEntryString("ns1", "foo1", "bar1_override")
            .putEntryString("ns3", "baz1", "bah1")
            .putEntryString("ns4", "baz2", "bah2")
            .putEntryString("ns4", "baz3", "bah3")
            .build()
        val eReaderKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val deviceResponseGenerator = DeviceResponseGenerator(0)
        deviceResponseGenerator.addDocument(
            DocumentGenerator(DOC_TYPE, staticAuthData.issuerAuth, encodedSessionTranscript)
                .setDeviceNamespacesSignature(
                    deviceSignedData,
                    mdocCredential.secureArea,
                    mdocCredential.alias,
                    null,
                    Algorithm.ES256
                )
                .generate()
        )
        val encodedDeviceResponse = deviceResponseGenerator.generate()
        val parser = DeviceResponseParser(
            encodedDeviceResponse,
            encodedSessionTranscript
        )
        parser.setEphemeralReaderKey(eReaderKey)
        val deviceResponse = parser.parse()
        assertEquals(1, deviceResponse.documents.size.toLong())
        val doc = deviceResponse.documents[0]
        assertTrue(doc.deviceSignedAuthenticated)
        assertTrue(doc.deviceSignedAuthenticatedViaSignature)
        // Check there is no Issuer Signed data
        assertEquals(0, doc.issuerNamespaces.size.toLong())
        // Check all Device Signed data is there
        assertEquals(3, doc.deviceNamespaces.size.toLong())
        assertEquals("ns1", doc.deviceNamespaces[0])
        assertEquals(1, doc.getDeviceEntryNames("ns1").size.toLong())
        assertEquals("bar1_override", doc.getDeviceEntryString("ns1", "foo1"))
        assertEquals("ns3", doc.deviceNamespaces[1])
        assertEquals(1, doc.getDeviceEntryNames("ns3").size.toLong())
        assertEquals("bah1", doc.getDeviceEntryString("ns3", "baz1"))
        assertEquals("ns4", doc.deviceNamespaces[2])
        assertEquals(2, doc.getDeviceEntryNames("ns4").size.toLong())
        assertEquals("bah2", doc.getDeviceEntryString("ns4", "baz2"))
        assertEquals("bah3", doc.getDeviceEntryString("ns4", "baz3"))
    }

    @Test
    fun testDocumentGeneratorDoNotSend() = runTest {
        provisionDocument()

        val ns1_foo2 = DataElement("ns1", "foo2", false, false)
        ns1_foo2.doNotSend = true
        val dataElements = listOf(
            DataElement("ns1", "foo1", false, false),
            ns1_foo2,
            DataElement("ns1", "foo3", false, false),
            DataElement("ns2", "bar1", false, false),
            DataElement("ns2", "does_not_exist", false, false),
            DataElement("ns_does_not_exist", "boo", false, false)
        )
        val request = DocumentRequest(dataElements)
        val encodedSessionTranscript = Cbor.encode(Tstr("Doesn't matter"))

        val staticAuthData = StaticAuthDataParser(mdocCredential.issuerProvidedData)
            .parse()
        val mergedIssuerNamespaces: Map<String, List<ByteArray>> =
            MdocUtil.mergeIssuerNamesSpaces(
                request,
                document.testMetadata.nameSpacedData,
                staticAuthData
            )
        val deviceResponseGenerator = DeviceResponseGenerator(0)
        deviceResponseGenerator.addDocument(
            DocumentGenerator(DOC_TYPE, staticAuthData.issuerAuth, encodedSessionTranscript)
                .setIssuerNamespaces(mergedIssuerNamespaces)
                .setDeviceNamespacesSignature(
                    NameSpacedData.Builder().build(),
                    mdocCredential.secureArea,
                    mdocCredential.alias,
                    null,
                    Algorithm.ES256
                )
                .generate()
        )
        val encodedDeviceResponse = deviceResponseGenerator.generate()

        // To verify, parse the response...
        val parser = DeviceResponseParser(
            encodedDeviceResponse,
            encodedSessionTranscript
        )
        val deviceResponse = parser.parse()
        assertEquals(1, deviceResponse.documents.size.toLong())
        val doc = deviceResponse.documents[0]

        // Check the MSO was properly signed.
        assertEquals(1, doc.issuerCertificateChain.certificates.size.toLong())
        assertEquals(dsCert, doc.issuerCertificateChain.certificates[0])
        assertEquals(DOC_TYPE, doc.docType)
        assertEquals(timeSigned, doc.validityInfoSigned)
        assertEquals(timeValidityBegin, doc.validityInfoValidFrom)
        assertEquals(timeValidityEnd, doc.validityInfoValidUntil)
        assertNull(doc.validityInfoExpectedUpdate)

        // Check DeviceSigned data
        assertEquals(0, doc.deviceNamespaces.size.toLong())
        // Check the key which signed DeviceSigned was the expected one.
        assertEquals(mdocCredential.getAttestation().publicKey, doc.deviceKey)
        // Check DeviceSigned was correctly authenticated.
        assertTrue(doc.deviceSignedAuthenticated)
        assertTrue(doc.deviceSignedAuthenticatedViaSignature)

        // Check IssuerSigned data didn't have any digest failures (meaning all the hashes were correct).
        assertEquals(0, doc.numIssuerEntryDigestMatchFailures.toLong())
        // Check IssuerSigned data was correctly authenticated.
        assertTrue(doc.issuerSignedAuthenticated)

        // Check Issuer Signed data
        assertEquals(2, doc.issuerNamespaces.size.toLong())
        assertEquals("ns1", doc.issuerNamespaces[0])
        assertEquals(2, doc.getIssuerEntryNames("ns1").size.toLong())
        assertEquals("bar1", doc.getIssuerEntryString("ns1", "foo1"))
        // Note: "ns1", "foo2" is not returned b/c it was marked as DoNotSend() above
        assertEquals("bar3_override", doc.getIssuerEntryString("ns1", "foo3"))
        assertEquals("ns2", doc.issuerNamespaces[1])
        assertEquals(1, doc.getIssuerEntryNames("ns2").size.toLong())
        assertEquals("foo1", doc.getIssuerEntryString("ns2", "bar1"))
    }

    companion object {
        const val DOC_TYPE = "com.example.document_xyz"
    }
}