package com.android.identity_credential.wallet

import com.android.identity.device.DeviceAssertion
import com.android.identity.issuance.evidence.EvidenceResponseMessage
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.security.Security

class SelfSignedMdlTest {
    @Before
    fun setup() {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    private fun getProofingQuestions() : List<com.android.identity.issuance.evidence.EvidenceRequest> {
        return listOf<com.android.identity.issuance.evidence.EvidenceRequest>(
            com.android.identity.issuance.evidence.EvidenceRequestMessage(
                "Here's a long string with TOS",
                mapOf(),
                "Accept",
                "Do Not Accept",
            ),
            com.android.identity.issuance.evidence.EvidenceRequestQuestionString(
                "What first name should be used for the mDL?",
                mapOf(),
                "Erika",
                "Continue",
            ),
            com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice(
                "Select the card art for the credential",
                mapOf(),
                mapOf("green" to "Green", "blue" to "Blue", "red" to "Red"),
                "Continue",
            ),
            com.android.identity.issuance.evidence.EvidenceRequestMessage(
                "Your application is about to be sent the ID issuer for " +
                        "verification. You will get notified when the " +
                        "application is approved.",
                mapOf(),
                "Continue",
                null,
            )
        )
    }

    @Test
    fun happyPath() = runTest {
        val storage = EphemeralStorage()
        val secureArea = SoftwareSecureArea.create(storage)

        val ia = TestIssuingAuthority()

        // Register credential...
        val registerdocumentFlow = ia.register()
        val registrationConfiguration = registerdocumentFlow.getDocumentRegistrationConfiguration()
        val documentId = registrationConfiguration.documentId
        val registrationResponse = com.android.identity.issuance.RegistrationResponse(true)
        registerdocumentFlow.sendDocumentRegistrationResponse(registrationResponse)
        registerdocumentFlow.complete()

        // Check we're now in the proofing state.
        Assert.assertEquals(
            com.android.identity.issuance.DocumentCondition.PROOFING_REQUIRED,
            ia.getState(documentId).condition)

        // Perform proofing
        val proofingFlow = ia.proof(documentId)

        // First piece of evidence to return...
        var evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is com.android.identity.issuance.evidence.EvidenceRequestMessage)
        Assert.assertEquals("Here's a long string with TOS", (evidenceToGet[0] as com.android.identity.issuance.evidence.EvidenceRequestMessage).message)
        proofingFlow.sendEvidence(
            com.android.identity.issuance.evidence.EvidenceResponseMessage(
                true
            )
        )

        // Second piece of evidence to return...
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is com.android.identity.issuance.evidence.EvidenceRequestQuestionString)
        Assert.assertEquals(
            "What first name should be used for the mDL?",
            (evidenceToGet[0] as com.android.identity.issuance.evidence.EvidenceRequestQuestionString).message)
        Assert.assertEquals(
            "Erika",
            (evidenceToGet[0] as com.android.identity.issuance.evidence.EvidenceRequestQuestionString).defaultValue)
        proofingFlow.sendEvidence(
            com.android.identity.issuance.evidence.EvidenceResponseQuestionString(
                "Max"
            )
        )
        Assert.assertEquals(
            com.android.identity.issuance.DocumentCondition.PROOFING_REQUIRED,
            ia.getState(documentId).condition)

        // Third piece of evidence to return...
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice)
        Assert.assertEquals(3,
            (evidenceToGet[0] as com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice).possibleValues.size)
        proofingFlow.sendEvidence(
            com.android.identity.issuance.evidence.EvidenceResponseQuestionMultipleChoice(
                (evidenceToGet[0] as com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice).possibleValues.keys.iterator()
                    .next()
            )
        )

        // Fourth piece of evidence to return...
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is com.android.identity.issuance.evidence.EvidenceRequestMessage)
        Assert.assertTrue((evidenceToGet[0] as com.android.identity.issuance.evidence.EvidenceRequestMessage).message
            .startsWith("Your application is about to be sent"))
        proofingFlow.sendEvidence(
            EvidenceResponseMessage(
                true
            )
        )

        // Check there are no more pieces of evidence to return and it's now processing
        // after we signal that proofing is complete
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(0, evidenceToGet.size)
        proofingFlow.complete()

        Assert.assertEquals(
            com.android.identity.issuance.DocumentCondition.PROOFING_PROCESSING,
            ia.getState(documentId).condition)
        // Processing is hard-coded to take three seconds
        Thread.sleep(2100)
        Assert.assertEquals(
            com.android.identity.issuance.DocumentCondition.PROOFING_PROCESSING,
            ia.getState(documentId).condition)
        Thread.sleep(900)
        Assert.assertEquals(
            com.android.identity.issuance.DocumentCondition.CONFIGURATION_AVAILABLE,
            ia.getState(documentId).condition)

        // Check we can get the credential configuration
        val configuration = ia.getDocumentConfiguration(documentId)
        Assert.assertEquals("Max's Driving License", configuration.displayName)
        Assert.assertEquals(
            com.android.identity.issuance.DocumentCondition.READY,
            ia.getState(documentId).condition)

        // Check we can get CPOs, first request them
        val numMso = 5
        val requestCpoFlow = ia.requestCredentials(documentId)
        val authKeyConfiguration = requestCpoFlow.getCredentialConfiguration(com.android.identity.issuance.CredentialFormat.MDOC_MSO)
        val credentialRequests = mutableListOf<com.android.identity.issuance.CredentialRequest>()
        for (authKeyNumber in IntRange(0, numMso - 1)) {
            val alias = "AuthKey_$authKeyNumber"
            secureArea.createKey(alias, CreateKeySettings())
            credentialRequests.add(
                com.android.identity.issuance.CredentialRequest(secureArea.getKeyInfo(alias).attestation)
            )
        }
        requestCpoFlow.sendCredentials(
            credentialRequests,
            DeviceAssertion(ByteString(), ByteString())
        )
        requestCpoFlow.complete()

        // documentInformation should now reflect that the CPOs are pending and not
        // yet available..
        ia.getState(documentId).let {
            Assert.assertEquals(com.android.identity.issuance.DocumentCondition.READY, it.condition)
            Assert.assertEquals(5, it.numPendingCredentials)
            Assert.assertEquals(0, it.numAvailableCredentials)
        }
        Assert.assertEquals(0, ia.getCredentials(documentId).size)
        Thread.sleep(100)
        // Still not available...
        ia.getState(documentId).let {
            Assert.assertEquals(com.android.identity.issuance.DocumentCondition.READY, it.condition)
            Assert.assertEquals(5, it.numPendingCredentials)
            Assert.assertEquals(0, it.numAvailableCredentials)
        }
        Assert.assertEquals(0, ia.getCredentials(documentId).size)
        // But it is available after 3 seconds
        Thread.sleep(2900)
        ia.getState(documentId).let {
            Assert.assertEquals(com.android.identity.issuance.DocumentCondition.READY, it.condition)
            Assert.assertEquals(0, it.numPendingCredentials)
            Assert.assertEquals(5, it.numAvailableCredentials)
        }
        // Check we get 5 CPOs and that they match the keys we passed in..
        ia.getCredentials(documentId).let {
            Assert.assertEquals(5, it.size)
            for (n in IntRange(0, it.size - 1)) {
                Assert.assertEquals(
                    it[n].secureAreaBoundKey,
                    credentialRequests[n].secureAreaBoundKeyAttestation.publicKey
                )
            }
        }
        // Once we collected them, they are no longer available to be collected
        // and nothing is pending
        ia.getState(documentId).let {
            Assert.assertEquals(com.android.identity.issuance.DocumentCondition.READY, it.condition)
            Assert.assertEquals(0, it.numPendingCredentials)
            Assert.assertEquals(0, it.numAvailableCredentials)
        }
        Assert.assertEquals(0, ia.getCredentials(documentId).size)
    }

}