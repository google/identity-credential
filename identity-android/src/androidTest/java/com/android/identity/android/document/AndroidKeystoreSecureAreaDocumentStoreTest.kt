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
package com.android.identity.android.document

import androidx.test.InstrumentationRegistry
import com.android.identity.android.TestUtil
import com.android.identity.android.securearea.AndroidKeystoreCreateKeySettings
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.credential.CredentialFactory
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.document.DocumentStore
import com.android.identity.document.SimpleDocumentMetadata
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.Storage
import com.android.identity.storage.android.AndroidStorage
import com.android.identity.util.AndroidAttestationExtensionParser
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test

// See DocumentStoreTest in non-Android tests for main tests for DocumentStore. These
// tests are just for the Android-specific bits including attestation.
//
class AndroidKeystoreSecureAreaDocumentStoreTest {
    companion object {
        private const val CREDENTIAL_DOMAIN = "domain"
    }

    private lateinit var storage: Storage
    private lateinit var secureAreaRepository: SecureAreaRepository
    private lateinit var credentialFactory: CredentialFactory

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getTargetContext()
        storage = AndroidStorage(":memory:")
        secureAreaRepository = SecureAreaRepository.build {
            add(AndroidKeystoreSecureArea.create(context, storage))
        }
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(SecureAreaBoundCredential::class) {
            document -> SecureAreaBoundCredential(document)
        }
    }

    @Test
    fun testBasic() = runBlocking {
        val documentStore = DocumentStore(
            storage = storage,
            secureAreaRepository = secureAreaRepository,
            credentialFactory = credentialFactory,
            documentMetadataFactory = SimpleDocumentMetadata::create
        )
        val document = documentStore.createDocument()

        // Create pending credential and check its attestation
        val authKeyChallenge = byteArrayOf(20, 21, 22)
        val secureArea =
            secureAreaRepository.getImplementation(AndroidKeystoreSecureArea.IDENTIFIER)
        val pendingCredential = SecureAreaBoundCredential.create(
            document,
            null,
            CREDENTIAL_DOMAIN,
            secureArea!!,
            AndroidKeystoreCreateKeySettings.Builder(authKeyChallenge).build()
        )
        Assert.assertFalse(pendingCredential.isCertified)
        val attestation = pendingCredential.getAttestation()
        val parser =
            AndroidAttestationExtensionParser(attestation.certChain!!.certificates[0])
        Assert.assertArrayEquals(
            authKeyChallenge,
            parser.attestationChallenge
        )
        if (!TestUtil.isRunningOnEmulator) {
            Assert.assertEquals(
                AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT,
                parser.keymasterSecurityLevel
            )
        }

        // Check we can load the document...
        val document2 = documentStore.lookupDocument(document.identifier)
        Assert.assertSame(document2, document)

        Assert.assertNull(documentStore.lookupDocument("nonExistingDocument"))
    }
}
