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
package com.android.identity.android.legacy

import androidx.test.InstrumentationRegistry
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.model.UnicodeString
import com.android.identity.android.legacy.Util.cborEncode
import com.android.identity.android.legacy.Util.cborEncodeBytestring
import com.android.identity.android.legacy.Util.cborEncodeNumber
import com.android.identity.android.legacy.Util.cborEncodeString
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.cbor.Cbor.toDiagnostics
import com.android.identity.cbor.DiagnosticOption
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto.checkSignature
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.toEcPublicKey
import com.android.identity.securearea.KeyPurpose
import com.android.identity.storage.StorageEngine
import com.android.identity.storage.android.AndroidStorage
import kotlinx.coroutines.runBlocking
import kotlinx.io.files.Path
import org.junit.Assert
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets

@Suppress("deprecation")
class MigrateFromKeystoreICStoreTest {
    // The two methods that can be used to migrate a credential from KeystoreIdentityCredentialStore
    // to CredentialStore are getNamedSpacedData() and getCredentialKey(). This test checks that
    // they work as expected..
    //
    @Test
    @Throws(Exception::class)
    fun testMigrateToCredentialStore() = runBlocking {
        val context = InstrumentationRegistry.getTargetContext()
        val storage = AndroidStorage(":memory:")
        val aksSecureArea = AndroidKeystoreSecureArea.create(context, storage)
        val icStore = Utility.getIdentityCredentialStore(context)

        val noAuthProfile =
            AccessControlProfile.Builder(AccessControlProfileId(0))
                .setUserAuthenticationRequired(false)
                .build()
        val ids: MutableCollection<AccessControlProfileId> = ArrayList()
        ids.add(AccessControlProfileId(0))

        val encodedDrivingPrivileges = cborEncode(
            CborBuilder()
                .addArray()
                .addMap()
                .put(
                    UnicodeString("vehicle_category_code"),
                    UnicodeString("A")
                )
                .end()
                .end()
                .build()[0]
        )

        val personalizationData =
            PersonalizationData.Builder()
                .addAccessControlProfile(noAuthProfile)
                .putEntry(MDL_NAMESPACE, "given_name", ids, cborEncodeString("Erika"))
                .putEntry(MDL_NAMESPACE, "family_name", ids, cborEncodeString("Mustermann"))
                .putEntry(MDL_NAMESPACE, "resident_address", ids, cborEncodeString("Germany"))
                .putEntry(
                    MDL_NAMESPACE,
                    "portrait",
                    ids,
                    cborEncodeBytestring(byteArrayOf(0x01, 0x02))
                )
                .putEntry(MDL_NAMESPACE, "height", ids, cborEncodeNumber(180))
                .putEntry(MDL_NAMESPACE, "driving_privileges", ids, encodedDrivingPrivileges)
                .putEntry(AAMVA_NAMESPACE, "weight_range", ids, cborEncodeNumber(5))
                .putEntry(TEST_NAMESPACE, "neg_int", ids, cborEncodeNumber(-42))
                .putEntry(TEST_NAMESPACE, "int_16", ids, cborEncodeNumber(0x101))
                .putEntry(TEST_NAMESPACE, "int_32", ids, cborEncodeNumber(0x10001))
                .putEntry(TEST_NAMESPACE, "int_64", ids, cborEncodeNumber(0x100000001L))
                .build()
        val credName = "test"
        icStore.deleteCredentialByName(credName)
        val wc = icStore.createCredential(credName, MDL_DOCTYPE)
        val wcCertChain =
            wc.getCredentialKeyCertificateChain("".toByteArray(StandardCharsets.UTF_8))
        val credentialKeyPublic = wcCertChain.iterator().next().publicKey
        wc.personalize(personalizationData)

        val cred = icStore.getCredentialByName(
            credName,
            IdentityCredentialStore.CIPHERSUITE_ECDHE_HKDF_ECDSA_WITH_AES_256_GCM_SHA256
        ) as KeystoreIdentityCredential?
        Assert.assertNotNull(cred)

        // Get and check NameSpacedData
        val nsd = cred!!.nameSpacedData
        Assert.assertEquals(
            """{
  "org.iso.18013.5.1": {
    "given_name": 24(<< "Erika" >>),
    "family_name": 24(<< "Mustermann" >>),
    "resident_address": 24(<< "Germany" >>),
    "portrait": 24(<< h'0102' >>),
    "height": 24(<< 180 >>),
    "driving_privileges": 24(<< [
      {
        "vehicle_category_code": "A"
      }
    ] >>)
  },
  "org.iso.18013.5.1.aamva": {
    "weight_range": 24(<< 5 >>)
  },
  "org.example.test": {
    "neg_int": 24(<< -42 >>),
    "int_16": 24(<< 257 >>),
    "int_32": 24(<< 65537 >>),
    "int_64": 24(<< 4294967297 >>)
  }
}""",
            toDiagnostics(
                nsd.encodeAsCbor(),
                setOf(DiagnosticOption.EMBEDDED_CBOR, DiagnosticOption.PRETTY_PRINT)
            )
        )

        val credentialKeyAlias = cred.credentialKeyAlias
        aksSecureArea.createKeyForExistingAlias(credentialKeyAlias)

        // Check that CrendentialKey's KeyInfo is correct
        val keyInfo = aksSecureArea.getKeyInfo(credentialKeyAlias)
        Assert.assertNotNull(keyInfo)
        val attestation = keyInfo.attestation
        Assert.assertTrue(attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertFalse(keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertEquals(setOf<Any>(), keyInfo.userAuthenticationTypes)
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)

        // Check that we can use CredentialKey via AndroidKeystoreSecureArea...
        val dataToSign = byteArrayOf(1, 2, 3)
        val ecSignature = aksSecureArea.sign(
            credentialKeyAlias,
            Algorithm.ES256,
            dataToSign,
            null
        )
        val ecCredentialKeyPublic = credentialKeyPublic.toEcPublicKey(EcCurve.P256)
        Assert.assertTrue(
            checkSignature(
                ecCredentialKeyPublic,
                dataToSign,
                Algorithm.ES256,
                ecSignature
            )
        )
    }

    companion object {
        private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
        private const val MDL_NAMESPACE = "org.iso.18013.5.1"
        private const val AAMVA_NAMESPACE = "org.iso.18013.5.1.aamva"
        private const val TEST_NAMESPACE = "org.example.test"
    }
}
