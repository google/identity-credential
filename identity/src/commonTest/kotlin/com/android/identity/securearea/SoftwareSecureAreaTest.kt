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
package com.android.identity.securearea

import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.securearea.software.SoftwareCreateKeySettings
import com.android.identity.securearea.software.SoftwareKeyUnlockData
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

class SoftwareSecureAreaTest {
    @Test
    fun testEcKeyDeletion() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)

        // First create the key...
        ks.createKey(
            "testKey",
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        val keyInfo = ks.getKeyInfo("testKey")

        // Now delete it...
        ks.deleteKey("testKey")

        // Now that we know the key doesn't exist, check that ecKeySign() throws
        try {
            ks.sign("testKey", Algorithm.ES256, byteArrayOf(1, 2), null)
            fail()
        } catch (e: IllegalArgumentException) {
            // Expected path.
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // Now delete it again, this should not fail.
        ks.deleteKey("testKey")
    }

    @Test
    fun testEcKeySigning() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        ks.createKey(
            "testKey",
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        val keyInfo = ks.getKeyInfo("testKey")
        assertNotNull(keyInfo)
        assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        assertFalse(keyInfo.isPassphraseProtected)
        assertNull(keyInfo.passphraseConstraints)
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
        assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    fun testEcKeyCreate() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        ks.createKey(
            "testKey",
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        val keyInfo = ks.getKeyInfo("testKey")
        assertNotNull(keyInfo)
        assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        assertFalse(keyInfo.isPassphraseProtected)
        assertNull(keyInfo.passphraseConstraints)
    }
    
    @Test
    fun testEcKeyWithGenericCreateKeySettings() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val challenge = byteArrayOf(1, 2, 3)
        ks.createKey("testKey", CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256))
        val keyInfo = ks.getKeyInfo("testKey")
        assertNotNull(keyInfo)
        assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        assertFalse(keyInfo.isPassphraseProtected)
        assertNull(keyInfo.passphraseConstraints)

        // TODO: Check challenge.
        //val cert = keyInfo.attestation.certificates[0].javaX509Certificate
        //assertContentEquals(challenge, getChallenge(cert))
    }

    @Test
    fun testEcKeySigningWithKeyWithoutCorrectPurpose() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        ks.createKey(
            "testKey",
            SoftwareCreateKeySettings.Builder()
                .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .build()
        )
        val dataToSign = byteArrayOf(4, 5, 6)
        try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
            fail("Signing shouldn't work with a key w/o purpose SIGN")
        } catch (e: IllegalArgumentException) {
            assertEquals("Key does not have purpose SIGN", e.message)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
    }

    @Test
    fun testEcdh() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)
        ks.createKey(
            "testKey",
            SoftwareCreateKeySettings.Builder()
                .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .build()
        )
        val keyInfo = ks.getKeyInfo("testKey")
        assertNotNull(keyInfo)
        assertEquals(setOf(KeyPurpose.AGREE_KEY), keyInfo.keyPurposes)
        assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        assertFalse(keyInfo.isPassphraseProtected)
        assertNull(keyInfo.passphraseConstraints)

        // First do the ECDH from the perspective of our side...
        val ourSharedSecret: ByteArray
        ourSharedSecret = try {
            ks.keyAgreement(
                "testKey",
                otherKey.publicKey,
                null
            )
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // ...now do it from the perspective of the other side...
        val theirSharedSecret = Crypto.keyAgreement(otherKey, keyInfo.publicKey)

        // ... finally, check that both sides compute the same shared secret.
        assertContentEquals(theirSharedSecret, ourSharedSecret)
    }

    @Test
    fun testEcdhAndSigning() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)
        ks.createKey(
            "testKey",
            SoftwareCreateKeySettings.Builder()
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .build()
        )
        val keyInfo = ks.getKeyInfo("testKey")
        assertNotNull(keyInfo)
        assertEquals(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY), keyInfo.keyPurposes)
        assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        assertFalse(keyInfo.isPassphraseProtected)
        assertNull(keyInfo.passphraseConstraints)

        // First do the ECDH from the perspective of our side...
        val ourSharedSecret: ByteArray
        ourSharedSecret = try {
            ks.keyAgreement(
                "testKey",
                otherKey.publicKey,
                null
            )
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // ...now do it from the perspective of the other side...
        val theirSharedSecret = Crypto.keyAgreement(otherKey, keyInfo.publicKey)

        // ... finally, check that both sides compute the same shared secret.
        assertContentEquals(theirSharedSecret, ourSharedSecret)

        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
        assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    fun testEcdhWithoutCorrectPurpose() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)
        ks.createKey(
            "testKey",
            SoftwareCreateKeySettings.Builder() //.setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .build()
        )
        try {
            ks.keyAgreement(
                "testKey",
                otherKey.publicKey,
                null
            )
            fail("ECDH shouldn't work with a key w/o purpose AGREE_KEY")
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        } catch (e: IllegalArgumentException) {
            assertEquals("Key does not have purpose AGREE_KEY", e.message)
        }
    }

    @Test
    fun testEcKeySigningWithLockedKey() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val passphrase = "verySekrit"
        val passphraseConstraints = PassphraseConstraints.PIN_SIX_DIGITS
        ks.createKey(
            "testKey",
            SoftwareCreateKeySettings.Builder()
                .setPassphraseRequired(true, passphrase, passphraseConstraints)
                .build()
        )
        val keyInfo = ks.getKeyInfo("testKey")
        assertNotNull(keyInfo)
        assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        assertTrue(keyInfo.isPassphraseProtected)
        assertNotNull(keyInfo.passphraseConstraints)
        assertEquals(keyInfo.passphraseConstraints, passphraseConstraints)
        val dataToSign = byteArrayOf(4, 5, 6)
        try {
            ks.sign(
                "testKey",
                Algorithm.ES256,
                dataToSign,
                null
            )
            fail()
        } catch (e: KeyLockedException) {
            // This is the expected path.
        }

        // Try with the wrong passphrase. This should fail.
        try {
            ks.sign(
                "testKey",
                Algorithm.ES256,
                dataToSign,
                SoftwareKeyUnlockData("wrongPassphrase")
            )
            fail()
        } catch (e: KeyLockedException) {
            // This is the expected path.
        }

        // ... and with the right passphrase. This should work.
        val signature = try {
            ks.sign(
                "testKey",
                Algorithm.ES256,
                dataToSign,
                SoftwareKeyUnlockData(passphrase)
            )
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // Verify the signature is correct.
        assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    fun testEcKeyCreationOverridesExistingAlias() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        ks.createKey(
            "testKey",
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        val keyInfoOld = ks.getKeyInfo("testKey")
        val certChainOld = keyInfoOld.attestation
        ks.createKey(
            "testKey",
            CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256)
        )
        val keyInfo = ks.getKeyInfo("testKey")
        val certChain = keyInfo.attestation
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // Check new key is a different cert chain.
        assertNotEquals(certChainOld, certChain)

        // Check new key is used to sign.
        assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    fun testEcKeySigningAllCurves() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val curvesSupportingSigning = setOf(
            EcCurve.P256,
            EcCurve.P384,
            EcCurve.P521,
            EcCurve.BRAINPOOLP256R1,
            EcCurve.BRAINPOOLP320R1,
            EcCurve.BRAINPOOLP384R1,
            EcCurve.BRAINPOOLP512R1,
            EcCurve.ED25519,
            EcCurve.ED448
        ).intersect(Crypto.supportedCurves)
        for (ecCurve in curvesSupportingSigning) {
            ks.createKey(
                "testKey",
                SoftwareCreateKeySettings.Builder()
                    .setEcCurve(ecCurve)
                    .build()
            )
            val keyInfo = ks.getKeyInfo("testKey")
            assertNotNull(keyInfo)
                assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
            assertEquals(ecCurve, keyInfo.publicKey.curve)
            assertFalse(keyInfo.isPassphraseProtected)
            assertNull(keyInfo.passphraseConstraints)
            val signatureAlgorithms = when (ecCurve) {
                EcCurve.P256,
                EcCurve.P384,
                EcCurve.P521,
                EcCurve.BRAINPOOLP256R1,
                EcCurve.BRAINPOOLP320R1,
                EcCurve.BRAINPOOLP384R1,
                EcCurve.BRAINPOOLP512R1 -> {
                        arrayOf(
                            Algorithm.ES256,
                            Algorithm.ES384,
                            Algorithm.ES512
                        )
                }
                EcCurve.ED25519,
                EcCurve.ED448 -> {
                    arrayOf(Algorithm.EDDSA)
                }
                else -> throw AssertionError()
            }
            for (signatureAlgorithm in signatureAlgorithms) {
                val dataToSign = byteArrayOf(4, 5, 6)
                val derSignature = try {
                    ks.sign("testKey", signatureAlgorithm, dataToSign, null)
                } catch (e: KeyLockedException) {
                    throw AssertionError(e)
                }
                assertTrue(
                    Crypto.checkSignature(
                        keyInfo.publicKey,
                        dataToSign,
                        signatureAlgorithm,
                        derSignature
                    )
                )
            }
        }
    }

    @Test
    fun testEcKeyEcdhAllCurves() = runTest {
        val storage = EphemeralStorage()
        val ks = SoftwareSecureArea.create(storage)
        val curvesSupportingKeyAgreement = arrayOf(
            EcCurve.P256,
            EcCurve.P384,
            EcCurve.P521,
            EcCurve.BRAINPOOLP256R1,
            EcCurve.BRAINPOOLP320R1,
            EcCurve.BRAINPOOLP384R1,
            EcCurve.BRAINPOOLP512R1,
            EcCurve.X25519,
            EcCurve.X448
        ).intersect(Crypto.supportedCurves)
        for (ecCurve in curvesSupportingKeyAgreement) {
            var otherKey = Crypto.createEcPrivateKey(ecCurve)

            ks.createKey(
                "testKey",
                SoftwareCreateKeySettings.Builder()
                    .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                    .setEcCurve(ecCurve)
                    .build()
            )
            val keyInfo = ks.getKeyInfo("testKey")
            assertNotNull(keyInfo)
                assertEquals(setOf(KeyPurpose.AGREE_KEY), keyInfo.keyPurposes)
            assertEquals(ecCurve, keyInfo.publicKey.curve)
            assertFalse(keyInfo.isPassphraseProtected)
            assertNull(keyInfo.passphraseConstraints)

            // First do the ECDH from the perspective of our side...
            var ourSharedSecret: ByteArray
            ourSharedSecret = try {
                ks.keyAgreement(
                    "testKey",
                    otherKey.publicKey,
                    null
                )
            } catch (e: KeyLockedException) {
                throw AssertionError(e)
            }

            // ...now do it from the perspective of the other side...
            var theirSharedSecret = Crypto.keyAgreement(otherKey, keyInfo.publicKey)

            // ... finally, check that both sides compute the same shared secret.
            assertContentEquals(theirSharedSecret, ourSharedSecret)
        }
    }
}
