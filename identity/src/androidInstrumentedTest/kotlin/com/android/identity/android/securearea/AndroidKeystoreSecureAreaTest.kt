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
package com.android.identity.android.securearea

import android.content.Context
import android.content.pm.PackageManager
import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.icu.util.TimeZone
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.InstrumentationRegistry
import com.android.identity.android.TestUtil
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyInfo
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.storage.KeyExistsStorageException
import com.android.identity.storage.android.AndroidStorage
import com.android.identity.util.AndroidAttestationExtensionParser
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert
import org.junit.Assume
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateException
import kotlinx.datetime.Instant.Companion.fromEpochMilliseconds

class AndroidKeystoreSecureAreaTest {

    private lateinit var secureAreaProvider: SecureAreaProvider<AndroidKeystoreSecureArea>

    @Before
    fun setup() {
        // This is needed to prefer BouncyCastle bundled with the app instead of the Conscrypt
        // based implementation included in Android.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())


        val context = InstrumentationRegistry.getTargetContext()
        val storage = AndroidStorage(databasePath = null, clock = Clock.System)
        secureAreaProvider = SecureAreaProvider {
            AndroidKeystoreSecureArea.create(context, storage)
        }
    }

    @Test
    fun testEcKeyDeletion() = runTest {
        val settings = AndroidKeystoreCreateKeySettings.Builder(byteArrayOf(1, 2, 3)).build()

        val ks = secureAreaProvider.get()

        // First create the key...
        ks.createKey("testKey", settings)

        // Now delete it...
        ks.deleteKey("testKey")

        // Now that we know the key doesn't exist, check that ecKeySign() throws
        try {
            ks.sign("testKey", Algorithm.ES256, byteArrayOf(1, 2), null)
            Assert.fail()
        } catch (e: IllegalArgumentException) {
            // Expected path.
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // Now delete it again, this should not fail.
        ks.deleteKey("testKey")
    }

    @Test
    fun testEcKeySigning() {
        testEcKeySigningHelper(false)
    }

    @Test
    fun testEcKeySigningStrongBox() {
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        testEcKeySigningHelper(true)
    }

    fun testEcKeySigningHelper(useStrongBox: Boolean) = runTest {
        val ks = secureAreaProvider.get()
        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setUseStrongBox(useStrongBox)
            .build()
        ks.createKey("testKey", settings)
        val keyInfo = ks.getKeyInfo("testKey")
        val attestation = keyInfo.attestation
        Assert.assertTrue(attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertEquals(useStrongBox, keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
        Assert.assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    fun testEcKeySigningAuthBound() {
        testEcKeySigningAuthBoundHelper(false)
    }

    @Test
    fun testEcKeySigningAuthBoundStrongBox() {
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        testEcKeySigningAuthBoundHelper(true)
    }

    fun testEcKeySigningAuthBoundHelper(useStrongBox: Boolean) = runTest {
        Assume.assumeFalse(TestUtil.isRunningOnEmulator)
        val ks = secureAreaProvider.get()

        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setUseStrongBox(useStrongBox)
            .setUserAuthenticationRequired(
                true,
                42,
                setOf(
                    UserAuthenticationType.LSKF,
                    UserAuthenticationType.BIOMETRIC
                )
            )
            .build()
        ks.createKey("testKey", settings)
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertEquals(useStrongBox, keyInfo.isStrongBoxBacked)
        Assert.assertTrue(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(42, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertEquals(
            setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC),
            keyInfo.userAuthenticationTypes
        )
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)
        val dataToSign = byteArrayOf(4, 5, 6)
        try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
            Assert.fail("Should not be reached")
        } catch (e: KeyLockedException) {
            /* expected path */
        }
    }

    @Test
    fun testEcKeyAuthenticationTypeLskf() = runTest {
        Assume.assumeFalse(TestUtil.isRunningOnEmulator)
        // setUserAuthenticationParameters() is only available on API 30 or later.
        //
        Assume.assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)

        val ks = secureAreaProvider.get()
        val type = setOf(UserAuthenticationType.LSKF)
        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setUserAuthenticationRequired(true, 42, type)
            .build()
        ks.createKey("testKey", settings)
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertFalse(keyInfo.isStrongBoxBacked)
        Assert.assertTrue(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(42, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertEquals(type, keyInfo.userAuthenticationTypes)
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)
        val dataToSign = byteArrayOf(4, 5, 6)
        try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
            Assert.fail("Should not be reached")
        } catch (e: KeyLockedException) {
            /* expected path */
        }
    }

    @Test
    fun testEcKeyAuthenticationTypeBiometric() = runTest {
        Assume.assumeFalse(TestUtil.isRunningOnEmulator)
        // setUserAuthenticationParameters() is only available on API 30 or later.
        //
        Assume.assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)

        val ks = secureAreaProvider.get()
        val type = setOf(UserAuthenticationType.BIOMETRIC)
        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setUserAuthenticationRequired(true, 42, type)
            .build()
        ks.createKey("testKey", settings)
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertFalse(keyInfo.isStrongBoxBacked)
        Assert.assertTrue(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(42, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertEquals(type, keyInfo.userAuthenticationTypes)
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)
        val dataToSign = byteArrayOf(4, 5, 6)
        try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
            Assert.fail("Should not be reached")
        } catch (e: KeyLockedException) {
            /* expected path */
        }
    }

    @Test
    fun testEcKeyAuthenticationTypeNone() {
        // setUserAuthenticationParameters() is only available on API 30 or later.
        //
        Assume.assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        val type = setOf<UserAuthenticationType>()
        val challenge = byteArrayOf(1, 2, 3)
        try {
            val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
                .setUserAuthenticationRequired(true, 42, type)
                .build()
            Assert.fail("Should not be reached")
        } catch (e: IllegalArgumentException) {
            /* expected path */
        }
    }

    // Curve 25519 on Android is currently broken, see b/282063229 for details. Ignore test for now.
    @Ignore
    @Test
    fun testEcKeySigningEd25519() = runTest {
        // ECDH is only available on Android 12 or later (only HW-backed on Keymint 1.0 or later)
        //
        // Also note it's not available on StrongBox.
        //
        Assume.assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        val ks = secureAreaProvider.get()

        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setEcCurve(EcCurve.ED25519)
            .build()
        ks.createKey("testKey", settings)
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.ED25519, keyInfo.publicKey.curve)
        Assert.assertFalse(keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.EDDSA, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
        Assert.assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.EDDSA,
                signature
            )
        )
    }

    @Test
    @Throws(IOException::class)
    fun testEcKeySigningWithKeyWithoutCorrectPurpose() = runTest {
        // According to https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_HARDWARE_KEYSTORE
        // ECDH is available if FEATURE_HARDWARE_KEYSTORE is >= 100.
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_HARDWARE_KEYSTORE, 100
            )
        )

        val ks = secureAreaProvider.get()
        ks.createKey(
            "testKey",
            AndroidKeystoreCreateKeySettings.Builder(byteArrayOf(1, 2, 3))
                .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .build()
        )
        val dataToSign = byteArrayOf(4, 5, 6)
        try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
            Assert.fail("Signing shouldn't work with a key w/o KEY_PURPOSE_SIGN")
        } catch (e: IllegalArgumentException) {
            // Expected path.
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
    }

    @Test
    fun testEcdh() {
        // According to https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_HARDWARE_KEYSTORE
        // ECDH is available if FEATURE_HARDWARE_KEYSTORE is >= 100.
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_HARDWARE_KEYSTORE, 100
            )
        )
        testEcdhHelper(false)
    }

    @Test
    fun testEcdhStrongBox() {
        // According to https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_STRONGBOX_KEYSTORE
        // ECDH is available if FEATURE_STRONGBOX_KEYSTORE is >= 100.
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE, 100
            )
        )
        testEcdhHelper(true)
    }

    fun testEcdhHelper(useStrongBox: Boolean) = runTest {
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val ks = secureAreaProvider.get()
        ks.createKey(
            "testKey",
            AndroidKeystoreCreateKeySettings.Builder(byteArrayOf(1, 2, 3))
                .setUseStrongBox(useStrongBox)
                .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .build()
        )
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.AGREE_KEY), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertEquals(useStrongBox, keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)

        // First do the ECDH from the perspective of our side...
        val ourSharedSecret: ByteArray
        ourSharedSecret = try {
            ks.keyAgreement("testKey", otherKey.publicKey, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // ...now do it from the perspective of the other side...
        val theirSharedSecret = Crypto.keyAgreement(otherKey, keyInfo.publicKey)

        // ... finally, check that both sides compute the same shared secret.
        Assert.assertArrayEquals(theirSharedSecret, ourSharedSecret)
    }

    // Curve 25519 on Android is currently broken, see b/282063229 for details. Ignore test for now.
    @Ignore
    @Test
    fun testEcdhX25519() = runTest {
        // ECDH is only available on Android 12 or later (only HW-backed on Keymint 1.0 or later)
        //
        // Also note it's not available on StrongBox.
        //
        Assume.assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)

        val ks = secureAreaProvider.get()

        val otherKey = Crypto.createEcPrivateKey(EcCurve.X25519)
        ks.createKey(
            "testKey",
            AndroidKeystoreCreateKeySettings.Builder(byteArrayOf(1, 2, 3))
                .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .setEcCurve(EcCurve.X25519)
                .build()
        )
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.AGREE_KEY), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.X25519, keyInfo.publicKey.curve)
        Assert.assertFalse(keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)

        // First do the ECDH from the perspective of our side...
        val ourSharedSecret: ByteArray
        ourSharedSecret = try {
            ks.keyAgreement("testKey", otherKey.publicKey, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // ...now do it from the perspective of the other side...
        val theirSharedSecret = Crypto.keyAgreement(otherKey, keyInfo.publicKey)

        // ... finally, check that both sides compute the same shared secret.
        Assert.assertArrayEquals(theirSharedSecret, ourSharedSecret)
    }

    @Test
    fun testEcdhAndSigning() {
        // According to https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_HARDWARE_KEYSTORE
        // ECDH is available if FEATURE_HARDWARE_KEYSTORE is >= 100.
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_HARDWARE_KEYSTORE, 100
            )
        )
        testEcdhAndSigningHelper(false)
    }

    @Test
    fun testEcdhAndSigningStrongBox() {
        // According to https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_STRONGBOX_KEYSTORE
        // ECDH is available if FEATURE_STRONGBOX_KEYSTORE is >= 100.
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE, 100
            )
        )
        testEcdhAndSigningHelper(true)
    }

    fun testEcdhAndSigningHelper(useStrongBox: Boolean) = runTest {
        val ks = secureAreaProvider.get()
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)
        ks.createKey(
            "testKey",
            AndroidKeystoreCreateKeySettings.Builder(byteArrayOf(1, 2, 3))
                .setUseStrongBox(useStrongBox)
                .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY, KeyPurpose.SIGN))
                .build()
        )
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.AGREE_KEY, KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertEquals(useStrongBox, keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)

        // First do the ECDH from the perspective of our side...
        val ourSharedSecret: ByteArray
        ourSharedSecret = try {
            ks.keyAgreement("testKey", otherKey.publicKey, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // ...now do it from the perspective of the other side...
        val theirSharedSecret = Crypto.keyAgreement(otherKey, keyInfo.publicKey)

        // ... finally, check that both sides compute the same shared secret.
        Assert.assertArrayEquals(theirSharedSecret, ourSharedSecret)
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
        Assert.assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    @Throws(IOException::class)
    fun testEcdhWithoutCorrectPurpose() = runTest {
        // According to https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_HARDWARE_KEYSTORE
        // ECDH is available if FEATURE_HARDWARE_KEYSTORE is >= 100.
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_HARDWARE_KEYSTORE, 100
            )
        )
        val ks = secureAreaProvider.get()
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)
        ks.createKey(
            "testKey",
            AndroidKeystoreCreateKeySettings.Builder(
                byteArrayOf(
                    1,
                    2,
                    3
                )
            ) //.setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
                .build()
        )
        try {
            ks.keyAgreement("testKey", otherKey.publicKey, null)
            Assert.fail("ECDH shouldn't work with a key w/o KEY_PURPOSE_AGREE_KEY")
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        } catch (e: IllegalArgumentException) {
            // Expected path.
        }
    }

    @Test
    fun testEcKeyCreationDuplicateAlias() = runTest {
        val ks = secureAreaProvider.get()
        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge).build()
        ks.createKey("testKey", settings)
        val keyInfoOld: KeyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfoOld.attestation.certChain!!.certificates.size >= 1)
        try {
            ks.createKey("testKey", settings)
            Assert.fail("Expected an exception")
        } catch (err: KeyExistsStorageException) {
            // expected path
        }
        ks.deleteKey("testKey")
        ks.createKey("testKey", settings)
        val keyInfo: KeyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            ks.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // Check new key is a different cert chain.
        Assert.assertNotEquals(
            keyInfoOld.attestation.certChain!!.certificates[0].ecPublicKey,
            keyInfo.attestation.certChain!!.certificates[0].ecPublicKey
        )

        // Check new key is used to sign.
        Assert.assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey,
                dataToSign,
                Algorithm.ES256,
                signature
            )
        )
    }

    @Test
    @Throws(IOException::class)
    fun testAttestation() {
        testAttestationHelper(false)
    }

    @Test
    @Throws(IOException::class)
    fun testAttestationStrongBox() {
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        testAttestationHelper(true)
    }

    @Throws(IOException::class)
    fun testAttestationHelper(useStrongBox: Boolean) = runTest {
        val ks = secureAreaProvider.get()
        val validFromCalendar: Calendar = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        validFromCalendar[2023, 5, 15, 0, 0] = 0
        val validUntilCalendar: Calendar = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        validUntilCalendar[2024, 5, 15, 0, 0] = 0
        val validFrom = fromEpochMilliseconds(validFromCalendar.timeInMillis)
        val validUntil = fromEpochMilliseconds(validUntilCalendar.timeInMillis)
        val challenge = byteArrayOf(1, 2, 3)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setUseStrongBox(useStrongBox)
            .setValidityPeriod(validFrom, validUntil)
            .build()
        ks.deleteKey("testKey")
        ks.createKey("testKey", settings)

        // On Android, at least three certificates are present in the chain.
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 3)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertEquals(useStrongBox, keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertNull(keyInfo.attestKeyAlias)
        Assert.assertEquals(validFrom, keyInfo.validFrom)
        Assert.assertEquals(validUntil, keyInfo.validUntil)

        // Check the attestation extension
        val parser = AndroidAttestationExtensionParser(
            keyInfo.attestation.certChain!!.certificates[0]
        )
        Assert.assertArrayEquals(challenge, parser.attestationChallenge)
        val securityLevel = parser.keymasterSecurityLevel
        if (!TestUtil.isRunningOnEmulator) {
            Assert.assertEquals(
                if (useStrongBox) {
                    AndroidAttestationExtensionParser.SecurityLevel.STRONG_BOX
                } else {
                    AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT
                },
                securityLevel
            )
        }

        // tag 400: https://source.android.com/docs/security/features/keystore/tags#active_datetime
        Assert.assertEquals(
            validFrom.toEpochMilliseconds(),
            parser.getSoftwareAuthorizationLong(400)
        )

        // tag 401: https://source.android.com/docs/security/features/keystore/tags#origination_expire_datetime
        Assert.assertEquals(
            validUntil.toEpochMilliseconds(),
            parser.getSoftwareAuthorizationLong(401)
        )
    }

    @Test
    @Throws(IOException::class)
    fun testAttestKey() {
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY))
        testAttestKeyHelper(context, false)
    }

    @Test
    @Throws(IOException::class)
    fun testAttestKeyStrongBox() {
        val context = InstrumentationRegistry.getTargetContext()
        Assume.assumeTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY))
        Assume.assumeTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
        testAttestKeyHelper(context, true)
    }

    @Throws(IOException::class)
    fun testAttestKeyHelper(context: Context, useStrongBox: Boolean) = runTest {
        val ks = secureAreaProvider.get()
        val attestKeyAlias = "icTestAttestKey"
        val attestKeyCertificates: Array<Certificate>
        var kpg: KeyPairGenerator? = null
        try {
            kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            val builder = KeyGenParameterSpec.Builder(
                attestKeyAlias,
                KeyProperties.PURPOSE_ATTEST_KEY
            )
            builder.setAttestationChallenge(byteArrayOf(1, 2, 3))
            if (useStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            val aks = KeyStore.getInstance("AndroidKeyStore")
            aks.load(null)
            attestKeyCertificates = aks.getCertificateChain(attestKeyAlias)
        } catch (e: InvalidAlgorithmParameterException) {
            throw IllegalStateException("Error creating attest key", e)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Error creating attest key", e)
        } catch (e: NoSuchProviderException) {
            throw IllegalStateException("Error creating attest key", e)
        } catch (e: KeyStoreException) {
            throw IllegalStateException("Error creating attest key", e)
        } catch (e: CertificateException) {
            throw IllegalStateException("Error creating attest key", e)
        }
        val challenge = byteArrayOf(4, 5, 6, 7)
        val settings = AndroidKeystoreCreateKeySettings.Builder(challenge)
            .setAttestKeyAlias(attestKeyAlias)
            .setUseStrongBox(useStrongBox)
            .build()
        ks.deleteKey("testKey")
        ks.createKey("testKey", settings)
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        Assert.assertEquals(useStrongBox, keyInfo.isStrongBoxBacked)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertTrue(keyInfo.userAuthenticationTypes.isEmpty())
        Assert.assertEquals(attestKeyAlias, keyInfo.attestKeyAlias)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)

        // When using an attest key, only one certificate is returned ...
        Assert.assertEquals(1, keyInfo.attestation.certChain!!.certificates.size.toLong())
        // ... and this certificate is signed by the attest key. Check that.
        try {
            keyInfo.attestation.certChain!!.certificates[0].javaX509Certificate.verify(
                attestKeyCertificates[0].publicKey
            )
            // expected path
        } catch (e: Throwable) {
            Assert.fail()
        }

        // Check the attestation extension
        val parser = AndroidAttestationExtensionParser(
            keyInfo.attestation.certChain!!.certificates[0]
        )
        Assert.assertArrayEquals(challenge, parser.attestationChallenge)
        val securityLevel = parser.keymasterSecurityLevel
        if (!TestUtil.isRunningOnEmulator) {
            Assert.assertEquals(
                if (useStrongBox) {
                    AndroidAttestationExtensionParser.SecurityLevel.STRONG_BOX
                } else {
                    AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT
                },
                securityLevel
            )
        }
    }

    @Test
    @Throws(IOException::class)
    fun testUsingGenericCreateKeySettings() = runTest {
        val ks = secureAreaProvider.get()
        // Challenge is always empty when using the generic CreateKeySettings
        val challenge = byteArrayOf()
        ks.createKey("testKey", CreateKeySettings(setOf(KeyPurpose.SIGN), EcCurve.P256))
        val keyInfo = ks.getKeyInfo("testKey")
        Assert.assertNotNull(keyInfo)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertEquals(EcCurve.P256, keyInfo.publicKey.curve)
        val parser = AndroidAttestationExtensionParser(
            keyInfo.attestation.certChain!!.certificates[0]
        )
        Assert.assertArrayEquals(challenge, parser.attestationChallenge)

        // Now delete it...
        ks.deleteKey("testKey")
    }
}
