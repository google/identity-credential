package com.android.identity.android.securearea.cloud

import android.content.Context
import android.content.pm.PackageManager
import androidx.test.InstrumentationRegistry
import com.android.identity.asn1.ASN1Integer
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.X500Name
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509KeyUsage
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.securearea.AttestationExtension
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol
import com.android.identity.securearea.cloud.CloudSecureAreaServer
import com.android.identity.securearea.cloud.SimplePassphraseFailureEnforcer
import com.android.identity.securearea.cloud.fromCbor
import com.android.identity.securearea.cloud.toCbor
import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.storage.StorageEngine
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.Security
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

class CloudSecureAreaTest {
    @Before
    fun setup() {
        // This is needed to prefer BouncyCastle bundled with the app instead of the Conscrypt
        // based implementation included in Android.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
    }

    var serverTime = Instant.fromEpochMilliseconds(0)

    internal inner class LoopbackCloudSecureArea(
        context: Context,
        storageEngine: StorageEngine,
        packageToAllow: String?,
    ) : CloudSecureArea(context, storageEngine, "CloudSecureArea", "uri-not-used") {
        private val server: CloudSecureAreaServer

        init {
            val enclaveBoundKey = Random.nextBytes(32)

            val attestationKeySubject = "CN=Cloud Secure Area Attestation Root"
            val attestationKeyValidFrom = Clock.System.now()
            val attestationKeyValidUntil = attestationKeyValidFrom + 365.days*5
            val attestationKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val attestationKeySignatureAlgorithm = attestationKey.curve.defaultSigningAlgorithm
            val attestationKeyCertificates = X509CertChain(
                listOf(
                    X509Cert.Builder(
                        publicKey = attestationKey.publicKey,
                        signingKey = attestationKey,
                        signatureAlgorithm = attestationKeySignatureAlgorithm,
                        serialNumber = ASN1Integer(1L),
                        subject = X500Name.fromName(attestationKeySubject),
                        issuer = X500Name.fromName(attestationKeySubject),
                        validFrom = attestationKeyValidFrom,
                        validUntil = attestationKeyValidUntil
                    )
                        .includeSubjectKeyIdentifier()
                        .setKeyUsage(setOf(X509KeyUsage.KEY_CERT_SIGN))
                        .build(),
                )
            )

            val cloudBindingKeySubject = "CN=Cloud Secure Area Cloud Binding Key Attestation Root"
            val cloudBindingKeyValidFrom = Clock.System.now()
            val cloudBindingKeyValidUntil = cloudBindingKeyValidFrom + 365.days*5
            val cloudBindingKeyAttestationKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val cloudBindingKeySignatureAlgorithm = cloudBindingKeyAttestationKey.curve.defaultSigningAlgorithm
            val cloudBindingKeyAttestationCertificates = X509CertChain(
                listOf(
                    X509Cert.Builder(
                        publicKey = cloudBindingKeyAttestationKey.publicKey,
                        signingKey = cloudBindingKeyAttestationKey,
                        signatureAlgorithm = cloudBindingKeySignatureAlgorithm,
                        serialNumber = ASN1Integer(1L),
                        subject = X500Name.fromName(cloudBindingKeySubject),
                        issuer = X500Name.fromName(cloudBindingKeySubject),
                        validFrom = cloudBindingKeyValidFrom,
                        validUntil = cloudBindingKeyValidUntil
                    )
                        .includeSubjectKeyIdentifier()
                        .setKeyUsage(setOf(X509KeyUsage.KEY_CERT_SIGN))
                        .build(),
                )
            )

            val digestOfSignatures: MutableList<ByteArray> = ArrayList()
            if (packageToAllow != null) {
                try {
                    val pkg = context.packageManager
                        .getPackageInfo(packageToAllow, PackageManager.GET_SIGNING_CERTIFICATES)
                    val digester = MessageDigest.getInstance("SHA-256")
                    for (n in pkg.signingInfo!!.apkContentsSigners.indices) {
                        digestOfSignatures.add(digester.digest(pkg.signingInfo!!.apkContentsSigners[n].toByteArray()))
                    }
                } catch (e: PackageManager.NameNotFoundException) {
                    throw CloudException(e)
                } catch (e: NoSuchAlgorithmException) {
                    throw CloudException(e)
                }
            }
            server = CloudSecureAreaServer(
                enclaveBoundKey,
                attestationKey,
                attestationKeySignatureAlgorithm,
                attestationKeySubject,
                attestationKeyCertificates,
                cloudBindingKeyAttestationKey,
                cloudBindingKeySignatureAlgorithm,
                cloudBindingKeySubject,
                cloudBindingKeyAttestationCertificates,
                10 * 60,
                false,
                false,
                digestOfSignatures,
                SimplePassphraseFailureEnforcer(
                    lockoutNumFailedAttempts = 3,
                    lockoutDuration = 1.minutes,
                    clockFunction = { serverTime }
                )
            )
        }

        override suspend fun communicateLowlevel(
            endpointUri: String,
            requestData: ByteArray
        ): Pair<Int, ByteArray> {
            return server.handleCommand(requestData, endpointUri)
        }

        override suspend fun delayForBruteforceMitigation(duration: Duration) {
            serverTime = serverTime + duration
        }
    }

    @Test
    fun testKeyCreation() = runTest {
        val context = InstrumentationRegistry.getTargetContext()
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )
        csa.register(
            "",
            PassphraseConstraints.NONE) { true }
        val challenge = byteArrayOf(1, 2, 3)
        val settings = CloudCreateKeySettings.Builder(challenge).build()
        csa.createKey("test", settings)

        // Check that the challenge is there.
        Assert.assertArrayEquals(
            challenge,
            getAttestationChallenge(csa.getKeyInfo("test").attestation)
        )
    }

    @Test
    fun testKeySigning() = runTest {
        val context = InstrumentationRegistry.getTargetContext()
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )
        csa.register(
            "",
            PassphraseConstraints.NONE) { true }
        val settings = CloudCreateKeySettings.Builder(byteArrayOf(1, 2, 3)).build()
        csa.createKey("testKey", settings)
        val keyInfo = csa.getKeyInfo("testKey")
        Assert.assertNotNull(keyInfo)
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertEquals(setOf<Any>(), keyInfo.userAuthenticationTypes)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)
        val dataToSign = byteArrayOf(4, 5, 6)
        val signature = try {
            csa.sign("testKey", Algorithm.ES256, dataToSign, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }
        Assert.assertTrue(
            Crypto.checkSignature(
                keyInfo.publicKey, dataToSign, Algorithm.ES256, signature
            )
        )
    }

    @Test
    fun testKeyAgreement() = runTest {
        val context = InstrumentationRegistry.getTargetContext()
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )
        csa.register(
            "",
            PassphraseConstraints.NONE) { true }
        val otherKeyPair = Crypto.createEcPrivateKey(EcCurve.P256)
        val settings = CloudCreateKeySettings.Builder(byteArrayOf(1, 2, 3))
            .setKeyPurposes(setOf(KeyPurpose.AGREE_KEY))
            .build()
        csa.createKey("testKey", settings)
        val keyInfo = csa.getKeyInfo("testKey")
        Assert.assertNotNull(keyInfo)
        Assert.assertTrue(keyInfo.attestation.certChain!!.certificates.size >= 1)
        Assert.assertEquals(setOf(KeyPurpose.AGREE_KEY), keyInfo.keyPurposes)
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired)
        Assert.assertEquals(0, keyInfo.userAuthenticationTimeoutMillis)
        Assert.assertEquals(setOf<Any>(), keyInfo.userAuthenticationTypes)
        Assert.assertNull(keyInfo.validFrom)
        Assert.assertNull(keyInfo.validUntil)

        // First do the ECDH from the perspective of our side...
        val ourSharedSecret = try {
            csa.keyAgreement("testKey", otherKeyPair.publicKey, null)
        } catch (e: KeyLockedException) {
            throw AssertionError(e)
        }

        // ...now do it from the perspective of the other side...
        val theirSharedSecret = Crypto.keyAgreement(otherKeyPair, keyInfo.publicKey)

        // ... finally, check that both sides compute the same shared secret.
        Assert.assertArrayEquals(theirSharedSecret, ourSharedSecret)
    }

    @Test
    fun testPassphraseCannotBeChanged() = runTest {
        val context = InstrumentationRegistry.getTargetContext()
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )
        csa.register(
            "",
            PassphraseConstraints.NONE) { true }

        // NOTE: [CloudSecureArea] doesn't provide API to change the passphrase but an
        // attacker could conceivable just try to re-run stage 2 of the registration
        // process with a new passphrase and hope that we're gullible enough to take it.
        //
        // Check that this doesn't work.
        //
        try {
            val spRequest0 = CloudSecureAreaProtocol.RegisterStage2Request0("New Passphrase")
            val spResponse0 = CloudSecureAreaProtocol.Command.fromCbor(csa.communicateE2EE(spRequest0.toCbor()))
                    as CloudSecureAreaProtocol.RegisterStage2Response0
            Assert.fail("Expected exception")
        } catch (e: CloudException) {
            Assert.assertEquals("Excepted status code 200 or 400, got 403", e.message)
        }
    }

    @Test
    fun testServerChecksAttestationForApplication() = runTest {
        val context = InstrumentationRegistry.getTargetContext()

        // Setup the server to only accept our package name. This should cause register to succeed().
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            context.packageName
        )
        csa.register(
            "",
            PassphraseConstraints.NONE) { true }
    }

    @Test
    fun testServerChecksAttestationForApplicationNegative() = runTest {
        val context = InstrumentationRegistry.getTargetContext()

        // Setup the server to only accept something which isn't our package name but still
        // exists on the system. We use com.android.externalstorage for that. This should
        // cause register() to fail.
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            "com.android.externalstorage"
        )
        try {
            csa.register(
                "",
                PassphraseConstraints.NONE
            ) { true }
            Assert.fail("Expected exception")
        } catch (e: CloudException) {
            // Expected path.
        }
    }

    @Test
    @Throws(IOException::class)
    fun testUsingGenericCreateKeySettings() = runTest {
        val context = InstrumentationRegistry.getTargetContext()
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )
        csa.register(
            "",
            PassphraseConstraints.NONE) { true }
        csa.createKey(
            "testKey",
             CreateKeySettings()
        )
        val keyInfo = csa.getKeyInfo("testKey")
        Assert.assertNotNull(keyInfo)
        Assert.assertEquals(setOf(KeyPurpose.SIGN), keyInfo.keyPurposes)

        // Check that the challenge is empty.
        Assert.assertArrayEquals(
            byteArrayOf(),
            getAttestationChallenge(csa.getKeyInfo("testKey").attestation)
        )

        // Now delete it...
        csa.deleteKey("testKey")
    }

    @Test
    fun testWrongPassphraseDelay_signing() = runTest {
        testWrongPassphraseDelayHelper(
            useKey = { alias, csa, unlockData ->
                csa.sign(alias, Algorithm.ES256, byteArrayOf(1, 2, 3), unlockData)
        })
    }

    @Test
    fun testWrongPassphraseDelay_keyAgreement() = runTest {
        val otherKey = Crypto.createEcPrivateKey(EcCurve.P256)

        testWrongPassphraseDelayHelper(
            useKey = { alias, csa, unlockData ->
                csa.keyAgreement(alias, otherKey.publicKey, unlockData)
        })
    }

    suspend fun testWrongPassphraseDelayHelper(
        useKey: (alias: String,
                 csa: CloudSecureArea,
                 unlockData: CloudKeyUnlockData?) -> Unit
    ) {
        val context = InstrumentationRegistry.getTargetContext()
        val csa = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )

        csa.register(
            "1111",
            PassphraseConstraints.PIN_FOUR_DIGITS
        ) { true }

        csa.createKey("testKey1",
            CloudCreateKeySettings.Builder(byteArrayOf())
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .setPassphraseRequired(true)
                .build()
        )

        csa.createKey("testKey2",
            CloudCreateKeySettings.Builder(byteArrayOf())
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .setPassphraseRequired(true)
                .build()
        )

        csa.createKey("testKey3NoPassphrase",
            CloudCreateKeySettings.Builder(byteArrayOf())
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .build()
        )

        val correctPassphrase = CloudKeyUnlockData(csa,"testKey1")
        correctPassphrase.passphrase = "1111"

        val incorrectPassphrase = CloudKeyUnlockData(csa,"testKey1")
        incorrectPassphrase.passphrase = "1112"

        val correctPassphraseTestKey2 = CloudKeyUnlockData(csa,"testKey2")
        correctPassphraseTestKey2.passphrase = "1111"

        // ----

        // Policy is configured above to be
        //
        //   lockoutNumFailedAttempts = 3,
        //   lockoutDuration = 1.minutes,
        //
        // so this is what we're going to test. We can also control the clock used by the
        // enforcer via [serverTime].
        //

        // First make three attempts at T = 0, 15, 30 to unlock... the third attempt will
        // will cause us to be locked out until there are no unlock failures inside the
        // last minute.
        serverTime = Instant.fromEpochMilliseconds(0)
        useKey("testKey1", csa, correctPassphrase)
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        serverTime = Instant.fromEpochMilliseconds(15 * 1000)
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        serverTime = Instant.fromEpochMilliseconds(30 * 1000)
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }

        // Unlock attempts should now start blocking EVEN if we supply the right passphrase.
        //
        // Note, this is subtle: `serverTime` is increased due to the test overriding
        // CloudSecureArea.delayForBruteforceMitigation() method which does just that
        // instead of blocking the calling thread.
        //
        serverTime = Instant.fromEpochMilliseconds(31 * 1000)
        useKey("testKey1", csa, correctPassphrase)
        Assert.assertEquals(Instant.fromEpochMilliseconds(60 * 1000), serverTime)

        // Let's do another failed attempt and then try again... this should block
        // until T = 75 seconds because we had failed attempts at T=15 and T=30 already.
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        useKey("testKey1", csa, correctPassphrase)
        Assert.assertEquals(Instant.fromEpochMilliseconds(75 * 1000), serverTime)

        // Jump forward in time to clear out failed attempts
        serverTime = Instant.fromEpochMilliseconds(1000 * 1000)

        // Also check that if one key from the client is blocked, so are all others. Also
        // check here that operations on keys w/o passphrases aren't blocked
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        // testKey3NoPassphrase shouldn't be blocked
        useKey("testKey3NoPassphrase", csa, null)
        Assert.assertEquals(Instant.fromEpochMilliseconds(1000 * 1000), serverTime)
        // Now we're blocked b/c of testKey1, even for testKey2
        useKey("testKey2", csa, correctPassphraseTestKey2)
        Assert.assertEquals(Instant.fromEpochMilliseconds(1060 * 1000), serverTime)

        // Jump forward in time to clear out failed attempts
        serverTime = Instant.fromEpochMilliseconds(2000 * 1000)

        // Finally, we want to check that different clients don't affect each other. To this
        // end we're creating a new client w/ a passphrase protected key.
        val csa2 = LoopbackCloudSecureArea(
            context,
            EphemeralStorageEngine(),
            null
        )
        csa2.register(
            "9876",
            PassphraseConstraints.PIN_FOUR_DIGITS,
        ) { true }
        csa2.createKey("client2_testKey1",
            CloudCreateKeySettings.Builder(byteArrayOf())
                .setKeyPurposes(setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY))
                .setPassphraseRequired(true)
                .build()
        )
        val correctPassphraseClient2 = CloudKeyUnlockData(csa2, "client2_testKey1")
        correctPassphraseClient2.passphrase = "9876"

        // Now use up all failed attempts on client 1
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        Assert.assertThrows(KeyLockedException::class.java) {
            useKey("testKey1", csa, incorrectPassphrase)
        }
        Assert.assertEquals(Instant.fromEpochMilliseconds(2000 * 1000), serverTime)
        // Check client 2 isn't affected
        useKey("client2_testKey1", csa2, correctPassphraseClient2)
        Assert.assertEquals(Instant.fromEpochMilliseconds(2000 * 1000), serverTime)
        useKey("testKey1", csa, correctPassphrase)
        Assert.assertEquals(Instant.fromEpochMilliseconds(2060 * 1000), serverTime)
    }

    companion object {
        fun getAttestationChallenge(attestation: KeyAttestation): ByteArray {
            val x509cert = attestation.certChain!!.certificates[0].javaX509Certificate
            val octetString = x509cert.getExtensionValue(AttestationExtension.ATTESTATION_OID)
            return try {
                val asn1InputStream = ASN1InputStream(octetString)
                val encodedCbor = (asn1InputStream.readObject() as ASN1OctetString).octets
                AttestationExtension.decode(encodedCbor)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }
    }
}