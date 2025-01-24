package com.android.identity.securearea.cloud

import com.android.identity.asn1.ASN1Integer
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.cose.CoseKey
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.X500Name
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.javaX509Certificates
import com.android.identity.securearea.AttestationExtension
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.CreateKeyRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.CreateKeyResponse1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EEResponse
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupResponse1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterResponse1
import com.android.identity.securearea.software.SoftwareCreateKeySettings
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.ephemeral.EphemeralStorage
import com.android.identity.util.AndroidAttestationExtensionParser
import com.android.identity.util.Logger
import com.android.identity.util.fromHex
import com.android.identity.util.toHex
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimePeriod
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.plus
import kotlinx.io.bytestring.ByteString
import java.io.IOException
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.SignatureException
import java.security.cert.CertificateException
import java.util.Arrays
import java.util.Locale
import kotlin.random.Random

/**
 * A reference implementation of the Cloud Secure Area server.
 *
 * This code is not intended for production use.
 *
 * @param serverSecureAreaBoundKey the secret key used to encrypt/decrypt state externally stored.
 * @param attestationKey the private key used to sign attestations for keys created by clients.
 * @param attestationKeyCertification a certification of the attestation key.
 * @param cloudRootAttestationKey the private key used to sign attestations for `CloudBindingKey`.
 * @param cloudRootAttestationKeyCertification a certification of the attestation key for `CloudBindingKey`.
 * @param requireGmsAttestation whether to require attestations made for local key on clients is using the Google root.
 * @param requireVerifiedBootGreen whether to require clients are in verified boot state green
 * @param requireAppSignatureCertificateDigests the allowed list of applications that can use the
 *   service. Each element is the bytes of the SHA-256 of a signing certificate, see the
 *   [Signature](https://developer.android.com/reference/android/content/pm/Signature) class in
 *   the Android SDK for details. If empty, allow any app.
 * @param passphraseFailureEnforcer the [PassphraseFailureEnforcer] to use.
 */
class CloudSecureAreaServer(
    private val serverSecureAreaBoundKey: ByteArray,
    private val attestationKey: EcPrivateKey,
    private val attestationKeySignatureAlgorithm: Algorithm,
    private val attestationKeyIssuer: String,
    private val attestationKeyCertification: X509CertChain,
    private val cloudRootAttestationKey: EcPrivateKey,
    private val cloudRootAttestationKeySignatureAlgorithm: Algorithm,
    private val cloudRootAttestationKeyIssuer: String,
    private val cloudRootAttestationKeyCertification: X509CertChain,
    private val e2eeKeyLimitSeconds: Int,
    private val requireGmsAttestation: Boolean,
    private val requireVerifiedBootGreen: Boolean,
    private val requireAppSignatureCertificateDigests: List<ByteArray>,
    private val passphraseFailureEnforcer: PassphraseFailureEnforcer
) {
    private fun encryptState(plaintext: ByteArray): ByteArray {
        val counter = encryptionGcmCounter
        val iv = ByteBuffer.allocate(12)
        iv.putInt(0, 0x00000000)
        iv.putLong(counter)
        val ciphertext = Crypto.encrypt(Algorithm.A128GCM, serverSecureAreaBoundKey, iv.array(), plaintext)
        return iv.array() + ciphertext
    }

    private fun decryptState(cipherText: ByteArray): ByteArray {
        require(cipherText.size >= 12) { "input too short" }
        val iv = cipherText.copyOfRange(0, 12)
        val encryptedData = cipherText.copyOfRange(12, cipherText.size)
        val plaintext = Crypto.decrypt(Algorithm.A128GCM, serverSecureAreaBoundKey, iv, encryptedData)
        return plaintext
    }

    @CborSerializable
    data class RegisterState(
        var clientVersion: String = "",
        var cloudChallenge: ByteArray? = null,
        var cloudBindingKey: CoseKey? = null,
        var deviceBindingKey: CoseKey? = null,
        var clientPassphraseSalt: ByteArray = byteArrayOf(),
        var clientSaltedPassphrase: ByteArray = byteArrayOf(),
        var registrationComplete: Boolean = false,
    ) {
        companion object
    }

    private fun RegisterState.encrypt(): ByteArray = encryptState(toCbor())

    private fun RegisterState.Companion.decrypt(encryptedState: ByteArray) =
        fromCbor(decryptState(encryptedState))

    private fun validateAndroidKeystoreAttestation(
        attestation: X509CertChain,
        cloudChallenge: ByteArray,
        remoteHost: String
    ) {
        val x509certs = attestation.javaX509Certificates
        // First check that all the certificates sign each other...
        for (n in 0 until x509certs.size - 1) {
            val cert = x509certs[n]
            val nextCert = x509certs[n + 1]
            try {
                cert.verify(nextCert.publicKey)
            } catch (e: NoSuchAlgorithmException) {
                throw IllegalStateException("Error verifying signature", e)
            } catch (e: InvalidKeyException) {
                throw IllegalStateException("Error verifying signature", e)
            } catch (e: SignatureException) {
                throw IllegalStateException("Error verifying signature", e)
            } catch (e: CertificateException) {
                throw IllegalStateException("Error verifying signature", e)
            } catch (e: NoSuchProviderException) {
                throw IllegalStateException("Error verifying signature", e)
            }
        }
        val rootCertificatePublicKey = x509certs[x509certs.size - 1].publicKey
        if (requireGmsAttestation) {
            // Must match the well-known Google root
            // TODO: check X and Y instead
            check(
                Arrays.equals(
                    GOOGLE_ROOT_ATTESTATION_KEY,
                    rootCertificatePublicKey.encoded)
            ) { "Unexpected attestation root" }
        }

        // Finally, check the Attestation Extension...
        try {
            val parser = AndroidAttestationExtensionParser(attestation.certificates.first())

            // Challenge must match...
            check(cloudChallenge.contentEquals(parser.attestationChallenge)) {
                "Challenge didn't match what was expected"
            }

            if (requireVerifiedBootGreen) {
                // Verified Boot state must VERIFIED
                check(parser.verifiedBootState ==
                        AndroidAttestationExtensionParser.VerifiedBootState.GREEN)
                { "Verified boot state is not GREEN" }
            }

            if (requireAppSignatureCertificateDigests.size > 0) {
                check (parser.applicationSignatureDigests.size == requireAppSignatureCertificateDigests.size)
                { "Number Signing certificates mismatch" }
                for (n in 0..<parser.applicationSignatureDigests.size) {
                    check (parser.applicationSignatureDigests[n].toByteArray().contentEquals(
                        requireAppSignatureCertificateDigests[n]))
                    { "Signing certificate $n mismatch" }
                }
            }

            // Log the digests for easy copy-pasting into config file.
            Logger.d(TAG, "$remoteHost: Accepting Android client with ${parser.applicationSignatureDigests.size} " +
                    "signing certificates digests")
            for (n in 0..<parser.applicationSignatureDigests.size) {
                Logger.d(TAG,
                    "$remoteHost: Digest $n: ${parser.applicationSignatureDigests[n].toByteArray().toHex()}")
            }

        } catch (e: IOException) {
            throw IllegalStateException("Error parsing Android Attestation Extension", e)
        }
    }

    private fun doRegisterRequest0(request0: RegisterRequest0,
                                   remoteHost: String): Pair<Int, ByteArray> {
        val state = RegisterState()
        state.clientVersion = request0.clientVersion
        state.registrationComplete = false
        state.clientPassphraseSalt = byteArrayOf()
        state.clientSaltedPassphrase = byteArrayOf()
        state.cloudChallenge = Random.Default.nextBytes(32)
        val response0 = RegisterResponse0(
            state.cloudChallenge!!,
            state.encrypt()
        )
        Logger.d(TAG, "$remoteHost: RegisterRequest0: Sending challenge to client")
        return Pair(200, response0.toCbor())
    }

    private fun doRegisterRequest1(request1: RegisterRequest1,
                                   remoteHost: String): Pair<Int, ByteArray> {
        val state = RegisterState.decrypt(request1.serverState)
        try {
            validateAndroidKeystoreAttestation(
                request1.deviceBindingKeyAttestation,
                state.cloudChallenge!!,
                remoteHost
            )
        } catch (e: IllegalStateException) {
            Logger.w(TAG, "$remoteHost: RegisterRequest1: Android Keystore attestation did not validate", e)
            return Pair(403, e.message!!.toByteArray())
        }
        state.deviceBindingKey = request1.deviceBindingKeyAttestation.certificates[0].ecPublicKey.toCoseKey()

        // This is used to re-initialize E2EE so it's used quite a bit. Give it a long
        // validity period.
        val cloudBindingKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val cloudBindingKeyValidFrom = Clock.System.now()
        val cloudBindingKeyValidUntil = cloudBindingKeyValidFrom.plus(
            DateTimePeriod(years = 10),
            TimeZone.currentSystemDefault()
        )
        val cloudBindingKeyAttestation = X509CertChain(
            listOf(
                X509Cert.Builder(
                    publicKey = cloudBindingKey.publicKey,
                    signingKey = cloudRootAttestationKey,
                    signatureAlgorithm = cloudRootAttestationKeySignatureAlgorithm,
                    serialNumber = ASN1Integer(1L),
                    subject = X500Name.fromName("CN=Cloud Secure Area Cloud Binding Key"),
                    issuer = X500Name.fromName(cloudRootAttestationKeyIssuer),
                    validFrom = cloudBindingKeyValidFrom,
                    validUntil = cloudBindingKeyValidUntil
                )
                    .includeSubjectKeyIdentifier()
                    .setAuthorityKeyIdentifierToCertificate(cloudRootAttestationKeyCertification.certificates[0])
                    .addExtension(
                        oid = AttestationExtension.ATTESTATION_OID,
                        critical = false,
                        value = AttestationExtension.encode(request1.deviceChallenge)
                    )
                    .build()
            ) + cloudRootAttestationKeyCertification.certificates
        )
        state.cloudBindingKey = cloudBindingKey.toCoseKey()
        val response1 = RegisterResponse1(
            cloudBindingKeyAttestation,
            state.encrypt()
        )
        Logger.d(TAG, "$remoteHost: RegisterRequest1: Client successfully registered")
        return Pair(200, response1.toCbor())
    }

    @CborSerializable
    data class E2EEState(
        var context: RegisterState? = null,
        var cloudNonce: ByteArray? = null,
        var skDevice: ByteArray? = null,
        var skCloud: ByteArray? = null,
        var encryptedCounter: Int = 0,
        var decryptedCounter: Int = 0,
        var derivationTimestamp: Long = 0,
    ) {
        companion object
    }

    private fun E2EEState.encrypt(): ByteArray = encryptState(toCbor())

    private fun E2EEState.Companion.decrypt(encryptedState: ByteArray) =
        fromCbor(decryptState(encryptedState))

    private fun doE2EESetupRequest0(request0: E2EESetupRequest0,
                                    remoteHost: String): Pair<Int, ByteArray> {
        val state = E2EEState()
        state.context = RegisterState.decrypt(request0.registrationContext)
        state.cloudNonce = Random.Default.nextBytes(32)
        val response0 = E2EESetupResponse0(
            state.cloudNonce!!,
            state.encrypt()
        )
        Logger.d(TAG, "$remoteHost: E2EESetupRequest0: Sending nonce to client")
        return Pair(200, response0.toCbor())
    }

    private fun doE2EESetupRequest1(request1: E2EESetupRequest1,
                                    remoteHost: String): Pair<Int, ByteArray> {
        val state = E2EEState.decrypt(request1.serverState)
        val dataThatWasSigned = Cbor.encode(
            CborArray.builder()
                .add(request1.eDeviceKey.toDataItem())
                .add(state.cloudNonce!!)
                .add(request1.deviceNonce)
                .end()
                .build()
        )
        check(Crypto.checkSignature(
            state.context!!.deviceBindingKey!!.ecPublicKey,
            dataThatWasSigned,
            Algorithm.ES256,
            request1.signature
        )) { "Error verifying signature" }

        // OK, the device's EDeviceKey checks out. Time for us to generate ECloudKey,
        // sign over it with CloudBindingKey, and send it to the device for verification
        val eCloudKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val dataToSign = Cbor.encode(
            CborArray.builder()
                .add(eCloudKey.publicKey.toCoseKey().toDataItem())
                .add(state.cloudNonce!!)
                .add(request1.deviceNonce)
                .end()
                .build()
        )
        val signature = Crypto.sign(
            state.context!!.cloudBindingKey!!.ecPrivateKey,
            Algorithm.ES256,
            dataToSign
        )

        // Also derive SKDevice and SKCloud, and stash in state since we're going to need this later
        val zab = Crypto.keyAgreement(eCloudKey, request1.eDeviceKey.ecPublicKey)
        val salt = Crypto.digest(Algorithm.SHA256,
            Cbor.encode(
                CborArray.builder()
                    .add(request1.deviceNonce)
                    .add(state.cloudNonce!!)
                    .end()
                    .build()
            )
        )
        state.skDevice = Crypto.hkdf(
            Algorithm.HMAC_SHA256,
            zab,
            salt,
            "SKDevice".toByteArray(),
            32
        )
        state.skCloud = Crypto.hkdf(
            Algorithm.HMAC_SHA256,
            zab,
            salt,
            "SKCloud".toByteArray(),
            32
        )
        state.encryptedCounter = 1
        state.decryptedCounter = 1
        state.derivationTimestamp = System.currentTimeMillis()
        val response1 = E2EESetupResponse1(
            eCloudKey.publicKey.toCoseKey(),
            signature,
            state.encrypt()
        )
        Logger.d(TAG, "$remoteHost: E2EESetupRequest1: Encrypted tunnel has been set up")
        return Pair<Int, ByteArray>(200, response1.toCbor())
    }

    private fun doRegisterStage2Request0(
        request0: CloudSecureAreaProtocol.RegisterStage2Request0,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        // Protect against an attacker trying to change the passphrase
        if (e2eeState.context!!.registrationComplete) {
            Logger.w(TAG, "$remoteHost: Registration stage 2 already completed")
            return Pair(403, "Registration stage 2 already completed".toByteArray())
        }
        e2eeState.context!!.registrationComplete = true
        e2eeState.context!!.clientPassphraseSalt = Random.Default.nextBytes(32)
        e2eeState.context!!.clientSaltedPassphrase = Crypto.digest(
            Algorithm.SHA256,
            e2eeState.context!!.clientPassphraseSalt + request0.passphrase.encodeToByteArray()
        )
        val response0 = CloudSecureAreaProtocol.RegisterStage2Response0(
            e2eeState.context!!.encrypt()
        )
        val encryptedResponse0 = E2EEResponse(
            encryptToDevice(e2eeState, response0.toCbor()),
            e2eeState.encrypt()
        )
        Logger.d(TAG, "$remoteHost: doRegisterStage2Request0: Completed")
        return Pair(200, encryptedResponse0.toCbor())
    }

    @CborSerializable
    data class CreateKeyState(
        var challenge: ByteArray? = null,
        var cloudChallenge: ByteArray? = null,
        var purposes: Set<KeyPurpose> = emptySet(),
        var curve: EcCurve = EcCurve.P256,
        var validFromMillis: Long = 0,
        var validUntilMillis: Long = 0,
        var passphraseRequired: Boolean = false,
        var cloudKeyStorage: ByteArray? = null,
        var localKey: CoseKey? = null,
        var clientId: String? = null,
    ) {
        companion object
    }

    private fun encryptCreateKeyState(state: CreateKeyState): ByteArray {
        return encryptState(state.toCbor())
    }

    private fun decryptCreateKeyState(encryptedState: ByteArray): CreateKeyState {
        return CreateKeyState.fromCbor(decryptState(encryptedState))
    }

    private fun doCreateKeyRequest0(
        request0: CreateKeyRequest0,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        val state = CreateKeyState()
        state.challenge = request0.challenge
        state.cloudChallenge = Random.Default.nextBytes(32)
        state.purposes = request0.purposes
        state.curve = request0.curve
        state.validFromMillis = request0.validFromMillis
        state.validUntilMillis = request0.validUntilMillis
        state.passphraseRequired = request0.passphraseRequired
        // This is used for [PassphraseFailureEnforcer].
        state.clientId = Crypto.digest(
            Algorithm.SHA256,
            Cbor.encode(e2eeState.context!!.deviceBindingKey!!.toDataItem())).toHex()
        val response0 = CloudSecureAreaProtocol.CreateKeyResponse0(
            state.cloudChallenge!!,
            encryptCreateKeyState(state)
        )
        val encryptedResponse0 = E2EEResponse(
            encryptToDevice(e2eeState, response0.toCbor()),
            e2eeState.encrypt()
        )
        Logger.d(TAG, "$remoteHost: CreateKeyRequest0: Sending challenge to client")
        return Pair(200, encryptedResponse0.toCbor())
    }

    private suspend fun doCreateKeyRequest1(
        request1: CloudSecureAreaProtocol.CreateKeyRequest1,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        val state = decryptCreateKeyState(request1.serverState)
        try {
            validateAndroidKeystoreAttestation(
                request1.localKeyAttestation,
                state.cloudChallenge!!,
                remoteHost
            )
        } catch (e: IllegalStateException) {
            throw IllegalStateException("Error verifying signature")
        }
        state.localKey = request1.localKeyAttestation.certificates.get(0).ecPublicKey.toCoseKey()
        val storage = EphemeralStorage()
        val secureArea = SoftwareSecureArea.create(storage)
        val builder = SoftwareCreateKeySettings.Builder()
            .setValidityPeriod(
                Instant.fromEpochMilliseconds(state.validFromMillis),
                Instant.fromEpochMilliseconds(state.validUntilMillis)
            )
            .setKeyPurposes(state.purposes)
            .setEcCurve(state.curve)
        secureArea.createKey("CloudKey", builder.build())

        val keyInfo = secureArea.getKeyInfo("CloudKey")

        val attestationCert = X509Cert.Builder(
                publicKey = keyInfo.publicKey,
                signingKey = attestationKey,
                signatureAlgorithm = attestationKeySignatureAlgorithm,
                serialNumber = ASN1Integer(1L),
                subject = X500Name.fromName("CN=Cloud Secure Area Key"),
                issuer = X500Name.fromName(attestationKeyIssuer),
                validFrom = Instant.fromEpochMilliseconds(state.validFromMillis),
                validUntil = Instant.fromEpochMilliseconds(state.validUntilMillis)
            )
                .includeSubjectKeyIdentifier()
                .setAuthorityKeyIdentifierToCertificate(attestationKeyCertification.certificates[0])
                .addExtension(
                    oid = AttestationExtension.ATTESTATION_OID,
                    critical = false,
                    value = AttestationExtension.encode(state.challenge!!)
                )
                .build()

        state.cloudKeyStorage = storage.serialize().toByteArray()
        val response1 = CreateKeyResponse1(
            X509CertChain(listOf(attestationCert) + attestationKeyCertification.certificates),
            encryptCreateKeyState(state)
        )
        val encryptedResponse1 = E2EEResponse(
            encryptToDevice(e2eeState, response1.toCbor()),
            e2eeState.encrypt()
        )
        Logger.d(TAG, "$remoteHost: CreateKeyRequest1: Created key for client")
        return Pair(200, encryptedResponse1.toCbor())
    }

    @CborSerializable
    data class SignState(
        var keyContext: CreateKeyState? = null,
        var dataToSign: ByteArray? = null,
        var cloudNonce: ByteArray? = null,
    ) {
        companion object
    }

    private fun encryptSignState(state: SignState): ByteArray {
        return encryptState(state.toCbor())
    }

    private fun decryptSignState(encryptedState: ByteArray): SignState {
        return SignState.fromCbor(decryptState(encryptedState))
    }

    private fun doSignRequest0(
        request0: CloudSecureAreaProtocol.SignRequest0,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        val state = SignState()
        state.keyContext = decryptCreateKeyState(request0.keyContext)
        state.dataToSign = request0.dataToSign
        state.cloudNonce = Random.Default.nextBytes(32)
        val response0 = CloudSecureAreaProtocol.SignResponse0(
            state.cloudNonce!!,
            encryptSignState(state)
        )
        val encryptedResponse0 = E2EEResponse(
            encryptToDevice(e2eeState, response0.toCbor()),
            e2eeState.encrypt()
        )
        Logger.d(TAG, "$remoteHost: SignRequest0: Sending nonce to client")
        return Pair(200, encryptedResponse0.toCbor())
    }

    private suspend fun doSignRequest1(
        request1: CloudSecureAreaProtocol.SignRequest1,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        try {
            val state = decryptSignState(request1.serverState)
            val dataThatWasSignedLocally = Cbor.encode(
                CborArray.builder()
                    .add(state.cloudNonce!!)
                    .end()
                    .build()
            )
            check(Crypto.checkSignature(
                state.keyContext!!.localKey!!.ecPublicKey,
                dataThatWasSignedLocally,
                Algorithm.ES256,
                request1.signature)) { "Error verifying signature" }

            if (state.keyContext!!.passphraseRequired) {
                val lockedOutDuration =
                    passphraseFailureEnforcer.isLockedOut(state.keyContext!!.clientId!!)
                if (lockedOutDuration != null) {
                    Logger.i(
                        TAG, "$remoteHost: SignRequest1: Too many wrong passphrase attempts, " +
                                "locked out for $lockedOutDuration"
                    )
                    val response1 = CloudSecureAreaProtocol.SignResponse1(
                        CloudSecureAreaProtocol.RESULT_TOO_MANY_PASSPHRASE_ATTEMPTS,
                        null,
                        lockedOutDuration.inWholeMilliseconds
                    )
                    val encryptedResponse1 = E2EEResponse(
                        encryptToDevice(e2eeState, response1.toCbor()),
                        e2eeState.encrypt()
                    )
                    return Pair(200, encryptedResponse1.toCbor())
                }

                if (!checkPassphrase(
                        remoteHost,
                        request1.passphrase,
                        e2eeState.context!!,
                        state.keyContext!!
                    )
                ) {
                    Logger.d(TAG, "$remoteHost: SignRequest1: Error checking passphrase")
                    val response1 = CloudSecureAreaProtocol.SignResponse1(
                        CloudSecureAreaProtocol.RESULT_WRONG_PASSPHRASE,
                        null,
                        0L
                    )
                    val encryptedResponse1 = E2EEResponse(
                        encryptToDevice(e2eeState, response1.toCbor()),
                        e2eeState.encrypt()
                    )
                    return Pair(200, encryptedResponse1.toCbor())
                }
            }

            val storage = EphemeralStorage.deserialize(ByteString(state.keyContext!!.cloudKeyStorage!!))
            val secureArea = SoftwareSecureArea.create(storage)
            val signature = secureArea.sign(
                "CloudKey",
                Algorithm.ES256,
                state.dataToSign!!,
                null
            )
            Logger.d(TAG, "$remoteHost: SignRequest1: Signed data for client")
            val response1 = CloudSecureAreaProtocol.SignResponse1(
                CloudSecureAreaProtocol.RESULT_OK,
                signature,
                0L)
            val encryptedResponse1 = E2EEResponse(
                encryptToDevice(e2eeState, response1.toCbor()),
                e2eeState.encrypt()
            )
            return Pair(200, encryptedResponse1.toCbor())
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException(e)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException(e)
        } catch (e: SignatureException) {
            throw IllegalStateException(e)
        }
    }

    private fun checkPassphrase(
        remoteHost: String,
        givenPassphrase: String?,
        context: RegisterState,
        keyContext: CreateKeyState
    ): Boolean {
        if (!context.registrationComplete) {
            Logger.d(TAG, "$remoteHost: checkPassphrase: Stage 2 registration not complete")
            return false
        }
        if (givenPassphrase == null) {
            passphraseFailureEnforcer.recordFailedPassphraseAttempt(keyContext.clientId!!)
            Logger.d(TAG, "$remoteHost: checkPassphrase: Passphrase required but none was supplied")
            return false
        }
        val saltedPassphrase = Crypto.digest(
            Algorithm.SHA256,
            context.clientPassphraseSalt + givenPassphrase.encodeToByteArray()
        )
        if (!saltedPassphrase.contentEquals(context.clientSaltedPassphrase)) {
            passphraseFailureEnforcer.recordFailedPassphraseAttempt(keyContext.clientId!!)
            Logger.d(TAG, "$remoteHost: checkPassphrase: Wrong passphrase supplied")
            return false
        }
        return true
    }

    @CborSerializable
    data class KeyAgreementState(
        var keyContext: CreateKeyState? = null,
        var otherPublicKey: CoseKey? = null,
        var cloudNonce: ByteArray? = null,
    ) {
        companion object
    }

    private fun KeyAgreementState.encrypt(): ByteArray = encryptState(toCbor())

    private fun KeyAgreementState.Companion.decrypt(encryptedState: ByteArray) =
        fromCbor(decryptState(encryptedState))

    private fun doKeyAgreementRequest0(
        request0: CloudSecureAreaProtocol.KeyAgreementRequest0,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        val state = KeyAgreementState()
        state.keyContext = decryptCreateKeyState(request0.keyContext)
        state.otherPublicKey = request0.otherPublicKey
        state.cloudNonce = Random.Default.nextBytes(32)
        val response0 = CloudSecureAreaProtocol.KeyAgreementResponse0(
            state.cloudNonce!!,
            state.encrypt()
        )
        val encryptedResponse0 = E2EEResponse(
            encryptToDevice(e2eeState, response0.toCbor()),
            e2eeState.encrypt()
        )
        Logger.d(TAG, "$remoteHost: KeyAgreementRequest0: Sending nonce to client")
        return Pair(200, encryptedResponse0.toCbor())
    }

    private suspend fun doKeyAgreementRequest1(
        request1: CloudSecureAreaProtocol.KeyAgreementRequest1,
        remoteHost: String,
        e2eeState: E2EEState
    ): Pair<Int, ByteArray> {
        try {
            val state = KeyAgreementState.decrypt(request1.serverState)
            val dataThatWasSignedLocally = Cbor.encode(
                CborArray.builder()
                    .add(state.cloudNonce!!)
                    .end()
                    .build()
            )
            check(Crypto.checkSignature(
                state.keyContext!!.localKey!!.ecPublicKey,
                dataThatWasSignedLocally,
                Algorithm.ES256,
                request1.signature
            )) { "Error verifying signature" }

            if (state.keyContext!!.passphraseRequired) {
                val lockedOutDuration =
                    passphraseFailureEnforcer.isLockedOut(state.keyContext!!.clientId!!)
                if (lockedOutDuration != null) {
                    Logger.i(
                        TAG, "$remoteHost: KeyAgreementRequest1: Too many wrong passphrase attempts, " +
                                "locked out for $lockedOutDuration"
                    )
                    val response1 = CloudSecureAreaProtocol.KeyAgreementResponse1(
                        CloudSecureAreaProtocol.RESULT_TOO_MANY_PASSPHRASE_ATTEMPTS,
                        null,
                        lockedOutDuration.inWholeMilliseconds
                    )
                    val encryptedResponse1 = E2EEResponse(
                        encryptToDevice(e2eeState, response1.toCbor()),
                        e2eeState.encrypt()
                    )
                    return Pair(200, encryptedResponse1.toCbor())
                }

                if (!checkPassphrase(
                        remoteHost,
                        request1.passphrase,
                        e2eeState.context!!,
                        state.keyContext!!
                    )
                ) {
                    Logger.d(TAG, "$remoteHost: KeyAgreementRequest1: Error checking passphrase")
                    val response1 = CloudSecureAreaProtocol.KeyAgreementResponse1(
                        CloudSecureAreaProtocol.RESULT_WRONG_PASSPHRASE,
                        null,
                        0L
                    )
                    val encryptedResponse1 = E2EEResponse(
                        encryptToDevice(e2eeState, response1.toCbor()),
                        e2eeState.encrypt()
                    )
                    return Pair(200, encryptedResponse1.toCbor())
                }
            }


            val storage = EphemeralStorage.deserialize(
                ByteString(state.keyContext!!.cloudKeyStorage!!))
            val secureArea = SoftwareSecureArea.create(storage)
            var Zab = secureArea.keyAgreement(
                    "CloudKey",
                    state.otherPublicKey!!.ecPublicKey,
                    null
                )
            Logger.d(TAG, "$remoteHost: KeyAgreementRequest1: Calculated Zab")
            val response1 = CloudSecureAreaProtocol.KeyAgreementResponse1(
                CloudSecureAreaProtocol.RESULT_OK,
                Zab,
                0L)
            val encryptedResponse1 = E2EEResponse(
                encryptToDevice(e2eeState, response1.toCbor()),
                e2eeState.encrypt()
            )
            return Pair(200, encryptedResponse1.toCbor())
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException(e)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException(e)
        } catch (e: SignatureException) {
            throw IllegalStateException(e)
        }
    }

    private fun encryptToDevice(
        e2eeState: E2EEState,
        messagePlaintext: ByteArray
    ): ByteArray {
        val iv = ByteBuffer.allocate(12)
        iv.putInt(0, 0x00000000)
        val ivIdentifier = 0x00000000
        iv.putInt(4, ivIdentifier)
        iv.putInt(8, e2eeState.encryptedCounter++)
        return Crypto.encrypt(Algorithm.A128GCM, e2eeState.skCloud!!, iv.array(), messagePlaintext)
    }

    private suspend fun doE2EERequest(
        request: CloudSecureAreaProtocol.E2EERequest,
        remoteHost: String
    ): Pair<Int, ByteArray> {
        val e2eeState = E2EEState.decrypt(request.e2eeContext)
        val ageMilliseconds = System.currentTimeMillis() - e2eeState.derivationTimestamp
        if (ageMilliseconds > e2eeKeyLimitSeconds * 1000) {
            Logger.d(
                TAG, String.format(
                    Locale.US,
                    "$remoteHost: E2EE derived keys are expired, age is %.1f seconds and limit is %d seconds",
                    ageMilliseconds / 1000.0, e2eeKeyLimitSeconds
                )
            )
            return Pair(400, "E2EE derived keys expired".toByteArray())
        }
        val iv = ByteBuffer.allocate(12)
        iv.putInt(0, 0x00000000)
        val ivIdentifier = 0x00000001
        iv.putInt(4, ivIdentifier)
        iv.putInt(8, e2eeState.decryptedCounter)
        val plainText = try {
            Crypto.decrypt(
                Algorithm.A128GCM,
                e2eeState.skDevice!!,
                iv.array(),
                request.encryptedRequest)
        } catch (e: IllegalStateException) {
            return Pair(400, "Decryption failed".toByteArray())
        }
        e2eeState.decryptedCounter += 1
        return handleCommandInternal(plainText, remoteHost, e2eeState)
    }

    private suspend fun handleCommandInternal(
        requestData: ByteArray,
        remoteHost: String,
        e2eeState: E2EEState?
    ): Pair<Int, ByteArray> {
        val command = CloudSecureAreaProtocol.Command.fromCbor(requestData)
        // Fail early if stage 2 registration isn't complete.
        if (e2eeState != null && command !is CloudSecureAreaProtocol.RegisterStage2Request0) {
            if (!e2eeState.context!!.registrationComplete) {
                Logger.w(TAG, "$remoteHost: Stage 2 registration not complete")
                return Pair(400, "Stage 2 registration not complete".encodeToByteArray())
            }
        }
        return when (command) {
            is RegisterRequest0 -> doRegisterRequest0(command, remoteHost)
            is RegisterRequest1 -> doRegisterRequest1(command, remoteHost)
            is E2EESetupRequest0 -> doE2EESetupRequest0(command, remoteHost)
            is E2EESetupRequest1 -> doE2EESetupRequest1(command, remoteHost)
            is CloudSecureAreaProtocol.E2EERequest -> doE2EERequest(command, remoteHost)
            is CloudSecureAreaProtocol.RegisterStage2Request0 -> doRegisterStage2Request0(command, remoteHost, e2eeState!!)
            is CreateKeyRequest0 -> doCreateKeyRequest0(command, remoteHost, e2eeState!!)
            is CloudSecureAreaProtocol.CreateKeyRequest1 -> doCreateKeyRequest1(command, remoteHost, e2eeState!!)
            is CloudSecureAreaProtocol.SignRequest0 -> doSignRequest0(command, remoteHost, e2eeState!!)
            is CloudSecureAreaProtocol.SignRequest1 -> doSignRequest1(command, remoteHost, e2eeState!!)
            is CloudSecureAreaProtocol.KeyAgreementRequest0 -> doKeyAgreementRequest0(command, remoteHost, e2eeState!!)
            is CloudSecureAreaProtocol.KeyAgreementRequest1 -> doKeyAgreementRequest1(command, remoteHost, e2eeState!!)
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown command ${command}, returning 404")
                Pair(404, "Unknown command".toByteArray())
            }
        }
    }

    suspend fun handleCommand(requestData: ByteArray, remoteHost: String): Pair<Int, ByteArray> {
        return handleCommandInternal(requestData, remoteHost, null)
    }

    companion object {
        const val TAG = "CloudSecureAreaServer"

        // Really important these counters are never reused. We rely on the system
        // clock always going forward to achieve this.
        @get:Synchronized
        val encryptionGcmCounter: Long
            get() {
                var counter = System.currentTimeMillis()
                while (counter < lastCounter) {
                    try {
                        Thread.sleep(1)
                    } catch (e: InterruptedException) {
                    }
                }
                lastCounter = counter
                return counter
            }

        var lastCounter = Long.MIN_VALUE

        // This public key is from https://developer.android.com/training/articles/security-key-attestation
        private val GOOGLE_ROOT_ATTESTATION_KEY =
            "30820222300d06092a864886f70d01010105000382020f003082020a0282020100afb6c7822bb1a701ec2bb42e8bcc541663abef982f32c77f7531030c97524b1b5fe809fbc72aa9451f743cbd9a6f1335744aa55e77f6b6ac3535ee17c25e639517dd9c92e6374a53cbfe258f8ffbb6fd129378a22a4ca99c452d47a59f3201f44197ca1ccd7e762fb2f53151b6feb2fffd2b6fe4fe5bc6bd9ec34bfe08239daafceb8eb5a8ed2b3acd9c5e3a7790e1b51442793159859811ad9eb2a96bbdd7a57c93a91c41fccd27d67fd6f671aa0b815261ad384fa37944864604ddb3d8c4f920a19b1656c2f14ad6d03c56ec060899041c1ed1a5fe6d3440b556bad1d0a152589c53e55d370762f0122eef91861b1b0e6c4c80927499c0e9bec0b83e3bc1f93c72c049604bbd2f1345e62c3f8e26dbec06c94766f3c128239d4f4312fad8123887e06becf567583bf8355a81feeabaf99a83c8df3e2a322afc672bf120b135158b6821ceaf309b6eee77f98833b018daa10e451f06a374d50781f359082966bb778b9308942698e74e0bcd24628a01c2cc03e51f0b3e5b4ac1e4df9eaf9ff6a492a77c1483882885015b422ce67b80b88c9b48e13b607ab545c723ff8c44f8f2d368b9f6520d31145ebf9e862ad71df6a3bfd2450959d653740d97a12f368b13ef66d5d0a54a6e2f5d9a6fef446832bc67844725861f093dd0e6f3405da89643ef0f4d69b6420051fdb93049673e36950580d3cdf4fbd08bc58483952600630203010001"
                .fromHex()
    }
}