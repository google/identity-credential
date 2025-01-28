package com.android.identity.android.securearea.cloud

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import com.android.identity.android.securearea.UserAuthenticationType
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcSignature
import com.android.identity.crypto.fromJavaX509Certificates
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.securearea.AttestationExtension
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.KeyInvalidatedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.CreateKeyRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.CreateKeyRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.CreateKeyResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.CreateKeyResponse1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EERequest
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EEResponse
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.E2EESetupResponse1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.KeyAgreementRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.KeyAgreementRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.KeyAgreementResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.KeyAgreementResponse1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.RegisterResponse1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.SignRequest0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.SignRequest1
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.SignResponse0
import com.android.identity.securearea.cloud.CloudSecureAreaProtocol.SignResponse1
import com.android.identity.securearea.cloud.fromCbor
import com.android.identity.securearea.cloud.toCbor
import com.android.identity.securearea.fromCbor
import com.android.identity.securearea.toCbor
import com.android.identity.storage.Storage
import com.android.identity.storage.StorageEngine
import com.android.identity.storage.StorageTable
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.Logger
import com.android.identity.util.toHex
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.request.accept
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.delay
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import java.io.IOException
import java.net.HttpURLConnection
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.SignatureException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * An implementation of [SecureArea] using a Secure Area managed by an external server.
 *
 * The given [identifier] must start with `CloudSecureArea` and if the application is only using
 * a single instance of [CloudSecureArea], just using this string as the identifier is fine.
 *
 * For applications using multiple instances of [CloudSecureArea], a common format for the
 * identifier is `CloudSecureArea?id=1234567890&url=https://csa.example.com/csa-server` where the
 * `id` parameter is a unique identifier for the document and the `url` parameter
 * contains the URL to connect to.
 *
 * The [identifier] is used as a prefix for the Android Keystore alias space and also as a prefix
 * for all keys used in the passed-in [storageEngine]. As such, it's safe to use the same
 * [StorageEngine] instance for multiple [CloudSecureArea] instances.
 *
 * @param storageTable the storage to use for storing metadata about keys.
 * @param identifier an identifier for the Cloud Secure Area.
 * @param serverUrl the URL the Cloud Secure Area is using.
 */
open class CloudSecureArea protected constructor(
    private val storageTable: StorageTable,
    final override val identifier: String,
    val serverUrl: String,
) : SecureArea {
    private var skDevice: ByteArray? = null
    private var skCloud: ByteArray? = null
    private var e2eeContext: ByteArray? = null
    private var encryptedCounter = 0
    private var decryptedCounter = 0

    internal open suspend fun delayForBruteforceMitigation(duration: Duration) {
        Logger.i(TAG, "delayForBruteforceMitigation: delaying for $duration")
        delay(duration)
        Logger.i(TAG, "delayForBruteforceMitigation: resuming (delayed for $duration)")
    }

    override val displayName: String
        get() = "Cloud Secure Area"

    private val httpClient = HttpClient(Android) {
        install(HttpTimeout)
    }

    private var cloudBindingKey: EcPublicKey? = null
    private var registrationContext: ByteString? = null

    protected open suspend fun initialize() {
        require(identifier.startsWith(IDENTIFIER_PREFIX))
        storageTable.get(BINDING_KEY, identifier)?.let { bindingKeyData ->
            cloudBindingKey = Cbor.decode(bindingKeyData.toByteArray()).asCoseKey.ecPublicKey
        }
        registrationContext = storageTable.get(REGISTRATION_CONTEXT, identifier)
    }

    open suspend fun communicateLowlevel(
        endpointUri: String,
        requestData: ByteArray
    ): Pair<Int, ByteArray> {
        try {
            val httpResponse = httpClient.post(endpointUri) {
                contentType(ContentType.Application.Cbor)
                accept(ContentType.Application.Cbor)
                timeout {
                    requestTimeoutMillis = 10000
                }
                setBody(requestData)
            }
            val responseStatus = httpResponse.status.value
            val responseBody: ByteArray = httpResponse.body()
            return Pair(responseStatus, responseBody)
        } catch (e: Exception) {
            throw CloudException("Error communicating with Cloud Secure Area", e)
        }
    }

    private suspend fun communicate(
        endpointUri: String,
        requestData: ByteArray
    ): ByteArray {
        val (status, data) = communicateLowlevel(endpointUri, requestData)
        if (status != HttpURLConnection.HTTP_OK) {
            val message = try {
                String(data, StandardCharsets.UTF_8)
            } catch (e: Exception) {
                "Failed parsing as UTF-8: ${data.toHex()}"
            }
            throw CloudException("Status $status: $message")
        }
        return data
    }

    val isRegistered: Boolean
        get() = registrationContext != null

    /**
     * Registers with the cloud secure area.
     *
     * @param passphrase the passphrase to use.
     * @param passphraseConstraints the constraints for the passphrase.
     * @param onAuthorizeRootOfTrust called to authorize the Cloud Secure Area's root certificate.
     * @throws CloudException if an error occurred.
     */
    suspend fun register(
        passphrase: String,
        passphraseConstraints: PassphraseConstraints,
        onAuthorizeRootOfTrust: (cloudSecureAreaRootOfTrust: X509Cert) -> Boolean,
    ) {
        var response: ByteArray
        try {
            val request0 = RegisterRequest0("1.0")
            response = communicate(serverUrl, request0.toCbor())
            val response0 = CloudSecureAreaProtocol.Command.fromCbor(response) as RegisterResponse0
            val deviceBindingKeyAlias = "DeviceBindingKey"
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(deviceBindingKeyAlias, KeyProperties.PURPOSE_SIGN)
            builder.setDigests(KeyProperties.DIGEST_SHA256)
            builder.setAttestationChallenge(response0.cloudChallenge)
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            val deviceBindingKeyAttestation =
                X509CertChain.fromJavaX509Certificates(ks.getCertificateChain(deviceBindingKeyAlias))
            val deviceChallenge = Random.Default.nextBytes(32)
            val request1 = RegisterRequest1(
                deviceChallenge,
                deviceBindingKeyAttestation,
                response0.serverState
            )
            response = communicate(serverUrl, request1.toCbor())
            val response1 = CloudSecureAreaProtocol.Command.fromCbor(response) as RegisterResponse1
            validateCloudBindingKeyAttestation(
                response1.cloudBindingKeyAttestation,
                deviceChallenge,
                onAuthorizeRootOfTrust,
            )

            // Ready to go...
            cloudBindingKey = response1.cloudBindingKeyAttestation.certificates[0].ecPublicKey
            registrationContext = ByteString(response1.serverState)

            // ... and save for future use
            storageTable.insert(
                key = BINDING_KEY,
                partitionId = identifier,
                data = ByteString(Cbor.encode(cloudBindingKey!!.toCoseKey().toDataItem()))
            )
            storageTable.insert(
                key = REGISTRATION_CONTEXT,
                partitionId = identifier,
                data = registrationContext!!
            )

            // We need E2EE before entering the second stage of registration - this is because we
            // need the data exchanged in this stage (e.g. the passphrase) to be encrypted so only
            // the Secure Enclave on the server side can see it.
            setupE2EE(false)

            // Note that the second registration phase modifies the registrationContext so we need
            // to update it once the operation completes.
            val stage2Request0 = CloudSecureAreaProtocol.RegisterStage2Request0(passphrase)
            val stage2Response0 =
                CloudSecureAreaProtocol.Command.fromCbor(communicateE2EE(stage2Request0.toCbor()))
                        as CloudSecureAreaProtocol.RegisterStage2Response0
            registrationContext = ByteString(stage2Response0.serverState)
            storageTable.update(
                key = REGISTRATION_CONTEXT,
                partitionId = identifier,
                data = registrationContext!!
            )
            storageTable.insert(
                key = PASSPHRASE_CONSTRAINTS,
                partitionId = identifier,
                data = ByteString(passphraseConstraints.toCbor())
            )
        } catch (e: Throwable) {
            throw CloudException(e)
        }
    }

    /**
     * The [PassphraseConstraints] configured at registration time.
     *
     * @return the [PassphraseConstraints] passed to to the [register] method.
     * @throws IllegalStateException if not registered with a Cloud Secure Area instance.
     */
    suspend fun getPassphraseConstraints(): PassphraseConstraints {
        val encoded = storageTable.get(key = PASSPHRASE_CONSTRAINTS, partitionId = identifier)
            ?: throw IllegalStateException("Not registered with CSA")
        return PassphraseConstraints.fromCbor(encoded.toByteArray())
    }

    suspend fun unregister() {
        // TODO: should we send a RPC to server to let them know we're bailing?
        storageTable.delete(BINDING_KEY)
        storageTable.delete(REGISTRATION_CONTEXT)
        storageTable.delete(PASSPHRASE_CONSTRAINTS)
        cloudBindingKey = null
        registrationContext = null
        skDevice = null
    }

    private fun validateCloudBindingKeyAttestation(
        attestation: X509CertChain,
        expectedDeviceChallenge: ByteArray,
        onAuthorizeRootOfTrust: (cloudSecureAreaRootOfTrust: X509Cert) -> Boolean,
    ) {
        val x509Certs = mutableListOf<X509Certificate>()
        for (cert in attestation.certificates) {
            x509Certs.add(cert.javaX509Certificate)
        }

        for (n in 0 until x509Certs.size - 1) {
            val cert = x509Certs[n]
            val nextCert = x509Certs[n + 1]
            try {
                cert.verify(nextCert.publicKey)
            } catch (e: Exception) {
                throw CloudException("Error verifying attestation chain")
            }
        }

        val rootX509Cert = attestation.certificates.last()
        if (!onAuthorizeRootOfTrust(rootX509Cert)) {
            throw CloudException("Root X509Cert not authorized by app")
        }

        val leafX509Cert = x509Certs.first()
        val extensionDerEncodedString = leafX509Cert.getExtensionValue(AttestationExtension.ATTESTATION_OID)
            ?: throw CloudException(
                "No attestation extension at OID ${AttestationExtension.ATTESTATION_OID}")

        val attestationExtension = try {
            val asn1InputStream = ASN1InputStream(extensionDerEncodedString);
            (asn1InputStream.readObject() as ASN1OctetString).octets
        } catch (e: Exception) {
            throw CloudException("Error decoding attestation extension", e)
        }

        val challengeInAttestation = AttestationExtension.decode(attestationExtension)
        if (!challengeInAttestation.contentEquals(expectedDeviceChallenge)) {
            throw CloudException("Challenge in attestation does match expected attestation")
        }
    }

    private suspend fun setupE2EE(forceSetup: Boolean) {
        // No need to setup E2EE if it's already up...
        if (!forceSetup && skDevice != null) {
            return
        }
        var response: ByteArray
        try {
            val request0 = E2EESetupRequest0(registrationContext!!.toByteArray())
            response = communicate(serverUrl, request0.toCbor())
            val response0 = CloudSecureAreaProtocol.Command.fromCbor(response) as E2EESetupResponse0
            val deviceNonce = Random.Default.nextBytes(32)
            val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val dataToSign = Cbor.encode(
                CborArray.builder()
                    .add(eDeviceKey.publicKey.toCoseKey().toDataItem())
                    .add(response0.cloudNonce)
                    .add(deviceNonce)
                    .end()
                    .build()
            )
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            val deviceBindingKeyEntry = ks.getEntry("DeviceBindingKey", null)
                ?: throw IllegalArgumentException("No entry for DeviceBindingKey")
            val deviceBindingKey = (deviceBindingKeyEntry as KeyStore.PrivateKeyEntry).privateKey
            val s = Signature.getInstance("SHA256withECDSA")
            s.initSign(deviceBindingKey)
            s.update(dataToSign)
            val derSignature = s.sign()
            val request1 = E2EESetupRequest1(
                eDeviceKey.publicKey.toCoseKey(),
                deviceNonce,
                EcSignature.fromDerEncoded(EcCurve.P256.bitSize, derSignature),
                response0.serverState
            )
            response = communicate(serverUrl, request1.toCbor())
            val response1 = CloudSecureAreaProtocol.Command.fromCbor(response) as E2EESetupResponse1
            val dataSignedByTheCloud = Cbor.encode(
                CborArray.builder()
                    .add(response1.eCloudKey.toDataItem())
                    .add(response0.cloudNonce)
                    .add(deviceNonce)
                    .end()
                    .build()
            )
            if (!Crypto.checkSignature(
                    cloudBindingKey!!,
                    dataSignedByTheCloud,
                    Algorithm.ES256,
                    response1.signature
                )
            ) {
                throw CloudException("Error verifying signature")
            }

            // Now we can derive SKDevice and SKCloud
            val Zab = Crypto.keyAgreement(eDeviceKey, response1.eCloudKey.ecPublicKey)
            val salt = Crypto.digest(
                Algorithm.SHA256,
                Cbor.encode(
                    CborArray.builder()
                        .add(deviceNonce)
                        .add(response0.cloudNonce)
                        .end()
                        .build()
                )
            )
            skDevice = Crypto.hkdf(
                Algorithm.HMAC_SHA256,
                Zab,
                salt,
                "SKDevice".toByteArray(),
                32
            )
            skCloud = Crypto.hkdf(
                Algorithm.HMAC_SHA256,
                Zab,
                salt,
                "SKCloud".toByteArray(),
                32
            )
            e2eeContext = response1.serverState
            encryptedCounter = 1
            decryptedCounter = 1
        } catch (e: Exception) {
            throw CloudException(e)
        }
    }

    private fun encryptToCloud(messagePlaintext: ByteArray): ByteArray {
        // The IV and these constants are specified in ISO/IEC 18013-5:2021 clause 9.1.1.5.
        val iv = ByteBuffer.allocate(12)
        iv.putInt(0, 0x00000000)
        val ivIdentifier = 0x00000001
        iv.putInt(4, ivIdentifier)
        iv.putInt(8, encryptedCounter++)
        return Crypto.encrypt(Algorithm.A128GCM, skDevice!!, iv.array(), messagePlaintext)
    }

    private fun decryptFromCloud(messageCiphertext: ByteArray): ByteArray {
        val iv = ByteBuffer.allocate(12)
        iv.putInt(0, 0x00000000)
        val ivIdentifier = 0x00000000
        iv.putInt(4, ivIdentifier)
        iv.putInt(8, decryptedCounter++)
        return Crypto.decrypt(Algorithm.A128GCM, skCloud!!, iv.array(), messageCiphertext)
    }

    // This is internal rather than private b/c it's used in testPassphraseCannotBeChanged()
    internal suspend fun communicateE2EE(requestData: ByteArray): ByteArray {
        return communicateE2EEInternal(requestData, 0)
    }

    private suspend fun communicateE2EEInternal(
        requestData: ByteArray,
        callDepth: Int
    ): ByteArray {
        val requestWrapper = E2EERequest(
            encryptToCloud(requestData),
            e2eeContext!!
        )
        val (httpResponseCode, response) = communicateLowlevel(serverUrl, requestWrapper.toCbor())

        if (httpResponseCode == HttpURLConnection.HTTP_BAD_REQUEST) {
            // This status code means that decryption failed
            if (callDepth > 10) {
                throw CloudException("Error reinitializing E2EE after $callDepth attempts")
            }
            Logger.d(TAG, "Received status 400, reinitializing E2EE")
            setupE2EE(true)
            return communicateE2EEInternal(requestData, callDepth + 1)
        } else if (httpResponseCode != HttpURLConnection.HTTP_OK) {
            throw CloudException("Excepted status code 200 or 400, got $httpResponseCode")
        }
        val responseWrapper = CloudSecureAreaProtocol.Command.fromCbor(response) as E2EEResponse
        e2eeContext = responseWrapper.e2eeContext
        return decryptFromCloud(responseWrapper.encryptedResponse)
    }

    override suspend fun createKey(
        alias: String?,
        createKeySettings: com.android.identity.securearea.CreateKeySettings
    ): String {
        if (alias != null) {
            // If the key with the given alias exists, it is silently overwritten.
            // TODO: review if this is the semantics we want
            storageTable.delete(alias)
        }
        val cSettings = if (createKeySettings is CloudCreateKeySettings) {
            createKeySettings
        } else {
            // Use default settings if user passed in a generic SecureArea.CreateKeySettings.
            CloudCreateKeySettings.Builder(byteArrayOf()).build()
        }
        setupE2EE(false)
        try {
            // Default for validFrom and validUntil is Jan 1, 1970 to Feb 7, 2106
            var validFrom: Long = 0
            var validUntil = Int.MAX_VALUE * 1000L * 2
            if (cSettings.validFrom != null) {
                validFrom = cSettings.validFrom.toEpochMilliseconds()
            }
            if (cSettings.validUntil != null) {
                validUntil = cSettings.validUntil.toEpochMilliseconds()
            }
            val request0 = CreateKeyRequest0(
                cSettings.keyPurposes,
                cSettings.ecCurve,
                validFrom,
                validUntil,
                cSettings.passphraseRequired,
                cSettings.attestationChallenge
            )
            val response0 = CloudSecureAreaProtocol.Command.fromCbor(communicateE2EE(request0.toCbor())) as CreateKeyResponse0
            val newKeyAlias = storageTable.insert(
                key = alias,
                partitionId = identifier,
                data = ByteString()
            )
            val localKeyAlias = getLocalKeyAlias(newKeyAlias)
            val kpg =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(localKeyAlias, KeyProperties.PURPOSE_SIGN)
            builder.setDigests(KeyProperties.DIGEST_SHA256)
            builder.setAttestationChallenge(response0.cloudChallenge)
            if (cSettings.userAuthenticationRequired) {
                builder.setUserAuthenticationRequired(true)
                val timeoutMillis = cSettings.userAuthenticationTimeoutMillis
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val userAuthenticationType = cSettings.userAuthenticationType
                    var type = 0
                    if (userAuthenticationType.contains(UserAuthenticationType.LSKF)) {
                        type = type or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    }
                    if (userAuthenticationType.contains(UserAuthenticationType.BIOMETRIC)) {
                        type = type or KeyProperties.AUTH_BIOMETRIC_STRONG
                    }
                    if (timeoutMillis == 0L) {
                        builder.setUserAuthenticationParameters(0, type)
                    } else {
                        val timeoutSeconds = Math.max(1, timeoutMillis / 1000).toInt()
                        builder.setUserAuthenticationParameters(timeoutSeconds, type)
                    }
                } else {
                    if (timeoutMillis == 0L) {
                        builder.setUserAuthenticationValidityDurationSeconds(-1)
                    } else {
                        val timeoutSeconds = Math.max(1, timeoutMillis / 1000).toInt()
                        builder.setUserAuthenticationValidityDurationSeconds(timeoutSeconds)
                    }
                }
                builder.setInvalidatedByBiometricEnrollment(false)
            }
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            val request1 = CreateKeyRequest1(
                X509CertChain.fromJavaX509Certificates(ks.getCertificateChain(localKeyAlias)),
                response0.serverState
            )
            val response1 = CloudSecureAreaProtocol.Command.fromCbor(communicateE2EE(request1.toCbor())) as CreateKeyResponse1
            storageTable.update(
                key = newKeyAlias,
                partitionId = identifier,
                data = ByteString(response1.serverState)
            )
            saveKeyMetadata(newKeyAlias, cSettings, response1.remoteKeyAttestation)
            return newKeyAlias
        } catch (e: Exception) {
            throw CloudException(e)
        }
    }

    override suspend fun deleteKey(alias: String) {
        val localKeyAlias = getLocalKeyAlias(alias)
        val ks: KeyStore
        try {
            ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            if (!ks.containsAlias(localKeyAlias)) {
                Logger.w(TAG, "Key with alias '$localKeyAlias' doesn't exist")
            } else {
                ks.deleteEntry(localKeyAlias)
            }
            storageTable.delete(
                key = alias,
                partitionId = identifier
            )
            storageTable.delete(
                key = METADATA_PREFIX + alias,
                partitionId = identifier
            )
        } catch (e: Exception) {
            throw IllegalStateException("Error loading keystore", e)
        }
    }

    @Throws(com.android.identity.securearea.KeyLockedException::class)
    override suspend fun sign(
        alias: String,
        signatureAlgorithm: Algorithm,
        dataToSign: ByteArray,
        keyUnlockData: com.android.identity.securearea.KeyUnlockData?
    ): EcSignature {
        var resultingSignature: EcSignature? = null
        val keyContext = storageTable.get(
            key = alias,
            partitionId = identifier
        )
        setupE2EE(false)
        var response: ByteArray

        // Throw if passphrase is required and not passed in.
        val keyInfo = getKeyInfo(alias)
        if (keyInfo.isPassphraseRequired) {
            if (keyUnlockData == null || (keyUnlockData as CloudKeyUnlockData).passphrase == null) {
                throw CloudKeyLockedException(
                    CloudKeyLockedException.Reason.WRONG_PASSPHRASE,
                    "No passphrase supplied"
                )
            }
        }

        try {
            val request0 =
                SignRequest0(signatureAlgorithm.coseAlgorithmIdentifier, dataToSign, keyContext!!.toByteArray())
            response = communicateE2EE(request0.toCbor())
            val response0 = CloudSecureAreaProtocol.Command.fromCbor(response) as SignResponse0
            val dataToSignLocally = Cbor.encode(
                CborArray.builder()
                    .add(response0.cloudNonce)
                    .end()
                    .build()
            )
            val localKeyAlias = getLocalKeyAlias(alias)
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            val deviceBindingKeyEntry = ks.getEntry(localKeyAlias, null)
                ?: throw KeyInvalidatedException("This key is no longer available")
            val localKey = (deviceBindingKeyEntry as KeyStore.PrivateKeyEntry).privateKey
            var s: Signature? = null
            if (keyUnlockData != null) {
                val csaUnlockData = keyUnlockData as CloudKeyUnlockData
                if (csaUnlockData.cryptoObject_ != null) {
                    s = csaUnlockData.cryptoObject_!!.signature
                }
            }
            if (s == null) {
                s = Signature.getInstance("SHA256withECDSA")
                s.initSign(localKey)
            }
            s!!.update(dataToSignLocally)
            val derSignatureLocal = s.sign()

            val request1 = SignRequest1(
                EcSignature.fromDerEncoded(EcCurve.P256.bitSize, derSignatureLocal),
                (keyUnlockData as? CloudKeyUnlockData)?.passphrase,
                response0.serverState
            )
            do {
                var tryAgain = false

                response = communicateE2EE(request1.toCbor())
                val response1 = CloudSecureAreaProtocol.Command.fromCbor(response) as SignResponse1
                when (response1.result) {
                    CloudSecureAreaProtocol.RESULT_OK -> {
                        resultingSignature = response1.signature
                    }

                    CloudSecureAreaProtocol.RESULT_WRONG_PASSPHRASE -> {
                        throw CloudKeyLockedException(
                            CloudKeyLockedException.Reason.WRONG_PASSPHRASE,
                            "Wrong passphrase supplied"
                        )
                    }

                    CloudSecureAreaProtocol.RESULT_TOO_MANY_PASSPHRASE_ATTEMPTS -> {
                        delayForBruteforceMitigation(response1.waitDurationMillis.milliseconds)
                        tryAgain = true
                    }

                    else -> throw CloudException("Unexpected result ${response1.result}")
                }
            } while (tryAgain)

        } catch (e: UserNotAuthenticatedException) {
            throw CloudKeyLockedException(
                CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED,
                "User not authenticated",
                e
            )
        } catch (e: SignatureException) {
            // This is a work-around for Android Keystore throwing a SignatureException
            // when it should be throwing UserNotAuthenticatedException instead. b/282174161
            //
            if (e.message!!.startsWith(
                    "android.security.KeyStoreException: Key user not authenticated"
                )
            ) {
                throw CloudKeyLockedException(
                    CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED,
                    "User not authenticated", e
                )
            }
            throw IllegalStateException("Unexpected exception while signing", e)
        } catch (e: KeyStoreException) {
            throw IllegalStateException("Unexpected exception while signing", e)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Unexpected exception while signing", e)
        } catch (e: UnrecoverableEntryException) {
            throw IllegalStateException("Unexpected exception while signing", e)
        } catch (e: CertificateException) {
            throw IllegalStateException("Unexpected exception while signing", e)
        } catch (e: IOException) {
            throw IllegalStateException("Unexpected exception while signing", e)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException("Unexpected exception while signing", e)
        }
        return resultingSignature!!
    }

    @Throws(com.android.identity.securearea.KeyLockedException::class)
    override suspend fun keyAgreement(
        alias: String,
        otherKey: EcPublicKey,
        keyUnlockData: com.android.identity.securearea.KeyUnlockData?
    ): ByteArray {
        var Zab: ByteArray? = null
        val keyContext = storageTable.get(key = alias, partitionId = identifier)
        setupE2EE(false)
        var response: ByteArray

        // Throw if passphrase is required and not passed in.
        val keyInfo = getKeyInfo(alias)
        if (keyInfo.isPassphraseRequired) {
            if (keyUnlockData == null || (keyUnlockData as CloudKeyUnlockData).passphrase == null) {
                throw CloudKeyLockedException(
                    CloudKeyLockedException.Reason.WRONG_PASSPHRASE,
                    "No passphrase supplied"
                )
            }
        }

        try {
            val request0 = KeyAgreementRequest0(otherKey.toCoseKey(), keyContext!!.toByteArray())
            response = communicateE2EE(request0.toCbor())
            val response0 = CloudSecureAreaProtocol.Command.fromCbor(response) as KeyAgreementResponse0
            val dataToSignLocally = Cbor.encode(
                CborArray.builder()
                    .add(response0.cloudNonce)
                    .end()
                    .build()
            )
            val localKeyAlias = getLocalKeyAlias(alias)
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            val deviceBindingKeyEntry = ks.getEntry(localKeyAlias, null)
                ?: throw KeyInvalidatedException("This key is no longer available")
            val localKey = (deviceBindingKeyEntry as KeyStore.PrivateKeyEntry).privateKey
            var s: Signature? = null
            if (keyUnlockData != null) {
                val csaUnlockData = keyUnlockData as CloudKeyUnlockData
                if (csaUnlockData.cryptoObject_ != null) {
                    s = csaUnlockData.cryptoObject_!!.signature
                }
            }
            if (s == null) {
                s = Signature.getInstance("SHA256withECDSA")
                s.initSign(localKey)
            }
            s!!.update(dataToSignLocally)
            val derSignatureLocal = s.sign()

            val request1 = KeyAgreementRequest1(
                EcSignature.fromDerEncoded(EcCurve.P256.bitSize, derSignatureLocal),
                (keyUnlockData as? CloudKeyUnlockData)?.passphrase,
                response0.serverState
            )
            do {
                var tryAgain = false

                response = communicateE2EE(request1.toCbor())
                val response1 = CloudSecureAreaProtocol.Command.fromCbor(response) as KeyAgreementResponse1
                when (response1.result) {
                    CloudSecureAreaProtocol.RESULT_OK -> {
                        Zab = response1.zab
                    }

                    CloudSecureAreaProtocol.RESULT_WRONG_PASSPHRASE -> {
                        throw CloudKeyLockedException(
                            CloudKeyLockedException.Reason.WRONG_PASSPHRASE,
                            "Wrong passphrase supplied"
                        )
                    }

                    CloudSecureAreaProtocol.RESULT_TOO_MANY_PASSPHRASE_ATTEMPTS -> {
                        delayForBruteforceMitigation(response1.waitDurationMillis.milliseconds)
                        tryAgain = true
                    }

                    else -> throw CloudException("Unexpected result ${response1.result}")
                }
            } while (tryAgain)

        } catch (e: UserNotAuthenticatedException) {
            throw CloudKeyLockedException(
                CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED,
                "User not authenticated", e
            )
        } catch (e: SignatureException) {
            // This is a work-around for Android Keystore throwing a SignatureException
            // when it should be throwing UserNotAuthenticatedException instead. b/282174161
            //
            if (e.message!!.startsWith(
                    "android.security.KeyStoreException: Key user not authenticated"
                )
            ) {
                throw CloudKeyLockedException(
                    CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED,
                    "User not authenticated", e
                )
            }
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        } catch (e: KeyStoreException) {
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        } catch (e: UnrecoverableEntryException) {
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        } catch (e: CertificateException) {
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        } catch (e: IOException) {
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException("Unexpected exception while performing Key Agreement", e)
        }
        return Zab!!
    }

    override suspend fun getKeyInfo(alias: String): CloudKeyInfo {
        val data = storageTable.get(key = METADATA_PREFIX + alias, partitionId = identifier)
            ?: throw IllegalArgumentException("No key with given alias")
        val map = Cbor.decode(data.toByteArray())
        val keyPurposes = map["keyPurposes"].asNumber
        val userAuthenticationRequired = map["userAuthenticationRequired"].asBoolean
        val userAuthenticationTimeoutMillis = map["userAuthenticationTimeoutMillis"].asNumber
        val isPassphraseRequired = map["isPassphraseRequired"].asBoolean
        val isStrongBoxBacked = map["useStrongBox"].asBoolean
        var validFrom: Instant? = null
        var validUntil: Instant? = null
        if (map.hasKey("validFrom")) {
            validFrom = Instant.fromEpochMilliseconds(map["validFrom"].asNumber)
        }
        if (map.hasKey("validUntil")) {
            validUntil = Instant.fromEpochMilliseconds(map["validUntil"].asNumber)
        }
        val attestationCertChain = map["attestationCertChain"].asX509CertChain
        val userAuthenticationType = map["userAuthenticationType"].asNumber
        return CloudKeyInfo(
            KeyAttestation(attestationCertChain.certificates[0].ecPublicKey, attestationCertChain),
            KeyPurpose.decodeSet(keyPurposes),
            userAuthenticationRequired,
            userAuthenticationTimeoutMillis,
            UserAuthenticationType.decodeSet(userAuthenticationType),
            validFrom,
            validUntil,
            isPassphraseRequired,
            isStrongBoxBacked,
        )
    }

    override suspend fun getKeyInvalidated(alias: String): Boolean {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        // TODO: move to an IO thread
        ks.load(null)
        // If the LSKF is removed, all auth-bound keys are removed and the result is
        // that KeyStore.getEntry() returns null.
        val localKeyAlias = getLocalKeyAlias(alias)
        return ks.getEntry(localKeyAlias, null) == null
    }

    private suspend fun saveKeyMetadata(
        alias: String,
        settings: CloudCreateKeySettings,
        attestationCertChain: X509CertChain
    ) {
        Logger.d(TAG, "attestation len = ${attestationCertChain.certificates.size}")
        val map = CborMap.builder()
        map.put("keyPurposes", KeyPurpose.encodeSet(settings.keyPurposes))
        map.put("userAuthenticationType",
            UserAuthenticationType.encodeSet(settings.userAuthenticationType)
        )
        map.put("userAuthenticationRequired", settings.userAuthenticationRequired)
        map.put("userAuthenticationTimeoutMillis", settings.userAuthenticationTimeoutMillis)
        if (settings.validFrom != null) {
            map.put("validFrom", settings.validFrom.toEpochMilliseconds())
        }
        if (settings.validUntil != null) {
            map.put("validUntil", settings.validUntil.toEpochMilliseconds())
        }
        map.put("isPassphraseRequired", settings.passphraseRequired)
        map.put("useStrongBox", settings.useStrongBox)
        map.put("attestationCertChain", attestationCertChain.toDataItem())
        storageTable.insert(
            key = METADATA_PREFIX + alias,
            partitionId = identifier,
            data = ByteString(Cbor.encode(map.end().build()))
        )
    }

    internal fun getLocalKeyAlias(alias: String): String {
        return "${identifier}_alias_${alias}"
    }

    companion object {
        const val IDENTIFIER_PREFIX = "CloudSecureArea"

        private const val TAG = "CloudSecureArea"

        // Special keys in storage
        private const val BINDING_KEY = "[BindingKey]"
        private const val REGISTRATION_CONTEXT = "[RegistrationContext]"
        private const val PASSPHRASE_CONSTRAINTS = "[PassphraseConstraints]"

        // Prefix for metadata storage key
        private const val METADATA_PREFIX = "@"

        /**
         * Creates an instance of AndroidKeystoreSecureArea.
         *
         * @param storage the storage engine to use for storing key material.
         */
        suspend fun create(
            storage: Storage,
            identifier: String,
            serverUrl: String
        ): CloudSecureArea {
            val secureArea = CloudSecureArea(
                storage.getTable(tableSpec),
                identifier,
                serverUrl
            )
            secureArea.initialize()
            return secureArea
        }

        private val tableSpec = StorageTableSpec(
            name = "CloudSecureArea",
            supportPartitions = true,
            supportExpiration = false
        )
    }
}