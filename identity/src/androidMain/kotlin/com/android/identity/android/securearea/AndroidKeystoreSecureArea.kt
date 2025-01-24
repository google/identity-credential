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

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.FeatureInfo
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.securearea.AndroidKeystoreSecureArea.Capabilities
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborMap
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcSignature
import com.android.identity.crypto.javaPublicKey
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.KeyInvalidatedException
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.keyPurposeSet
import com.android.identity.storage.Storage
import com.android.identity.storage.StorageTable
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.Logger
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.ProviderException
import java.security.Signature
import java.security.SignatureException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.sql.Date
import javax.crypto.KeyAgreement
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import java.io.ByteArrayInputStream

/**
 * An implementation of [SecureArea] using Android Keystore.
 *
 *
 * Keys created using this implementation are hardware-backed, that is the private key
 * material is designed to never leave Secure Hardware. In this context Secure Hardware
 * can mean either the TEE (Trusted Execution Environment) or an SE (Secure Element),
 * specifically anything meeting the definition of an *Isolated Execution Environment
 * as per
 * [section 9.11 of the Android CDD](https://source.android.com/docs/compatibility/13/android-13-cdd#911_keys_and_credentials).
 *
 * Any key created will be attested to by the Secure Hardware, using
 * [Android Keystore Key Attestation](https://developer.android.com/training/articles/security-key-attestation).
 * This gives remote parties (such as real-world identity document issuers) a high level of
 * assurance that the private part of the key exists only in Secure Hardware and also gives a
 * strong signal about the general state of the device (including whether
 * [verified boot](https://source.android.com/docs/security/features/verifiedboot)
 * is enabled, latest patch level, etc.) and which particular Android application (identified by
 * [Application Id](https://developer.android.com/build/configure-app-module#set_the_application_id))
 * created the key.
 *
 * Curve [EcCurve.P256] for signing using algorithm [Algorithm.ES256] is guaranteed to be
 * implemented in Secure Hardware on any Android device shipping with Android 8.1 or later. As of
 * 2024 this includes nearly all Android devices.
 *
 * If the device has a
 * [StrongBox Android Keystore](https://source.android.com/docs/compatibility/13/android-13-cdd#9112_strongbox),
 * keys can be stored there using [CreateKeySettings.Builder.setUseStrongBox].
 *
 * Other optional features may be available depending on the version of the underlying
 * software (called [Keymint](https://source.android.com/docs/security/features/keystore))
 * running in the Secure Area. The [Capabilities] helper class can be used to determine
 * what the device supports.
 *
 * This implementation works only on Android and requires API level 24 or later.
 *
 * Use [AndroidKeystoreSecureArea.create] to create an instance of this class.
 */
class AndroidKeystoreSecureArea(
    private val context: Context,
    private val storageTable: StorageTable
) : SecureArea {
    override val identifier: String
        get() = IDENTIFIER

    override val displayName: String
        get() = "Android Keystore Secure Area"

    private val keymintTeeFeatureLevel: Int
    private val keymintSbFeatureLevel: Int

    /**
     * Constructs a new [AndroidKeystoreSecureArea].
     *
     * @param context the application context.
     * @param storageEngine the storage engine to use for storing metadata about keys.
     */
    init {
        keymintTeeFeatureLevel = getFeatureVersionKeystore(
            context, false
        )
        keymintSbFeatureLevel = getFeatureVersionKeystore(
            context, true
        )
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

        // This will throw an exception if an already-used alias is given.
        val newKeyAlias = storageTable.insert(alias, ByteString())

        val aSettings: AndroidKeystoreCreateKeySettings
        aSettings = if (createKeySettings is AndroidKeystoreCreateKeySettings) {
            createKeySettings
        } else {
            // Use default settings if user passed in a generic SecureArea.CreateKeySettings.
            AndroidKeystoreCreateKeySettings.Builder("".toByteArray()).build()
        }
        var kpg: KeyPairGenerator? = null
        try {
            kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            var purposes = 0
            if (aSettings.keyPurposes.contains(KeyPurpose.SIGN)) {
                purposes = purposes or KeyProperties.PURPOSE_SIGN
            }
            if (aSettings.keyPurposes.contains(KeyPurpose.AGREE_KEY)) {
                purposes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    purposes or KeyProperties.PURPOSE_AGREE_KEY
                } else {
                    throw IllegalArgumentException(
                        "PURPOSE_AGREE_KEY not supported on this device"
                    )
                }

                // Android KeyStore tries to be "helpful" by creating keys in Software if
                // the Secure World (Keymint) lacks support for the requested feature, for
                // example ECDH. This will never work (for RWI, the document issuer will
                // detect it when examining the attestation) so just bail early if this
                // is the case.
                if (aSettings.useStrongBox) {
                    require(keymintSbFeatureLevel >= 100) {
                        "PURPOSE_AGREE_KEY not supported on " +
                                "this StrongBox KeyMint version"
                    }
                } else {
                    require(keymintTeeFeatureLevel >= 100) {
                        "PURPOSE_AGREE_KEY not supported on " +
                                "this KeyMint version"
                    }
                }
            }
            val builder = KeyGenParameterSpec.Builder(newKeyAlias, purposes)
            when (aSettings.ecCurve) {
                EcCurve.P256 ->                     // Works with both purposes.
                    builder.setDigests(KeyProperties.DIGEST_SHA256)

                EcCurve.ED25519 -> {
                    // Only works with KEY_PURPOSE_SIGN
                    require(aSettings.keyPurposes.contains(KeyPurpose.SIGN)) { "Curve Ed25519 only works with purpose SIGN" }
                    builder.setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
                }

                EcCurve.X25519 -> {
                    // Only works with KEY_PURPOSE_AGREE_KEY
                    require(aSettings.keyPurposes.contains(KeyPurpose.AGREE_KEY)) { "Curve X25519 only works with purpose AGREE_KEY" }
                    builder.setAlgorithmParameterSpec(ECGenParameterSpec("x25519"))
                }

                EcCurve.BRAINPOOLP256R1, EcCurve.BRAINPOOLP320R1, EcCurve.BRAINPOOLP384R1, EcCurve.BRAINPOOLP512R1, EcCurve.ED448, EcCurve.P384, EcCurve.P521, EcCurve.X448 -> throw IllegalArgumentException(
                    "Curve is not supported"
                )

                else -> throw IllegalArgumentException("Curve is not supported")
            }
            if (aSettings.userAuthenticationRequired) {
                val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                if (!keyguardManager.isDeviceSecure) {
                    throw ScreenLockRequiredException(
                        "Screen lock must be set up to create keys with user authentication"
                    )
                }
                builder.setUserAuthenticationRequired(true)
                val timeoutMillis = aSettings.userAuthenticationTimeoutMillis
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val userAuthenticationTypes = aSettings.userAuthenticationTypes
                    var type = 0
                    if (userAuthenticationTypes.contains(UserAuthenticationType.LSKF)) {
                        type = type or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    }
                    if (userAuthenticationTypes.contains(UserAuthenticationType.BIOMETRIC)) {
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
            if (aSettings.useStrongBox) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true)
                }
            }
            if (aSettings.attestKeyAlias != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    builder.setAttestKeyAlias(aSettings.attestKeyAlias)
                }
            }
            builder.setAttestationChallenge(aSettings.attestationChallenge)
            if (aSettings.validFrom != null) {
                val notBefore = Date(aSettings.validFrom.toEpochMilliseconds())
                val notAfter = Date(aSettings.validUntil!!.toEpochMilliseconds())
                builder.setKeyValidityStart(notBefore)
                builder.setCertificateNotBefore(notBefore)
                builder.setKeyValidityEnd(notAfter)
                builder.setCertificateNotAfter(notAfter)
            }
            try {
                kpg.initialize(builder.build())
            } catch (e: InvalidAlgorithmParameterException) {
                throw IllegalStateException(e)
            }
            kpg.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Error creating key", e)
        } catch (e: NoSuchProviderException) {
            throw IllegalStateException("Error creating key", e)
        }
        val attestationCerts = mutableListOf<X509Cert>()
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            ks.getCertificateChain(newKeyAlias).forEach { certificate ->
                attestationCerts.add(X509Cert(certificate.encoded))
            }
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }
        Logger.d(TAG, "EC key with alias '$alias' created")
        saveKeyMetadata(newKeyAlias, aSettings, X509CertChain(attestationCerts))
        return newKeyAlias
    }

    /**
     * Creates a key for an existing Android KeyStore key.
     *
     *
     * This doesn't actually create a key but creates the out-of-band data
     * structures so an existing Android KeyStore key can be used with e.g.
     * [.getKeyInfo],
     * [.sign],
     * [.keyAgreement]
     * and other methods.
     *
     * @param existingAlias the alias of the existing key.
     */
    suspend fun createKeyForExistingAlias(existingAlias: String) {
        // If the key with the given alias exists, it is silently overwritten.
        // TODO: review if this is the semantics we want
        storageTable.delete(existingAlias)
        storageTable.insert(existingAlias, ByteString())

        val ks = KeyStore.getInstance("AndroidKeyStore")
        // TODO: move to an IO thread
        ks.load(null)
        val entry = ks.getEntry(existingAlias, null)
            ?: throw IllegalArgumentException("A key with this alias doesn't exist")

        var keyInfo: android.security.keystore.KeyInfo = try {
            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            try {
                factory.getKeySpec(privateKey, android.security.keystore.KeyInfo::class.java)
            } catch (e: InvalidKeySpecException) {
                throw IllegalStateException("Given key is not an Android Keystore key", e)
            }
        } catch (e: UnrecoverableEntryException) {
            throw IllegalStateException(e.message, e)
        } catch (e: CertificateException) {
            throw IllegalStateException(e.message, e)
        } catch (e: KeyStoreException) {
            throw IllegalStateException(e.message, e)
        } catch (e: IOException) {
            throw IllegalStateException(e.message, e)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException(e.message, e)
        } catch (e: NoSuchProviderException) {
            throw IllegalStateException(e.message, e)
        }

        // Need to generate the data which getKeyInfo() reads from disk.
        val settingsBuilder =
            AndroidKeystoreCreateKeySettings.Builder("".toByteArray(StandardCharsets.UTF_8))

        // attestation
        val attestationCerts = mutableListOf<X509Cert>()
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            ks.getCertificateChain(existingAlias).forEach { certificate ->
                attestationCerts.add(X509Cert(certificate.encoded))
            }
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        // curve - not available in KeyInfo, assume P-256

        // keyPurposes
        val purposes: MutableSet<KeyPurpose> = LinkedHashSet()
        val ksPurposes = keyInfo.purposes
        if (ksPurposes and KeyProperties.PURPOSE_SIGN != 0) {
            purposes.add(KeyPurpose.SIGN)
        }
        if (ksPurposes and KeyProperties.PURPOSE_AGREE_KEY != 0) {
            purposes.add(KeyPurpose.AGREE_KEY)
        }
        settingsBuilder.setKeyPurposes(purposes)

        // useStrongBox
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            settingsBuilder.setUseStrongBox(keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX)
        }

        // attestKeyAlias - not available in KeyInfo

        // userAuthentication*
        var userAuthenticationTypes = mutableSetOf<UserAuthenticationType>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val ksAuthType = keyInfo.userAuthenticationType
            if (ksAuthType and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0) {
                userAuthenticationTypes.add(UserAuthenticationType.LSKF)
            }
            if (ksAuthType and KeyProperties.AUTH_BIOMETRIC_STRONG != 0) {
                userAuthenticationTypes.add(UserAuthenticationType.BIOMETRIC)
            }
        } else {
            userAuthenticationTypes.add(UserAuthenticationType.LSKF)
            userAuthenticationTypes.add(UserAuthenticationType.BIOMETRIC)
        }
        settingsBuilder.setUserAuthenticationRequired(
            keyInfo.isUserAuthenticationRequired,
            keyInfo.userAuthenticationValidityDurationSeconds * 1000L,
            userAuthenticationTypes
        )
        saveKeyMetadata(existingAlias, settingsBuilder.build(), X509CertChain(attestationCerts))
        Logger.d(TAG, "EC existing key with alias '$existingAlias' created")
    }

    override suspend fun deleteKey(alias: String) {
        val ks: KeyStore
        var entry: KeyStore.Entry
        try {
            ks = KeyStore.getInstance("AndroidKeyStore")
            // TODO: move to an IO thread
            ks.load(null)
            if (!ks.containsAlias(alias)) {
                Logger.w(TAG, "Key with alias '$alias' doesn't exist")
                return
            }
            ks.deleteEntry(alias)
            storageTable.delete(alias)
        } catch (e: CertificateException) {
            throw IllegalStateException("Error loading keystore", e)
        } catch (e: IOException) {
            throw IllegalStateException("Error loading keystore", e)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Error loading keystore", e)
        } catch (e: KeyStoreException) {
            throw IllegalStateException("Error loading keystore", e)
        }
        Logger.d(TAG, "EC key with alias '$alias' deleted")
    }

    override suspend fun sign(
        alias: String,
        signatureAlgorithm: Algorithm,
        dataToSign: ByteArray,
        keyUnlockData: com.android.identity.securearea.KeyUnlockData?
    ): EcSignature {
        val (entry, data) = loadKey(alias)
        val decodedData = Cbor.decode(data)
        val curve = EcCurve.fromInt(decodedData["curve"].asNumber.toInt())

        if (keyUnlockData != null) {
            val unlockData = keyUnlockData as AndroidKeystoreKeyUnlockData
            require(unlockData.alias == alias) {
                "keyUnlockData has alias ${unlockData.alias} which differs from passed-in alias $alias"
            }
            if (unlockData.signature != null) {
                require(unlockData.signatureAlgorithm === signatureAlgorithm) {
                    "keyUnlockData has signature algorithm ${unlockData.signatureAlgorithm} " +
                    "which differs from passed-in algorithm $signatureAlgorithm"
                }
                return try {
                    unlockData.signature!!.update(dataToSign)
                    val derEncodedSignature = unlockData.signature!!.sign()
                    signatureFromDer(curve, derEncodedSignature)
                } catch (e: SignatureException) {
                    throw IllegalStateException(e.message, e)
                }
            }
        }

        return try {
            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
            val s = Signature.getInstance(getSignatureAlgorithmName(signatureAlgorithm))
            s.initSign(privateKey)
            s.update(dataToSign)
            val derEncodedSignature = s.sign()
            signatureFromDer(curve, derEncodedSignature)
        } catch (e: UserNotAuthenticatedException) {
            throw KeyLockedException("User not authenticated", e)
        } catch (e: SignatureException) {
            // This is a work-around for Android Keystore throwing a SignatureException
            // when it should be throwing UserNotAuthenticatedException instead. b/282174161
            //
            if (e.message!!.startsWith("android.security.KeyStoreException: Key user not authenticated")
            ) {
                throw KeyLockedException("User not authenticated", e)
            }
            throw IllegalStateException(e.message, e)
        } catch (e: Exception) {
            throw IllegalArgumentException(e)
        }
    }

    @Throws(KeyLockedException::class)
    override suspend fun keyAgreement(
        alias: String,
        otherKey: EcPublicKey,
        keyUnlockData: com.android.identity.securearea.KeyUnlockData?
    ): ByteArray {
        val (entry, _) = loadKey(alias)
        return try {
            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
            val ka = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
            ka.init(privateKey)
            ka.doPhase(otherKey.javaPublicKey, true)
            ka.generateSecret()
        } catch (e: UserNotAuthenticatedException) {
            throw KeyLockedException("User not authenticated", e)
        } catch (e: ProviderException) {
            // This is a work-around for Android Keystore throwing a ProviderException
            // when it should be throwing UserNotAuthenticatedException instead. b/282174161
            //
            if (e.cause != null
                && e.cause!!.message!!.startsWith("Key user not authenticated")
            ) {
                throw KeyLockedException("User not authenticated", e)
            }
            throw IllegalArgumentException(e)
        } catch (e: Exception) {
            throw IllegalArgumentException(e)
        }
    }

    // @throws IllegalArgumentException if the key doesn't exist.
    // @throws KeyInvalidatedException if LSKF was removed and the key is no longer available.
    private suspend fun loadKey(alias: String): Pair<KeyStore.Entry, ByteArray> {
        val data = storageTable.get(alias)
            ?: throw IllegalArgumentException("No key with given alias")

        val ks = KeyStore.getInstance("AndroidKeyStore")
        // TODO: move to an IO thread
        ks.load(null)
        // If the LSKF is removed, all auth-bound keys are removed and the result is
        // that KeyStore.getEntry() returns null.
        val entry = ks.getEntry(alias, null)
            ?: throw KeyInvalidatedException("This key is no longer available")

        return Pair(entry, data.toByteArray())
    }

    override suspend fun getKeyInvalidated(alias: String): Boolean {
        try {
            loadKey(alias)
        } catch (e: KeyInvalidatedException) {
            return true
        }
        return false
    }

    override suspend fun getKeyInfo(alias: String): AndroidKeystoreKeyInfo {
        val (entry, data) = loadKey(alias)
        return try {
            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo =
                factory.getKeySpec(privateKey, android.security.keystore.KeyInfo::class.java)
            val map = Cbor.decode(data)
            val keyPurposes = map["keyPurposes"].asNumber.keyPurposeSet
            val userAuthenticationRequired = map["userAuthenticationRequired"].asBoolean
            val userAuthenticationTimeoutMillis = map["userAuthenticationTimeoutMillis"].asNumber
            val isStrongBoxBacked = map["useStrongBox"].asBoolean
            val attestKeyAlias = map.getOrNull("attestKeyAlias")?.asTstr
            var validFrom: Instant? = null
            var validUntil: Instant? = null
            if (keyInfo.keyValidityStart != null) {
                validFrom = Instant.fromEpochMilliseconds(
                    keyInfo.keyValidityStart!!.time
                )
            }
            if (keyInfo.keyValidityForOriginationEnd != null) {
                validUntil = Instant.fromEpochMilliseconds(
                    keyInfo.keyValidityForOriginationEnd!!.time
                )
            }
            val attestationCertChain = map["attestation"].asX509CertChain
            val publicKey = attestationCertChain.certificates.first().ecPublicKey

            val userAuthenticationTypes = mutableSetOf<UserAuthenticationType>()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val type = keyInfo.userAuthenticationType
                if (type and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0) {
                    userAuthenticationTypes.add(UserAuthenticationType.LSKF)
                }
                if (type and KeyProperties.AUTH_BIOMETRIC_STRONG != 0) {
                    userAuthenticationTypes.add(UserAuthenticationType.BIOMETRIC)
                }
            } else {
                userAuthenticationTypes.add(UserAuthenticationType.LSKF)
                userAuthenticationTypes.add(UserAuthenticationType.BIOMETRIC)
            }
            AndroidKeystoreKeyInfo(
                publicKey,
                KeyAttestation(publicKey, attestationCertChain),
                keyPurposes,
                attestKeyAlias,
                userAuthenticationRequired,
                userAuthenticationTimeoutMillis,
                userAuthenticationTypes,
                isStrongBoxBacked,
                validFrom,
                validUntil
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }
    }

    private suspend fun saveKeyMetadata(
        alias: String,
        settings: AndroidKeystoreCreateKeySettings,
        attestation: X509CertChain
    ) {
        val map = CborMap.builder()
        map.put("keyPurposes", KeyPurpose.encodeSet(settings.keyPurposes))
        if (settings.attestKeyAlias != null) {
            map.put("attestKeyAlias", settings.attestKeyAlias)
        }
        map.put("userAuthenticationRequired", settings.userAuthenticationRequired)
        map.put("userAuthenticationTimeoutMillis", settings.userAuthenticationTimeoutMillis)
        map.put("useStrongBox", settings.useStrongBox)
        map.put("attestation", attestation.toDataItem())
        map.put("curve", settings.ecCurve.coseCurveIdentifier)
        storageTable.update(alias, ByteString(Cbor.encode(map.end().build())))
    }

    /**
     * Helper class to determine capabilities of the device.
     *
     * This class can be used by applications to determine the extent of
     * Android Keystore support on the device the application is running on.
     *
     * Once constructed, the application may query this object to determine
     * which Android Keystore features are available.
     *
     * In general this is implemented by examining
     * [FEATURE_HARDWARE_KEYSTORE](https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_HARDWARE_KEYSTORE) and
     * [FEATURE_STRONGBOX_KEYSTORE](https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_STRONGBOX_KEYSTORE) to determine the KeyMint version for both
     * the normal hardware-backed keystore and - if available - the StrongBox-backed keystore.
     *
     * @param context the application context.
     */
    class Capabilities(context: Context) {
        private val keyguardManager: KeyguardManager
        private val apiLevel: Int
        private val teeFeatureLevel: Int
        private val sbFeatureLevel: Int

        init {
            keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            teeFeatureLevel = getFeatureVersionKeystore(context, false)
            sbFeatureLevel = getFeatureVersionKeystore(context, true)
            apiLevel = Build.VERSION.SDK_INT
        }

        val secureLockScreenSetup: Boolean
            /**
             * Whether a Secure Lock Screen has been set up.
             *
             * This checks whether the device currently has a secure lock
             * screen (either PIN, pattern, or password).
             */
            get() = keyguardManager.isDeviceSecure

        /**
         * Whether it's possible to specify multiple authentication types.
         *
         * On Android versions before API 30 (Android 11), it's not possible to specify whether
         * LSKF or Biometric or both can be used to unlock a key (both are always possible).
         * Starting with Android 11, it's possible to specify all three combinations (LSKF only,
         * Biometric only, or both).
         */
        val multipleAuthenticationTypesSupported: Boolean
            get() = apiLevel >= Build.VERSION_CODES.R

        /**
         * Whether Attest Keys are supported.
         *
         * This is only supported in KeyMint 1.0 (version 100) and higher.
         */
        val attestKeySupported: Boolean
            get() = teeFeatureLevel >= 100

        /**
         * Whether Key Agreement is supported.
         *
         * This is only supported in KeyMint 1.0 (version 100) and higher.
         */
        val keyAgreementSupported: Boolean
            get() = teeFeatureLevel >= 100

        /**
         * Whether Curve25519 is supported.
         *
         * This is only supported in KeyMint 2.0 (version 200) and higher.
         */
        val curve25519Supported: Boolean
            get() = teeFeatureLevel >= 200

        /**
         * Whether StrongBox is supported.
         *
         * StrongBox requires dedicated hardware and is not available on all devices.
         */
        val strongBoxSupported: Boolean
            get() = sbFeatureLevel > 0

        /**
         * Whether StrongBox Attest Keys are supported.
         *
         * This is only supported in StrongBox KeyMint 1.0 (version 100) and higher.
         */
        val strongBoxAttestKeySupported: Boolean
            get() = sbFeatureLevel >= 100

        /**
         * Whether StrongBox Key Agreement is supported.
         *
         * This is only supported in StrongBox KeyMint 1.0 (version 100) and higher.
         */
        val strongBoxKeyAgreementSupported: Boolean
            get() = sbFeatureLevel >= 100

        /**
         * Whether StrongBox Curve25519 is supported.
         *
         * This is only supported in StrongBox KeyMint 2.0 (version 200) and higher.
         */
        val strongBoxCurve25519Supported: Boolean
            get() = sbFeatureLevel >= 200
    }

    companion object {
        /**
         * The Secure Area identifier for the Android Keystore Secure Area.
         */
        private const val TAG = "AndroidKeystoreSA" // limit to <= 23 chars

        const val IDENTIFIER = "AndroidKeystoreSecureArea"

        /**
         * Creates an instance of AndroidKeystoreSecureArea.
         *
         * @param storage the storage engine to use for storing key material.
         */
        suspend fun create(context: Context, storage: Storage): AndroidKeystoreSecureArea {
            return AndroidKeystoreSecureArea(context, storage.getTable(tableSpec))
        }

        private val tableSpec = StorageTableSpec(
            name = "AndroidKeystoreSecureArea",
            supportPartitions = false,
            supportExpiration = false
        )

        internal fun getSignatureAlgorithmName(signatureAlgorithm: Algorithm): String {
            return when (signatureAlgorithm) {
                Algorithm.ES256 -> "SHA256withECDSA"
                Algorithm.ES384 -> "SHA384withECDSA"
                Algorithm.ES512 -> "SHA512withECDSA"
                Algorithm.EDDSA -> "Ed25519"
                else -> throw IllegalArgumentException(
                    "Unsupported signing algorithm with id $signatureAlgorithm"
                )
            }
        }

        private fun stripLeadingZeroes(array: ByteArray): ByteArray {
            val idx = array.indexOfFirst { it != 0.toByte() }
            if (idx == -1)
                return array
            return array.copyOfRange(idx, array.size)
        }

        internal fun signatureFromDer(curve: EcCurve, derEncodedSignature: ByteArray): EcSignature {
            val asn1 = try {
                ASN1InputStream(ByteArrayInputStream(derEncodedSignature)).readObject()
            } catch (e: IOException) {
                throw IllegalArgumentException("Error decoding DER signature", e)
            }
            val asn1Encodables = (asn1 as ASN1Sequence).toArray()
            require(asn1Encodables.size == 2) { "Expected two items in sequence" }
            val r = stripLeadingZeroes(((asn1Encodables[0].toASN1Primitive() as ASN1Integer).value).toByteArray())
            val s = stripLeadingZeroes(((asn1Encodables[1].toASN1Primitive() as ASN1Integer).value).toByteArray())

            val keySize = (curve.bitSize + 7)/8
            check(r.size <= keySize)
            check(s.size <= keySize)

            val rPadded = ByteArray(keySize)
            val sPadded = ByteArray(keySize)
            r.copyInto(rPadded, keySize - r.size)
            s.copyInto(sPadded, keySize - s.size)

            check(rPadded.size == keySize)
            check(sPadded.size == keySize)

            return EcSignature(rPadded, sPadded)
        }



        private fun getFeatureVersionKeystore(appContext: Context, useStrongbox: Boolean): Int {
            var feature = PackageManager.FEATURE_HARDWARE_KEYSTORE
            if (useStrongbox) {
                feature = PackageManager.FEATURE_STRONGBOX_KEYSTORE
            }
            val pm = appContext.packageManager
            if (pm.hasSystemFeature(feature)) {
                var info: FeatureInfo? = null
                val infos = pm.systemAvailableFeatures
                for (n in infos.indices) {
                    val i = infos[n]
                    if (i.name == feature) {
                        info = i
                        break
                    }
                }
                var version = 0
                if (info != null) {
                    version = info.version
                }
                // It's entirely possible that the feature exists but the version number hasn't
                // been set. In that case, assume it's at least KeyMaster 4.1.
                if (version < 41) {
                    version = 41
                }
                return version
            }
            // It's only a requirement to set PackageManager.FEATURE_HARDWARE_KEYSTORE since
            // Android 12 so for old devices this isn't set. However all devices since Android
            // 8.1 has had HW-backed keystore so in this case we can report KeyMaster 4.1
            return if (!useStrongbox) {
                41
            } else 0
        }
    }
}
