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
package com.android.identity.securearea.software

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborMap
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcSignature
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.KeyPurpose.Companion.encodeSet
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.fromDataItem
import com.android.identity.securearea.keyPurposeSet
import com.android.identity.securearea.toDataItem
import com.android.identity.storage.StorageEngine
import kotlin.random.Random

/**
 * An implementation of [SecureArea] in software.
 *
 * This implementation supports all the curves and algorithms defined by [SecureArea]
 * and also supports passphrase-protected keys. Key material is stored using the
 * [StorageEngine] abstraction and passphrase-protected keys are encrypted using
 * [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
 * with 256-bit keys with the key derived from the passphrase using
 * [HKDF](https://en.wikipedia.org/wiki/HKDF).
 *
 * This is currently implemented using the
 * [Bouncy Castle](https://www.bouncycastle.org/) library but this implementation
 * detail may change in the future.
 *
 * @param storageEngine the storage engine to use for storing key material.
 */
class SoftwareSecureArea(private val storageEngine: StorageEngine) : SecureArea {
    override val identifier get() = "SoftwareSecureArea"

    override val displayName get() = "Software Secure Area"

    override fun createKey(
        alias: String,
        createKeySettings: com.android.identity.securearea.CreateKeySettings
    ) {
        val settings = if (createKeySettings is SoftwareCreateKeySettings) {
            createKeySettings
        } else {
            // Use default settings if user passed in a generic SecureArea.CreateKeySettings.
            SoftwareCreateKeySettings.Builder().build()
        }
        try {
            val privateKey = Crypto.createEcPrivateKey(settings.ecCurve)
            val mapBuilder = CborMap.builder().apply {
                put("curve", settings.ecCurve.coseCurveIdentifier.toLong())
                put("keyPurposes", encodeSet(settings.keyPurposes).toLong())
                put("passphraseRequired", settings.passphraseRequired)
            }

            if (!settings.passphraseRequired) {
                mapBuilder.put("privateKey", privateKey.toCoseKey().toDataItem())
            } else {
                val encodedPublicKey = Cbor.encode(privateKey.publicKey.toCoseKey().toDataItem())
                val secretKey = derivePrivateKeyEncryptionKey(
                    encodedPublicKey,
                    settings.passphrase!!
                )
                val cleartextPrivateKey = Cbor.encode(privateKey.toCoseKey().toDataItem())
                val iv = Random.Default.nextBytes(12)
                val encryptedPrivateKey = Crypto.encrypt(
                    Algorithm.A128GCM,
                    secretKey,
                    iv,
                    cleartextPrivateKey
                )
                mapBuilder.apply {
                    put("encodedPublicKey", encodedPublicKey)
                    put("encryptedPrivateKey", encryptedPrivateKey)
                    put("encryptedPrivateKeyIv", iv)
                }
            }
            mapBuilder.put("publicKey", privateKey.publicKey.toCoseKey().toDataItem())
            if (settings.passphraseConstraints != null) {
                mapBuilder.put("passphraseConstraints", settings.passphraseConstraints.toDataItem())
            }
            storageEngine.put(PREFIX + alias, Cbor.encode(mapBuilder.end().build()))
        } catch (e: Exception) {
            // such as NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, OperatorCreationException, IOException, NoSuchProviderException
            throw IllegalStateException("Unexpected exception", e)
        }
    }

    private fun derivePrivateKeyEncryptionKey(
        encodedPublicKey: ByteArray,
        passphrase: String
    ): ByteArray {
        val info = "ICPrivateKeyEncryption1".encodeToByteArray()
        return Crypto.hkdf(
            Algorithm.HMAC_SHA256,
            passphrase.encodeToByteArray(),
            encodedPublicKey,
            info,
            32
        )
    }

    override fun deleteKey(alias: String) = storageEngine.delete(PREFIX + alias)

    private data class KeyData(
        val keyPurposes: Set<KeyPurpose>,
        val privateKey: EcPrivateKey,
    )

    private fun loadKey(
        prefix: String,
        alias: String,
        keyUnlockData: KeyUnlockData?
    ): KeyData {
        var passphrase: String? = null
        if (keyUnlockData != null) {
            val unlockData = keyUnlockData as SoftwareKeyUnlockData
            passphrase = unlockData.passphrase
        }
        val data = storageEngine[prefix + alias]
            ?: throw IllegalArgumentException("No key with given alias")
        val map = Cbor.decode(data)
        val keyPurposes = map["keyPurposes"].asNumber.keyPurposeSet
        val passphraseRequired = map["passphraseRequired"].asBoolean
        val privateKeyCoseKey = if (passphraseRequired) {
            if (passphrase == null) {
                throw KeyLockedException("No passphrase provided")
            }
            val encodedPublicKey = map["encodedPublicKey"].asBstr
            val encryptedPrivateKey = map["encryptedPrivateKey"].asBstr
            val iv = map["encryptedPrivateKeyIv"].asBstr
            val secretKey = derivePrivateKeyEncryptionKey(encodedPublicKey, passphrase)
            val encodedPrivateKey = try {
                Crypto.decrypt(Algorithm.A128GCM, secretKey, iv, encryptedPrivateKey)
            } catch (e: Exception) {
                throw KeyLockedException("Error decrypting private key - wrong passphrase?", e)
            }
            Cbor.decode(encodedPrivateKey).asCoseKey
        } else {
            map["privateKey"].asCoseKey
        }
        return KeyData(keyPurposes, privateKeyCoseKey.ecPrivateKey)
    }

    /**
     * Gets the underlying private key.
     *
     * @param alias the alias for the key.
     * @param keyUnlockData unlock data, or `null`.
     * @return a [PrivateKey].
     * @throws KeyLockedException
     */
    fun getPrivateKey(
        alias: String,
        keyUnlockData: KeyUnlockData?
    ): EcPrivateKey = loadKey(PREFIX, alias, keyUnlockData).privateKey

    override fun sign(
        alias: String,
        signatureAlgorithm: Algorithm,
        dataToSign: ByteArray,
        keyUnlockData: KeyUnlockData?
    ): EcSignature = loadKey(PREFIX, alias, keyUnlockData).run {
        require(keyPurposes.contains(KeyPurpose.SIGN)) { "Key does not have purpose SIGN" }
        Crypto.sign(privateKey, signatureAlgorithm, dataToSign)
    }

    override fun keyAgreement(
        alias: String,
        otherKey: EcPublicKey,
        keyUnlockData: KeyUnlockData?
    ): ByteArray = loadKey(PREFIX, alias, keyUnlockData).run {
        require(keyPurposes.contains(KeyPurpose.AGREE_KEY)) { "Key does not have purpose AGREE_KEY" }
        Crypto.keyAgreement(privateKey, otherKey)
    }

    override fun getKeyInfo(alias: String): SoftwareKeyInfo {
        val data = storageEngine[PREFIX + alias]
            ?: throw IllegalArgumentException("No key with given alias")
        val map = Cbor.decode(data)
        val keyPurposes = map["keyPurposes"].asNumber.keyPurposeSet
        val passphraseRequired = map["passphraseRequired"].asBoolean
        val publicKey = map["publicKey"].asCoseKey.ecPublicKey
        val passphraseConstraints = map.getOrNull("passphraseConstraints")?.let {
            PassphraseConstraints.fromDataItem(it)
        }
        return SoftwareKeyInfo(
            publicKey,
            KeyAttestation(publicKey, null),
            keyPurposes,
            passphraseRequired,
            passphraseConstraints
        )
    }

    override fun getKeyInvalidated(alias: String): Boolean {
        // Software keys are never invalidated.
        return false
    }

    companion object {
        private const val TAG = "SoftwareSecureArea"

        // Prefix for storage items.
        private const val PREFIX = "IC_SoftwareSecureArea_key_"
    }
}
