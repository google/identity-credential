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
package com.android.identity.credential

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborException
import co.nstant.`in`.cbor.builder.ArrayBuilder
import co.nstant.`in`.cbor.builder.MapBuilder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import com.android.identity.internal.Util
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.StorageEngine
import com.android.identity.util.ApplicationData
import com.android.identity.util.Logger
import com.android.identity.util.SimpleApplicationData
import com.android.identity.util.Timestamp
import java.io.ByteArrayInputStream

/**
 * This class represents a credential created in [CredentialStore].
 *
 * Credentials in this store are identified by a name which must be unique
 * per credential.
 *
 * Arbitrary data can be stored in credentials using the [ApplicationData] returned
 * by [.getApplicationData] which supports key/value pairs with typed values
 * including raw blobs, strings, booleans, numbers, and [NameSpacedData].
 * This data is persisted for the life-time of the credential.
 *
 * One typical use of [ApplicationData] is for using it to store the alias
 * of a [SecureArea] key used for communicating with the Issuing Authority
 * issuing data for the credential and and proving - via the attestation on the key - that
 * the device is in a known good state (e.g. verified boot is enabled, the OS is at a
 * sufficiently recent patch level, it's communicating with the expected Android
 * application, etc).
 *
 * Each credential may have a number of *Authentication Keys*
 * associated with it. These keys are intended to be used in ways specified by the
 * underlying credential format but the general idea is that they are created on
 * the device and then sent to the issuer for certification. The issuer then returns
 * some format-specific data related to the key. For Mobile Driving License and MDOCs according
 * to [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html)
 * the authentication key plays the role of *DeviceKey* and the issuer-signed
 * data includes the *Mobile Security Object* which includes the authentication
 * key and is signed by the issuer. This is used for anti-cloning and to return data signed
 * by the device. The way it works in this API is that the application can use
 * [.createPendingAuthenticationKey]
 * to get a [PendingAuthenticationKey]. With this in hand, the application can use
 * [PendingAuthenticationKey.attestation] and send the attestation
 * to the issuer for certification. The issuer will then craft credential-format
 * specific data (for ISO/IEC 18013-5:2021 it will be a signed MSO which references
 * the public part of the newly created authentication key) and send it back
 * to the app. The application can then call
 * [PendingAuthenticationKey.certify] to
 * upgrade the [PendingAuthenticationKey] to a [AuthenticationKey].
 *
 * At credential presentation time the application first receives the request
 * from a remote reader using a specific credential presentation protocol, such
 * as ISO/IEC 18013-5:2021. The details of the credential-specific request includes
 * enough information (for example, the *DocType* if using ISO/IEC 18013-5:2021)
 * for the application to locate a suitable [Credential] from a [CredentialStore].
 * See [CredentialRequest] for more information about how to generate the response for
 * the remote reader given a [Credential] instance.
 *
 * There is nothing mDL/MDOC specific about this type, it can be used for any kind
 * of credential regardless of format, presentation, or issuance protocol used.
 */
class Credential private constructor(
    val name: String,
    private val storageEngine: StorageEngine,
    internal val secureAreaRepository: SecureAreaRepository
) {
    private var privateApplicationData = SimpleApplicationData { saveCredential() }
    /**
     * Application specific data.
     *
     * Use this object to store additional data an application may want to associate
     * with the authentication key. Setters and associated getters are
     * enumerated in the [ApplicationData] interface.
     */
    val applicationData: ApplicationData
        get() = privateApplicationData

    private var privatePendingAuthenticationKeys: MutableList<PendingAuthenticationKey> = ArrayList()
    /**
     * Pending authentication keys.
     */
    val pendingAuthenticationKeys: List<PendingAuthenticationKey>
        // Return shallow copy b/c backing field may get modified if certify() or delete() is called.
        get() = ArrayList(privatePendingAuthenticationKeys)

    private var privateAuthenticationKeys: MutableList<AuthenticationKey> = ArrayList()

    /**
     * Certified authentication keys.
     */
    val authenticationKeys: List<AuthenticationKey>
        // Return shallow copy b/c backing field may get modified if certify() or delete() is called.
        get() = ArrayList(privateAuthenticationKeys)

    /**
     * Authentication key counter.
     *
     * This is a number which starts at 0 and is increased by one for every call
     * to [.createPendingAuthenticationKey].
     */
    var authenticationKeyCounter: Long = 0
        private set

    internal fun saveCredential() {
        val t0 = Timestamp.now()
        val builder = CborBuilder()
        val map: MapBuilder<CborBuilder> = builder.addMap()
        map.put("applicationData", privateApplicationData.encodeAsCbor())
        val pendingAuthenticationKeysArrayBuilder: ArrayBuilder<MapBuilder<CborBuilder>> =
            map.putArray("pendingAuthenticationKeys")
        for (pendingAuthenticationKey in privatePendingAuthenticationKeys) {
            pendingAuthenticationKeysArrayBuilder.add(pendingAuthenticationKey.toCbor())
        }
        val authenticationKeysArrayBuilder: ArrayBuilder<MapBuilder<CborBuilder>> =
            map.putArray("authenticationKeys")
        for (authenticationKey in privateAuthenticationKeys) {
            authenticationKeysArrayBuilder.add(authenticationKey.toCbor())
        }
        map.put("authenticationKeyCounter", authenticationKeyCounter)
        storageEngine.put(CREDENTIAL_PREFIX + name, Util.cborEncode(builder.build().get(0)))
        val t1 = Timestamp.now()

        // Saving a credential is a costly affair (often more than 100ms) so log when we're doing
        // this so application developers are aware. This is to deter applications from storing
        // ephemeral data in the ApplicationData instances of the credential and our associated
        // authentication keys.
        val durationMillis = t1.toEpochMilli() - t0.toEpochMilli()
        Logger.i(TAG, "Saved credential '$name' to disk in $durationMillis msec")
    }

    private fun loadCredential(): Boolean {
        val data = storageEngine[CREDENTIAL_PREFIX + name] ?: return false
        val bais = ByteArrayInputStream(data)
        val dataItems = try {
            CborDecoder(bais).decode()
        } catch (e: CborException) {
            throw IllegalStateException("Error decoding CBOR", e)
        }
        check(dataItems.size == 1) { "Expected 1 item, found " + dataItems.size }
        check(dataItems[0] is Map) { "Item is not a map" }

        val map = dataItems[0] as Map
        val applicationDataDataItem: DataItem = map[UnicodeString("applicationData")]
        check(applicationDataDataItem is ByteString) { "applicationData not found or not byte[]" }

        privateApplicationData = SimpleApplicationData.decodeFromCbor(
            applicationDataDataItem.bytes
        ) { saveCredential() }

        privatePendingAuthenticationKeys = ArrayList()
        val pendingAuthenticationKeysDataItem: DataItem =
            map[UnicodeString("pendingAuthenticationKeys")]
        check(pendingAuthenticationKeysDataItem is Array) { "pendingAuthenticationKeys not found or not array" }
        for (item in pendingAuthenticationKeysDataItem.dataItems) {
            privatePendingAuthenticationKeys.add(PendingAuthenticationKey.fromCbor(item, this))
        }
        privateAuthenticationKeys = ArrayList()
        val authenticationKeysDataItem: DataItem = map[UnicodeString("authenticationKeys")]
        check(authenticationKeysDataItem is Array) { "authenticationKeys not found or not array" }
        for (item in authenticationKeysDataItem.dataItems) {
            privateAuthenticationKeys.add(AuthenticationKey.fromCbor(item, this))
        }
        authenticationKeyCounter = Util.cborMapExtractNumber(map, "authenticationKeyCounter")
        return true
    }

    fun deleteCredential() {
        // Need to use shallow copies because delete() modifies the list.
        for (key in ArrayList(privatePendingAuthenticationKeys)) {
            key.delete()
        }
        for (key in ArrayList(privateAuthenticationKeys)) {
            key.delete()
        }
        storageEngine.delete(CREDENTIAL_PREFIX + name)
    }

    /**
     * Finds a suitable authentication key to use.
     *
     * @param domain The domain to pick the authentication key from.
     * @param now Pass current time to ensure that the selected slot's validity period or
     * `null` to not consider validity times.
     * @return An authentication key which can be used for signing or `null` if none was found.
     */
    fun findAuthenticationKey(
        domain: String,
        now: Timestamp?
    ): AuthenticationKey? {
        var candidate: AuthenticationKey? = null
        for (authenticationKey in privateAuthenticationKeys) {
            if (authenticationKey.domain != domain) {
                continue
            }
            // If current time is passed...
            if (now != null) {
                // ... ignore slots that aren't yet valid
                if (now.toEpochMilli() < authenticationKey.validFrom.toEpochMilli()) {
                    continue
                }
                // .. ignore slots that aren't valid anymore
                if (now.toEpochMilli() > authenticationKey.validUntil.toEpochMilli()) {
                    continue
                }
            }
            // If we already have a candidate, prefer this one if its usage count is lower
            if (candidate != null) {
                if (authenticationKey.usageCount < candidate.usageCount) {
                    candidate = authenticationKey
                }
            } else {
                candidate = authenticationKey
            }
        }
        return candidate
    }

    /**
     * Creates a new authentication key.
     *
     *
     * This returns a [PendingAuthenticationKey] which should be sent to the
     * credential issuer for certification. Use
     * [PendingAuthenticationKey.certify] when certification
     * has been obtained.
     *
     *
     * For a higher-level way of managing authentication keys, see
     * [CredentialUtil.managedAuthenticationKeyHelper].
     *
     * @param domain a string used to group authentications keys together.
     * @param secureArea the secure area to use for the authentication key.
     * @param createKeySettings settings for the authentication key.
     * @param asReplacementFor if not `null`, replace the given authentication key
     * with this one, once it has been certified.
     * @return a [PendingAuthenticationKey].
     * @throws IllegalArgumentException if `asReplacementFor` is not null and the given
     * key already has a pending key intending to replace it.
     */
    fun createPendingAuthenticationKey(
        domain: String,
        secureArea: SecureArea,
        createKeySettings: CreateKeySettings,
        asReplacementFor: AuthenticationKey?
    ): PendingAuthenticationKey {
        check(asReplacementFor?.replacement == null) {
            "The given key already has an existing pending key intending to replace it"
        }
        val alias =
            AUTHENTICATION_KEY_ALIAS_PREFIX + name + "_authKey_" + authenticationKeyCounter++
        val pendingAuthenticationKey = PendingAuthenticationKey.create(
            alias,
            domain,
            secureArea,
            createKeySettings,
            asReplacementFor,
            this
        )
        privatePendingAuthenticationKeys.add(pendingAuthenticationKey)
        asReplacementFor?.setReplacementAlias(pendingAuthenticationKey.alias)
        saveCredential()
        return pendingAuthenticationKey
    }

    fun removePendingAuthenticationKey(pendingAuthenticationKey: PendingAuthenticationKey) {
        check(privatePendingAuthenticationKeys.remove(pendingAuthenticationKey)) { "Error removing pending authentication key" }
        if (pendingAuthenticationKey.replacementForAlias != null) {
            for (authKey in privateAuthenticationKeys) {
                if (authKey.alias == pendingAuthenticationKey.replacementForAlias) {
                    authKey.replacementAlias = null
                    break
                }
            }
        }
        saveCredential()
    }

    fun removeAuthenticationKey(authenticationKey: AuthenticationKey) {
        check(privateAuthenticationKeys.remove(authenticationKey)) { "Error removing authentication key" }
        if (authenticationKey.replacementAlias != null) {
            for (pendingAuthKey in privatePendingAuthenticationKeys) {
                if (pendingAuthKey.alias == authenticationKey.replacementAlias) {
                    pendingAuthKey.replacementForAlias = null
                    break
                }
            }
        }
        saveCredential()
    }

    fun certifyPendingAuthenticationKey(
        pendingAuthenticationKey: PendingAuthenticationKey,
        issuerProvidedAuthenticationData: ByteArray,
        validFrom: Timestamp,
        validUntil: Timestamp
    ): AuthenticationKey {
        check(privatePendingAuthenticationKeys.remove(pendingAuthenticationKey)) { "Error removing pending authentication key" }
        val authenticationKey = AuthenticationKey.create(
            pendingAuthenticationKey,
            issuerProvidedAuthenticationData,
            validFrom,
            validUntil,
            this
        )
        privateAuthenticationKeys.add(authenticationKey)
        val authKeyToDelete = pendingAuthenticationKey.replacementFor
        authKeyToDelete?.delete()
        saveCredential()
        return authenticationKey
    }

    companion object {
        private const val TAG = "Credential"
        const val CREDENTIAL_PREFIX = "IC_Credential_"
        const val AUTHENTICATION_KEY_ALIAS_PREFIX = "IC_AuthenticationKey_"

        // Called by CredentialStore.createCredential().
        fun create(
            storageEngine: StorageEngine,
            secureAreaRepository: SecureAreaRepository,
            name: String
        ): Credential {
            val credential = Credential(name, storageEngine, secureAreaRepository)
            credential.saveCredential()
            return credential
        }

        // Called by CredentialStore.lookupCredential().
        fun lookup(
            storageEngine: StorageEngine,
            secureAreaRepository: SecureAreaRepository,
            name: String
        ): Credential? {
            val credential = Credential(name, storageEngine, secureAreaRepository)
            return if (!credential.loadCredential()) {
                null
            } else credential
        }
    }
}