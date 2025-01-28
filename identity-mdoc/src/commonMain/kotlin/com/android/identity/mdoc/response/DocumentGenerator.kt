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
package com.android.identity.mdoc.response

import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.RawCbor
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.toDataItem
import com.android.identity.cose.Cose
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.document.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcPublicKey
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.SecureArea

/**
 * Helper class for building `Document` [CBOR](http://cbor.io/)
 * as specified in ISO/IEC 18013-5:2021 section 8.3.
 *
 * @param docType the document type.
 * @param encodedIssuerAuth bytes of `IssuerAuth` CBOR, as per ISO/IEC 18013-5:2021 section 9.1.2.4.
 * @param encodedSessionTranscript bytes of `SessionTranscript` CBOR as per ISO/IEC 18013-5:2021
 * section 9.1.5.1.
 */
class DocumentGenerator
    (
    private val docType: String,
    private val encodedIssuerAuth: ByteArray,
    private val encodedSessionTranscript: ByteArray
) {
    private var errors: Map<String, Map<String, Long>>? = null
    private var issuerNamespaces: Map<String, List<ByteArray>>? = null
    private var deviceSigned: DataItem? = null

    /**
     * Sets document errors.
     *
     * The `errors` parameter is a map from namespaces where each value is a map from
     * data elements in said namespace to an error code from ISO/IEC 18013-5:2021 Table 9.
     *
     * @param errors the map described above.
     * @return the generator.
     */
    fun setErrors(errors: Map<String, Map<String, Long>>): DocumentGenerator = apply {
        this.errors = errors
    }

    /**
     * Sets issuer-signed data elements to return.
     *
     * Since a document response may not contain issuer signed data elements, this is
     * optional to call.
     *
     * @param issuerNameSpaces a map from name spaces into a list of `IssuerSignedItemBytes`.
     * @return the generator.
     */
    fun setIssuerNamespaces(issuerNameSpaces: Map<String, List<ByteArray>>?) = apply {
        issuerNamespaces = issuerNameSpaces
    }

    private suspend fun setDeviceNamespaces(
        dataElements: NameSpacedData,
        secureArea: SecureArea,
        keyAlias: String,
        keyUnlockData: KeyUnlockData?,
        signatureAlgorithm: Algorithm,
        eReaderKey: EcPublicKey?
    ) = apply {
        val mapBuilder = CborMap.builder()
        for (nameSpaceName in dataElements.nameSpaceNames) {
            val nsBuilder = mapBuilder.putMap(nameSpaceName)
            for (dataElementName in dataElements.getDataElementNames(nameSpaceName)) {
                nsBuilder.put(
                    dataElementName,
                    RawCbor(dataElements.getDataElement(nameSpaceName, dataElementName))
                )
            }
        }
        mapBuilder.end()
        val encodedDeviceNameSpaces = Cbor.encode(mapBuilder.end().build())
        val deviceAuthentication = Cbor.encode(
            CborArray.builder()
                .add("DeviceAuthentication")
                .add(RawCbor(encodedSessionTranscript))
                .add(docType)
                .addTaggedEncodedCbor(encodedDeviceNameSpaces)
                .end()
                .build()
        )
        val deviceAuthenticationBytes = Cbor.encode(Tagged(24, Bstr(deviceAuthentication)))
        var encodedDeviceSignature: ByteArray? = null
        var encodedDeviceMac: ByteArray? = null
        if (signatureAlgorithm !== Algorithm.UNSET) {
            encodedDeviceSignature = Cbor.encode(
                Cose.coseSign1Sign(
                    secureArea,
                    keyAlias,
                    deviceAuthenticationBytes,
                    false,
                    signatureAlgorithm,
                    mapOf(
                        Pair(
                            CoseNumberLabel(Cose.COSE_LABEL_ALG),
                            signatureAlgorithm.coseAlgorithmIdentifier.toDataItem()
                        )
                    ),
                    mapOf(),
                    keyUnlockData
                ).toDataItem()
            )
        } else {
            val sharedSecret = secureArea.keyAgreement(
                keyAlias,
                eReaderKey!!,
                keyUnlockData
            )
            val sessionTranscriptBytes = Cbor.encode(Tagged(24, Bstr(encodedSessionTranscript)))
            val salt = Crypto.digest(Algorithm.SHA256, sessionTranscriptBytes)
            val info = "EMacKey".encodeToByteArray()
            val eMacKey = Crypto.hkdf(Algorithm.HMAC_SHA256, sharedSecret, salt, info, 32)
            encodedDeviceMac = Cbor.encode(
                Cose.coseMac0(
                    Algorithm.HMAC_SHA256,
                    eMacKey,
                    deviceAuthenticationBytes,
                    false,
                    mapOf(
                        Pair(
                            CoseNumberLabel(Cose.COSE_LABEL_ALG),
                            Algorithm.HMAC_SHA256.coseAlgorithmIdentifier.toDataItem()
                        )
                    ),
                    mapOf()
                ).toDataItem()
            )
        }
        val deviceAuthType: String
        val deviceAuthDataItem: DataItem
        if (encodedDeviceSignature != null) {
            deviceAuthType = "deviceSignature"
            deviceAuthDataItem = Cbor.decode(encodedDeviceSignature)
        } else {
            deviceAuthType = "deviceMac"
            deviceAuthDataItem = Cbor.decode(encodedDeviceMac!!)
        }
        deviceSigned = CborMap.builder()
            .putTaggedEncodedCbor("nameSpaces", encodedDeviceNameSpaces)
            .putMap("deviceAuth")
            .put(deviceAuthType, deviceAuthDataItem)
            .end()
            .end()
            .build()
    }

    /**
     * Sets device-signed data elements to return.
     *
     * This variant produces an EC signature as per ISO/IEC 18013-5:2021 section 9.1.3.6
     * mdoc ECDSA / EdDSA Authentication.
     *
     * @param dataElements the data elements to return in `DeviceSigned`.
     * @param secureArea the [SecureArea] for the authentication key to sign with.
     * @param keyAlias the alias for the authentication key to sign with.
     * @param keyUnlockData unlock data for the authentication key, or `null`.
     * @param signatureAlgorithm the signature algorithm to use.
     * @return the generator.
     * @throws KeyLockedException if the authentication key is locked.
     */
    suspend fun setDeviceNamespacesSignature(
        dataElements: NameSpacedData,
        secureArea: SecureArea,
        keyAlias: String,
        keyUnlockData: KeyUnlockData?,
        signatureAlgorithm: Algorithm
    ) = apply {
        setDeviceNamespaces(
            dataElements,
            secureArea,
            keyAlias,
            keyUnlockData,
            signatureAlgorithm,
            null
        )
    }

    /**
     * Sets device-signed data elements to return.
     *
     * This variant produces a MAC as per ISO/IEC 18013-5:2021 section 9.1.3.5
     * mdoc MAC Authentication.
     *
     * @param dataElements the data elements to return in `DeviceSigned`.
     * @param secureArea the [SecureArea] for the authentication key to sign with.
     * @param keyAlias the alias for the authentication key to sign with.
     * @param keyUnlockData unlock data for the authentication key, or `null`.
     * @param eReaderKey the ephemeral public key used by the remote reader.
     * @return the generator.
     * @throws KeyLockedException if the authentication key is locked.
     */
    suspend fun setDeviceNamespacesMac(
        dataElements: NameSpacedData,
        secureArea: SecureArea,
        keyAlias: String,
        keyUnlockData: KeyUnlockData?,
        eReaderKey: EcPublicKey
    ) = apply {
        setDeviceNamespaces(
            dataElements,
            secureArea,
            keyAlias,
            keyUnlockData,
            Algorithm.UNSET,
            eReaderKey
        )
    }

    /**
     * Generates CBOR.
     *
     * This generates the bytes of the `Document` CBOR according to ISO/IEC 18013-5:2021
     * section 8.3.2.1.2.2.
     *
     * @return the bytes described above.
     * @throws IllegalStateException if one of [.setDeviceNamespacesSignature]
     * or [.setDeviceNamespacesMac] hasn't been called on the generator.
     */
    fun generate(): ByteArray {
        checkNotNull(deviceSigned) { "DeviceSigned isn't set" }
        val issuerSignedMapBuilder = CborMap.builder()
        if (issuerNamespaces != null) {
            val insOuter = CborMap.builder()
            for (ns in issuerNamespaces!!.keys) {
                val insInner = insOuter.putArray(ns)
                for (encodedIssuerSignedItemBytes in issuerNamespaces!![ns]!!) {
                    insInner.add(RawCbor(encodedIssuerSignedItemBytes))
                }
                insInner.end()
            }
            insOuter.end()
            issuerSignedMapBuilder.put("nameSpaces", insOuter.end().build())
        }
        issuerSignedMapBuilder.put("issuerAuth", RawCbor(encodedIssuerAuth))
        val issuerSigned = issuerSignedMapBuilder.end().build()
        val mapBuilder = CborMap.builder().apply {
            put("docType", docType)
            put("issuerSigned", issuerSigned)
            put("deviceSigned", deviceSigned!!)
        }
        errors?.let { errMap ->
            val errorsOuterMapBuilder = CborMap.builder()
            for ((namespaceName, innerMap) in errMap) {
                val errorsInnerMapBuilder = errorsOuterMapBuilder.putMap(namespaceName)
                for (dataElementName in innerMap.keys) {
                    val value = innerMap[dataElementName]!!
                    errorsInnerMapBuilder.put(dataElementName, value)
                }
            }
            mapBuilder.put("errors", errorsOuterMapBuilder.end().build())
        }
        return Cbor.encode(mapBuilder.end().build())
    }
}
