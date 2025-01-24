package com.android.identity.cose

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcSignature
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.SecureArea

/**
 * COSE support routines.
 *
 * This package includes support for COSE as specified in
 * [RFC 9052](https://datatracker.ietf.org/doc/rfc9052/).
 */
object Cose {

    /**
     * The COSE Key common parameter for the key type (tstr / int).
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    const val COSE_KEY_KTY: Long = 1

    /**
     * The COSE Key common parameter for the key id (bstr).
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     */
    const val COSE_KEY_KID: Long = 2

    /**
     * The COSE Key type parameter for the EC curve (int / tstr).
     *
     * Values are from https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    const val COSE_KEY_PARAM_CRV: Long = -1

    /**
     * The COSE Key type parameter for the X coordinate (bstr).
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    const val COSE_KEY_PARAM_X: Long = -2

    /**
     * The COSE Key type parameter for the Y coordinate (bstr / bool).
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    const val COSE_KEY_PARAM_Y: Long = -3

    /**
     * The COSE Key type parameter for the private key (bstr).
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    const val COSE_KEY_PARAM_D: Long = -4

    /**
     * The COSE Key Type for OKP.
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-type
     */
    const val COSE_KEY_TYPE_OKP: Long = 1

    /**
     * The COSE Key Type for EC2.
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#key-type
     */
    const val COSE_KEY_TYPE_EC2: Long = 2

    /**
     * The COSE label for conveying an algorithm.
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
     */
    const val COSE_LABEL_ALG = 1L

    /**
     * The COSE label for conveying an X.509 certificate chain.
     *
     * Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
     */
    const val COSE_LABEL_X5CHAIN = 33L
    
    private fun coseBuildToBeSigned(
        encodedProtectedHeaders: ByteArray,
        dataToBeSigned: ByteArray,
    ): ByteArray {
        val arrayBuilder = CborArray.builder().apply {
            add("Signature1")
            add(encodedProtectedHeaders)

            // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
            // so external_aad is the empty bstr
            val emptyExternalAad = ByteArray(0)
            add(emptyExternalAad)

            // Next field is the payload, independently of how it's transported (RFC
            // 8152 section 4.4).
            add(dataToBeSigned)
            end()
        }

        return Cbor.encode(arrayBuilder.end().build())
    }

    /**
     * Checks a COSE_Sign1 signature.
     *
     * @param publicKey the public to check with.
     * @param detachedData detached data, if any.
     * @param signature the COSE_Sign1 object.
     * @param signatureAlgorithm the signature algorithm to use.
     * @throws IllegalArgumentException if not exactly one of `detachedData` and
     * `signature.payload` are non-`null`.
     * @return whether the signature is valid and was made with the private key corresponding to the
     * given public key.
     */
    fun coseSign1Check(
        publicKey: EcPublicKey,
        detachedData: ByteArray?,
        signature: CoseSign1,
        signatureAlgorithm: Algorithm
    ): Boolean {
        require(
            (detachedData != null && signature.payload == null) ||
                    (detachedData == null && signature.payload != null)
        )
        val encodedProtectedHeaders =
            if (signature.protectedHeaders.isNotEmpty()) {
                val phb = CborMap.builder()
                signature.protectedHeaders.forEach { (label, di) -> phb.put(label.toDataItem(), di) }
                Cbor.encode(phb.end().build())
            } else {
                byteArrayOf()
            }
        val toBeSigned = coseBuildToBeSigned(
            encodedProtectedHeaders = encodedProtectedHeaders,
            dataToBeSigned = detachedData ?: signature.payload!!
        )

        return Crypto.checkSignature(
            publicKey,
            toBeSigned,
            signatureAlgorithm,
            EcSignature.fromCoseEncoded(signature.signature))
    }

    /**
     * Creates a COSE_Sign1 signature.
     *
     * By default, no headers are added. Applications likely want to include [Cose.COSE_LABEL_ALG]
     * in the protected header and if certification is needed, [Cose.COSE_LABEL_X5CHAIN] in
     * either the unprotected or protected header.
     *
     * This function signs with a key in a Secure Area, for signing with a software-based
     * [EcPrivateKey], see the other function with the same name but taking a [EcPrivateKey]
     * instead.
     *
     * @param secureArea the [SecureArea] holding the private key.
     * @param alias the alias for the private key to use to sign with.
     * @param message the data to sign.
     * @param includeMessageInPayload whether to include the message in the COSE_Sign1 payload.
     * @param signatureAlgorithm the signature algorithm to use.
     * @param protectedHeaders the protected headers to include.
     * @param unprotectedHeaders the unprotected headers to include.
     * @param keyUnlockData a [KeyUnlockData] for unlocking the key in the [SecureArea].
     */
    suspend fun coseSign1Sign(
        secureArea: SecureArea,
        alias: String,
        message: ByteArray,
        includeMessageInPayload: Boolean,
        signatureAlgorithm: Algorithm,
        protectedHeaders: Map<CoseLabel, DataItem>,
        unprotectedHeaders: Map<CoseLabel, DataItem>,
        keyUnlockData: KeyUnlockData?
    ): CoseSign1 {
        val encodedProtectedHeaders = if (protectedHeaders.isNotEmpty()) {
            val phb = CborMap.builder()
            protectedHeaders.forEach { (label, di) -> phb.put(label.toDataItem(), di) }
            Cbor.encode(phb.end().build())
        } else {
            byteArrayOf()
        }
        val toBeSigned = coseBuildToBeSigned(encodedProtectedHeaders, message)
        val signature = secureArea.sign(alias, signatureAlgorithm, toBeSigned, keyUnlockData)

        return CoseSign1(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            signature = signature.toCoseEncoded(),
            payload = if (includeMessageInPayload) message else null
        )
    }

    /**
     * Creates a COSE_Sign1 signature.
     *
     * By default, no headers are added. Applications likely want to include [Cose.COSE_LABEL_ALG]
     * in the protected header and if certification is needed, [Cose.COSE_LABEL_X5CHAIN] in
     * either the unprotected or protected header.
     *
     * This function signs with a software-based [EcPrivateKey], for using a key in a
     * Secure Area see the other function with the same name but taking a [SecureArea]
     * and alias.
     *
     * @param key the private key to sign with.
     * @param message the data to sign.
     * @param includeMessageInPayload whether to include the message in the COSE_Sign1 payload.
     * @param signatureAlgorithm the signature algorithm to use.
     * @param protectedHeaders the protected headers to include.
     * @param unprotectedHeaders the unprotected headers to include.
     */
    fun coseSign1Sign(
        key: EcPrivateKey,
        dataToSign: ByteArray,
        includeDataInPayload: Boolean,
        signatureAlgorithm: Algorithm,
        protectedHeaders: Map<CoseLabel, DataItem>,
        unprotectedHeaders: Map<CoseLabel, DataItem>
    ): CoseSign1 {
        val encodedProtectedHeaders = if (protectedHeaders.size > 0) {
            val phb = CborMap.builder()
            protectedHeaders.forEach { (label, di) -> phb.put(label.toDataItem(), di) }
            Cbor.encode(phb.end().build())
        } else {
            byteArrayOf()
        }
        val toBeSigned = coseBuildToBeSigned(encodedProtectedHeaders, dataToSign)
        val signature = Crypto.sign(key, signatureAlgorithm, toBeSigned)

        return CoseSign1(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            signature = signature.toCoseEncoded(),
            payload = if (includeDataInPayload) dataToSign else null
        )
    }

    /**
     * Creates a COSE_Mac0 message authentication code.
     *
     * By default, no headers are added. Applications likely want to include [Cose.COSE_LABEL_ALG]
     * in the protected header.
     *
     * @param algorithm the algorithm to use, e.g. [Algorithm.HMAC_SHA256].
     * @param key the bytes of the symmetric key to use.
     * @param message the message.
     * @param includeMessageInPayload whether to include the message in the payload.
     * @param protectedHeaders the protected headers to include.
     * @param unprotectedHeaders the unprotected headers to include.
     */
    fun coseMac0(
        algorithm: Algorithm,
        key: ByteArray,
        message: ByteArray,
        includeMessageInPayload: Boolean,
        protectedHeaders: Map<CoseLabel, DataItem>,
        unprotectedHeaders: Map<CoseLabel, DataItem>,
    ): CoseMac0 {
        val encodedProtectedHeaders = if (protectedHeaders.size > 0) {
            val phb = CborMap.builder()
            protectedHeaders.forEach { (label, di) -> phb.put(label.toDataItem(), di) }
            Cbor.encode(phb.end().build())
        } else {
            byteArrayOf()
        }
        val toBeMACed = coseBuildToBeMACed(encodedProtectedHeaders, message)
        val mac = Crypto.mac(algorithm, key, toBeMACed)
        return CoseMac0(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            tag = mac,
            payload = if (includeMessageInPayload) message else null
        )
    }

    private fun coseBuildToBeMACed(
        encodedProtectedHeaders: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val arrayBuilder = CborArray.builder().apply {
            add("MAC0")
            add(encodedProtectedHeaders)
            // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
            // so external_aad is the empty bstr
            val emptyExternalAad = ByteArray(0)
            add(emptyExternalAad)
            add(data)
        }

        return Cbor.encode(arrayBuilder.end().build())
    }
}