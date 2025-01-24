/*
 * Copyright 2019 The Android Open Source Project
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

package com.android.identity.android.legacy

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.CborException
import co.nstant.`in`.cbor.builder.ArrayBuilder
import co.nstant.`in`.cbor.builder.MapBuilder
import co.nstant.`in`.cbor.model.AbstractFloat
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.DoublePrecisionFloat
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.Number
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.Special
import co.nstant.`in`.cbor.model.SpecialType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.android.identity.crypto.EcCurve
import com.android.identity.util.Logger.w
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequenceGenerator
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey
import org.bouncycastle.jcajce.spec.XDHParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.BigIntegers
import java.lang.StringBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.AlgorithmParameters
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec


/**
 * Utility functions.
 */
object Util {

    private const val TAG = "Util"
    private const val COSE_LABEL_ALG: Long = 1
    private const val COSE_LABEL_X5CHAIN: Long = 33 // temporary identifier

    // From RFC 8152: Table 5: ECDSA Algorithm Values
    private const val COSE_ALG_ECDSA_256: Long = -7
    private const val COSE_ALG_ECDSA_384: Long = -35
    private const val COSE_ALG_ECDSA_512: Long = -36
    private const val COSE_ALG_HMAC_256_256: Long = 5
    private const val CBOR_SEMANTIC_TAG_ENCODED_CBOR: Long = 24
    private const val COSE_KEY_KTY: Long = 1
    private const val COSE_KEY_TYPE_OKP: Long = 1
    private const val COSE_KEY_TYPE_EC2: Long = 2
    private const val COSE_KEY_PARAM_CRV: Long = -1
    private const val COSE_KEY_PARAM_X: Long = -2
    private const val COSE_KEY_PARAM_Y: Long = -3
    private const val COSE_KEY_PARAM_CRV_P256: Long = 1

    /* TODO: add cborBuildDate() which generates a full-date where
     *
     *  full-date = #6.1004(tstr),
     *
     * and where tag 1004 is specified in RFC 8943.
     */
    @JvmStatic
    fun fromHex(stringWithHex: String): ByteArray {
        val stringLength = stringWithHex.length
        require(stringLength % 2 == 0) { "Invalid length of hex string: $stringLength" }
        val numBytes = stringLength / 2
        val data = ByteArray(numBytes)
        for (n in 0 until numBytes) {
            val byteStr = stringWithHex.substring(2 * n, 2 * n + 2)
            data[n] = byteStr.toInt(16).toByte()
        }
        return data
    }

    @JvmStatic
    fun toHex(bytes: ByteArray): String = toHex(bytes, 0, bytes.size)

    @JvmStatic
    fun toHex(bytes: ByteArray, from: Int, to: Int): String {
        require(from >= 0 && to <= bytes.size && from <= to)
        val sb = StringBuilder()
        for (n in from until to) {
            val b = bytes[n]
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    @JvmStatic
    fun base16(bytes: ByteArray): String =
        toHex(bytes).uppercase()

    @JvmStatic
    fun cborEncode(dataItem: DataItem): ByteArray {
        val baos = ByteArrayOutputStream()
        try {
            CborEncoder(baos).nonCanonical().encode(dataItem)
        } catch (e: CborException) {
            // This should never happen and we don't want cborEncode() to throw since that
            // would complicate all callers. Log it instead.
            throw IllegalStateException("Unexpected failure encoding data", e)
        }
        return baos.toByteArray()
    }

    @JvmStatic
    fun cborEncodeBoolean(value: Boolean): ByteArray =
        cborEncode(CborBuilder().add(value).build().first())

    @JvmStatic
    fun cborEncodeString(value: String): ByteArray =
        cborEncode(CborBuilder().add(value).build().first())

    @JvmStatic
    fun cborEncodeNumber(value: Long): ByteArray =
        cborEncode(CborBuilder().add(value).build().first())

    @JvmStatic
    fun cborEncodeBytestring(value: ByteArray): ByteArray =
        cborEncode(CborBuilder().add(value).build().first())

    @JvmStatic
    fun cborEncodeDateTime(timestamp: Timestamp): ByteArray =
        cborEncode(cborBuildDateTime(timestamp))

    /**
     * Returns #6.0(tstr) where tstr is the ISO 8601 encoding of the given point in time.
     * Only supports UTC times.
     */
    @JvmStatic
    fun cborBuildDateTime(timestamp: Timestamp): DataItem {
        val df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US)
        df.timeZone = TimeZone.getTimeZone("UTC")
        val dateString = df.format(Date(timestamp.toEpochMilli()))
        val dataItem: DataItem = UnicodeString(dateString)
        dataItem.setTag(0)
        return dataItem
    }

    @JvmStatic
    fun cborDecode(encodedBytes: ByteArray): DataItem {
        val bais = ByteArrayInputStream(encodedBytes)
        val dataItems = try {
            CborDecoder(bais).decode()
        } catch (e: CborException) {
            throw IllegalArgumentException("Error decoding CBOR", e)
        }
        require(dataItems.size == 1) {
            "Unexpected number of items, expected 1 got ${dataItems.size}"
        }
        return dataItems.first()
    }

    @JvmStatic
    fun cborDecodeBoolean(data: ByteArray): Boolean {
        val simple: SimpleValue = try {
            cborDecode(data) as SimpleValue
        } catch (e: ClassCastException) {
            throw IllegalArgumentException("Data given cannot be cast into a boolean.", e)
        }
        return simple.simpleValueType == SimpleValueType.TRUE
    }

    /**
     * Accepts a `DataItem`, attempts to cast it to a `Number`, then returns the value
     * Throws `IllegalArgumentException` if the `DataItem` is not a `Number`. This
     * method also checks bounds, and if the given data item is too large to fit in a long, it
     * throws `ArithmeticException`.
     */
    @JvmStatic
    fun checkedLongValue(item: DataItem): Long {
        val bigNum = item.castToNumber().value
        val result = bigNum.toLong()
        if (bigNum != BigInteger.valueOf(result)) {
            throw ArithmeticException("Expected long value, got '$bigNum'")
        }
        return result
    }

    @JvmStatic
    fun cborDecodeString(data: ByteArray): String =
        checkedStringValue(cborDecode(data))

    /**
     * Accepts a `DataItem`, attempts to cast it to a `UnicodeString`, then returns the
     * value. Throws `IllegalArgumentException` if the `DataItem` is not a
     * `UnicodeString`.
     */
    @JvmStatic
    fun checkedStringValue(item: DataItem): String = item.castToUnicodeString().string

    @JvmStatic
    fun cborDecodeLong(data: ByteArray): Long =
        checkedLongValue(cborDecode(data))

    @JvmStatic
    fun cborDecodeByteString(data: ByteArray): ByteArray =
        cborDecode(data).castToByteString().bytes

    @JvmStatic
    fun cborDecodeDateTime(data: ByteArray): Timestamp =
        cborDecodeDateTime(cborDecode(data))

    @JvmStatic
    fun cborDecodeDateTime(di: DataItem): Timestamp {
        require(di is UnicodeString) { "Passed in data is not a Unicode-string" }
        require(!(!di.hasTag() || di.tag.value != 0L)) { "Passed in data is not tagged with tag 0" }
        val dateString = checkedStringValue(di)

        // Manually parse the timezone
        var parsedTz = TimeZone.getTimeZone("UTC")
        if (!dateString.endsWith("Z")) {
            val timeZoneSubstr = dateString.substring(dateString.length - 6)
            parsedTz = TimeZone.getTimeZone("GMT$timeZoneSubstr")
        }
        val df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US)
        df.timeZone = parsedTz
        val date = try {
            df.parse(dateString)
        } catch (e: ParseException) {
            throw RuntimeException("Error parsing string", e)
        }
        return Timestamp.ofEpochMilli(date.time)
    }

    /**
     * Similar to a typecast of `value` to the given type `clazz`, except:
     *
     *  * Throws `IllegalArgumentException` instead of `ClassCastException` if
     * `!clazz.isAssignableFrom(value.getClass())`.
     *  * Also throws `IllegalArgumentException` if `value == null`.
     *
     */
    fun <T : V?, V> castTo(clazz: Class<T>, value: V?): T =
        if (value == null || !clazz.isAssignableFrom(value.javaClass)) {
            throw IllegalArgumentException("Expected type $clazz")
        } else {
            value as T
        }

    /**
     * Helper function to check if a given certificate chain is valid.
     *
     * NOTE NOTE NOTE: We only check that the certificates in the chain sign each other. We
     * *specifically* don't check that each certificate is also a CA certificate.
     *
     * @param certificateChain the chain to validate.
     * @return `true` if valid, `false` otherwise.
     */
    @JvmStatic
    fun validateCertificateChain(
        certificateChain: Collection<X509Certificate>
    ): Boolean {
        // First check that each certificate signs the previous one...
        var prevCertificate: X509Certificate? = null
        for (certificate in certificateChain) {
            if (prevCertificate != null) {
                // We're not the leaf certificate...
                //
                // Check the previous certificate was signed by this one.
                try {
                    prevCertificate.verify(certificate.publicKey)
                } catch (e: Exception) {
                    when (e) {
                        is CertificateException,
                        is InvalidKeyException,
                        is NoSuchAlgorithmException,
                        is NoSuchProviderException,
                        is SignatureException -> return false
                    }
                }
            } else {
                // we're the leaf certificate so we're not signing anything nor
                // do we need to be e.g. a CA certificate.
            }
            prevCertificate = certificate
        }
        return true
    }

    /**
     * Computes an HKDF.
     *
     * This is based on https://github.com/google/tink/blob/master/java/src/main/java/com/google
     * /crypto/tink/subtle/Hkdf.java
     * which is also Copyright (c) Google and also licensed under the Apache 2 license.
     *
     * @param macAlgorithm the MAC algorithm used for computing the Hkdf. I.e., "HMACSHA1" or
     * "HMACSHA256".
     * @param ikm          the input keying material.
     * @param salt         optional salt. A possibly non-secret random value. If no salt is
     * provided (i.e. if
     * salt has length 0) then an array of 0s of the same size as the hash
     * digest is used as salt.
     * @param info         optional context and application specific information.
     * @param size         The length of the generated pseudorandom string in bytes. The maximal
     * size is
     * 255.DigestSize, where DigestSize is the size of the underlying HMAC.
     * @return size pseudorandom bytes.
     */
    @JvmStatic
    fun computeHkdf(
        macAlgorithm: String, ikm: ByteArray, salt: ByteArray?,
        info: ByteArray?, size: Int
    ): ByteArray {
        val mac = try {
            Mac.getInstance(macAlgorithm)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("No such algorithm: $macAlgorithm", e)
        }
        require(size <= 255 * mac.macLength) { "size too large" }
        return try {
            if (salt == null || salt.size == 0) {
                // According to RFC 5869, Section 2.2 the salt is optional. If no salt is provided
                // then HKDF uses a salt that is an array of zeros of the same length as the hash
                // digest.
                mac.init(SecretKeySpec(ByteArray(mac.macLength), macAlgorithm))
            } else {
                mac.init(SecretKeySpec(salt, macAlgorithm))
            }
            val prk = mac.doFinal(ikm)
            val result = ByteArray(size)
            var ctr = 1
            var pos = 0
            mac.init(SecretKeySpec(prk, macAlgorithm))
            var digest = ByteArray(0)
            while (true) {
                mac.update(digest)
                mac.update(info)
                mac.update(ctr.toByte())
                digest = mac.doFinal()
                if (pos + digest.size < size) {
                    System.arraycopy(digest, 0, result, pos, digest.size)
                    pos += digest.size
                    ctr++
                } else {
                    System.arraycopy(digest, 0, result, pos, size - pos)
                    break
                }
            }
            result
        } catch (e: InvalidKeyException) {
            throw IllegalStateException("Error MACing", e)
        }
    }

    private fun coseBuildToBeSigned(
        encodedProtectedHeaders: ByteArray,
        payload: ByteArray?,
        detachedContent: ByteArray?
    ): ByteArray {
        val sigStructure = CborBuilder()
        val array: ArrayBuilder<CborBuilder> = sigStructure.addArray()
        array.add("Signature1")
        array.add(encodedProtectedHeaders)

        // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
        // so external_aad is the empty bstr
        val emptyExternalAad = ByteArray(0)
        array.add(emptyExternalAad)

        // Next field is the payload, independently of how it's transported (RFC
        // 8152 section 4.4). Since our API specifies only one of |data| and
        // |detachedContent| can be non-empty, it's simply just the non-empty one.
        if (payload != null && payload.isNotEmpty()) {
            array.add(payload)
        } else {
            array.add(detachedContent)
        }
        array.end()
        return cborEncode(sigStructure.build().first())
    }

    /*
     * From RFC 8152 section 8.1 ECDSA:
     *
     * The signature algorithm results in a pair of integers (R, S).  These
     * integers will be the same length as the length of the key used for
     * the signature process.  The signature is encoded by converting the
     * integers into byte strings of the same length as the key size.  The
     * length is rounded up to the nearest byte and is left padded with zero
     * bits to get to the correct length.  The two integers are then
     * concatenated together to form a byte string that is the resulting
     * signature.
     */
    private fun signatureDerToCose(signature: ByteArray, keySize: Int): ByteArray? {
        val asn1 = try {
            ASN1InputStream(ByteArrayInputStream(signature)).readObject()
        } catch (e: IOException) {
            throw IllegalArgumentException("Error decoding DER signature", e)
        }
        val asn1Encodables: Array<ASN1Encodable> = castTo(ASN1Sequence::class.java, asn1).toArray()
        require(asn1Encodables.size == 2) { "Expected two items in sequence" }
        val r: BigInteger =
            castTo(ASN1Integer::class.java, asn1Encodables[0].toASN1Primitive()).value
        val s: BigInteger =
            castTo(ASN1Integer::class.java, asn1Encodables[1].toASN1Primitive()).value
        val rBytes = stripLeadingZeroes(r.toByteArray())
        val sBytes = stripLeadingZeroes(s.toByteArray())
        val baos = ByteArrayOutputStream()
        try {
            for (n in 0 until keySize - rBytes.size) {
                baos.write(0x00)
            }
            baos.write(rBytes)
            for (n in 0 until keySize - sBytes.size) {
                baos.write(0x00)
            }
            baos.write(sBytes)
        } catch (e: IOException) {
            e.printStackTrace()
            return null
        }
        return baos.toByteArray()
    }

    private fun signatureCoseToDer(signature: ByteArray): ByteArray {
        // r and s are always positive and may use all bits so use the constructor which
        // parses them as unsigned.
        val r = BigInteger(
            1, signature.copyOfRange(0, signature.size / 2)
        )
        val s = BigInteger(
            1, signature.copyOfRange(signature.size / 2, signature.size)
        )
        val baos = ByteArrayOutputStream()
        try {
            val seq = DERSequenceGenerator(baos)
            seq.addObject(ASN1Integer(r.toByteArray()))
            seq.addObject(ASN1Integer(s.toByteArray()))
            seq.close()
        } catch (e: IOException) {
            throw IllegalStateException("Error generating DER signature", e)
        }
        return baos.toByteArray()
    }

    @JvmStatic
    fun coseSign1Sign(
        s: Signature,
        data: ByteArray?,
        detachedContent: ByteArray?,
        certificateChain: Collection<X509Certificate>?
    ): DataItem {
        val dataLen = data?.size ?: 0
        val detachedContentLen = detachedContent?.size ?: 0
        require(!(dataLen > 0 && detachedContentLen > 0)) {
            "data and detachedContent cannot both be non-empty"
        }
        val keySize: Int
        val alg: Long
        if (s.algorithm == "SHA256withECDSA") {
            keySize = 32
            alg = COSE_ALG_ECDSA_256
        } else if (s.algorithm == "SHA384withECDSA") {
            keySize = 48
            alg = COSE_ALG_ECDSA_384
        } else if (s.algorithm == "SHA512withECDSA") {
            keySize = 64
            alg = COSE_ALG_ECDSA_512
        } else {
            throw IllegalArgumentException("Unsupported algorithm ${s.algorithm}")
        }
        val protectedHeaders = CborBuilder()
        val protectedHeadersMap: MapBuilder<CborBuilder> = protectedHeaders.addMap()
        protectedHeadersMap.put(COSE_LABEL_ALG, alg)
        val protectedHeadersBytes = cborEncode(protectedHeaders.build().first())
        val toBeSigned = coseBuildToBeSigned(protectedHeadersBytes, data, detachedContent)
        val coseSignature = try {
            s.update(toBeSigned)
            val derSignature = s.sign()
            signatureDerToCose(derSignature, keySize)
        } catch (e: SignatureException) {
            throw IllegalStateException("Error signing data", e)
        }
        val builder = CborBuilder()
        val array: ArrayBuilder<CborBuilder> = builder.addArray()
        array.add(protectedHeadersBytes)
        val unprotectedHeaders: MapBuilder<ArrayBuilder<CborBuilder>> = array.addMap()
        try {
            if (!certificateChain.isNullOrEmpty()) {
                if (certificateChain.size == 1) {
                    val cert = certificateChain.iterator().next()
                    unprotectedHeaders.put(COSE_LABEL_X5CHAIN, cert.encoded)
                } else {
                    val x5chainsArray: ArrayBuilder<MapBuilder<ArrayBuilder<CborBuilder>>> =
                        unprotectedHeaders.putArray(
                            COSE_LABEL_X5CHAIN
                        )
                    for (cert in certificateChain) {
                        x5chainsArray.add(cert.encoded)
                    }
                }
            }
        } catch (e: CertificateEncodingException) {
            throw IllegalStateException("Error encoding certificate", e)
        }
        if (data == null || data.isEmpty()) {
            array.add(SimpleValue(SimpleValueType.NULL))
        } else {
            array.add(data)
        }
        array.add(coseSignature)
        return builder.build().first()
    }

    /**
     * Note: this uses the default JCA provider which may not support a lot of curves, for
     * example it doesn't support Brainpool curves. If you need to use such curves, use
     * [.coseSign1Sign] instead with a
     * Signature created using a provider that does have support.
     *
     * Currently only ECDSA signatures are supported.
     *
     * TODO: add support and tests for Ed25519 and Ed448.
     */
    @JvmStatic
    fun coseSign1Sign(
        key: PrivateKey,
        algorithm: String, data: ByteArray?,
        additionalData: ByteArray?,
        certificateChain: Collection<X509Certificate>?
    ): DataItem = try {
        val s = Signature.getInstance(algorithm)
        s.initSign(key)
        coseSign1Sign(s, data, additionalData, certificateChain)
    } catch (e: Exception) {
        // can be either NoSuchAlgorithmException, InvalidKeyException or for any exception
        throw IllegalStateException("Caught exception", e)
    }

    /**
     * Currently only ECDSA signatures are supported.
     *
     * TODO: add support and tests for Ed25519 and Ed448.
     */
    @JvmStatic
    fun coseSign1CheckSignature(
        coseSign1: DataItem,
        detachedContent: ByteArray?,
        publicKey: PublicKey
    ): Boolean {
        require(coseSign1.majorType == MajorType.ARRAY) { "Data item is not an array" }
        val items = (coseSign1 as co.nstant.`in`.cbor.model.Array).dataItems
        require(items.size >= 4) { "Expected at least four items in COSE_Sign1 array" }
        require(items[0].majorType == MajorType.BYTE_STRING) { "Item 0 (protected headers) is not a byte-string" }
        val encodedProtectedHeaders = (items[0] as ByteString).bytes
        var payload = ByteArray(0)
        when (items[2].majorType) {
            MajorType.SPECIAL -> {
                require((items[2] as Special).specialType == SpecialType.SIMPLE_VALUE) { "Item 2 (payload) is a special but not a simple value" }
                val simple: SimpleValue = items[2] as SimpleValue
                require(simple.simpleValueType == SimpleValueType.NULL) { "Item 2 (payload) is a simple but not the value null" }
            }

            MajorType.BYTE_STRING -> {
                payload = (items[2] as ByteString).bytes
            }

            else -> {
                throw IllegalArgumentException("Item 2 (payload) is not nil or byte-string")
            }
        }
        require(items[3].majorType == MajorType.BYTE_STRING) { "Item 3 (signature) is not a byte-string" }

        val coseSignature = (items[3] as ByteString).bytes
        val derSignature = signatureCoseToDer(coseSignature)
        val dataLen = payload.size
        val detachedContentLen = detachedContent?.size ?: 0
        require(!(dataLen > 0 && detachedContentLen > 0)) { "data and detachedContent cannot both be non-empty" }
        val protectedHeaders = cborDecode(encodedProtectedHeaders)
        val alg = cborMapExtractNumber(protectedHeaders, COSE_LABEL_ALG)
        val signature = if (alg == COSE_ALG_ECDSA_256) {
            "SHA256withECDSA"
        } else if (alg == COSE_ALG_ECDSA_384) {
            "SHA384withECDSA"
        } else if (alg == COSE_ALG_ECDSA_512) {
            "SHA512withECDSA"
        } else {
            throw IllegalArgumentException("Unsupported COSE alg $alg")
        }
        val toBeSigned = coseBuildToBeSigned(
            encodedProtectedHeaders, payload,
            detachedContent
        )
        return try {
            // Using the default provider here. If BounceyCastle is to be used it is up to client
            // to register that provider beforehand.
            // https://docs.oracle.com/javase/7/docs/api/java/security/Security.html#addProvider(java.security.Provider)
            val verifier = Signature.getInstance(signature)
            verifier.initVerify(publicKey)
            verifier.update(toBeSigned)
            verifier.verify(derSignature)
        } catch (e: Exception) {
            // on any exception, such as SignatureException, NoSuchAlgorithmException, InvalidKeyException
            throw IllegalStateException("Error verifying signature", e)
        }
    }

    private fun coseBuildToBeMACed(
        encodedProtectedHeaders: ByteArray,
        payload: ByteArray,
        detachedContent: ByteArray
    ): ByteArray =
        CborBuilder().run {
            addArray().run {
                add("MAC0")
                add(encodedProtectedHeaders)

                // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
                // so external_aad is the empty bstr
                val emptyExternalAad = ByteArray(0)
                add(emptyExternalAad)

                // Next field is the payload, independently of how it's transported (RFC
                // 8152 section 4.4). Since our API specifies only one of |data| and
                // |detachedContent| can be non-empty, it's simply just the non-empty one.
                if (payload.isNotEmpty()) {
                    add(payload)
                } else {
                    add(detachedContent)
                }
            }

            return cborEncode(build().first())
        }

    @JvmStatic
    fun coseMac0(
        key: SecretKey,
        data: ByteArray?,
        detachedContent: ByteArray?
    ): DataItem {
        val dataLen = data?.size ?: 0
        val detachedContentLen = detachedContent?.size ?: 0
        require(!(dataLen > 0 && detachedContentLen > 0)) { "data and detachedContent cannot both be non-empty" }
        val protectedHeaders = CborBuilder()
        val protectedHeadersMap: MapBuilder<CborBuilder> = protectedHeaders.addMap()
        protectedHeadersMap.put(COSE_LABEL_ALG, COSE_ALG_HMAC_256_256)
        val protectedHeadersBytes = cborEncode(protectedHeaders.build().first())
        val toBeMACed = coseBuildToBeMACed(protectedHeadersBytes, data!!, detachedContent!!)
        val mac: ByteArray = try {
            val m = Mac.getInstance("HmacSHA256")
            m.init(key)
            m.update(toBeMACed)
            m.doFinal()
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Unexpected error", e)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException("Unexpected error", e)
        }
        val builder = CborBuilder()
        val array: ArrayBuilder<CborBuilder> = builder.addArray()
        array.add(protectedHeadersBytes)
        /* MapBuilder<ArrayBuilder<CborBuilder>> unprotectedHeaders = */array.addMap()
        if (data.isEmpty()) {
            array.add(SimpleValue(SimpleValueType.NULL))
        } else {
            array.add(data)
        }
        array.add(mac)
        return builder.build().first()
    }

    @JvmStatic
    fun coseMac0GetTag(coseMac0: DataItem): ByteArray {
        val items = coseMac0.castToArray().dataItems
        require(items.size >= 4) { "coseMac0 have less than 4 elements" }
        val tagItem = items[3]
        return tagItem.castToByteString().bytes
    }

    /**
     * Brute-force but good enough since users will only pass relatively small amounts of data.
     */
    @JvmStatic
    fun hasSubByteArray(haystack: ByteArray, needle: ByteArray): Boolean {
        var n = 0
        while (needle.size + n <= haystack.size) {
            var found = true
            for (m in needle.indices) {
                if (needle[m] != haystack[n + m]) {
                    found = false
                    break
                }
            }
            if (found) {
                return true
            }
            n++
        }
        return false
    }

    @JvmStatic
    fun stripLeadingZeroes(value: ByteArray): ByteArray {
        var n = 0
        while (n < value.size && value[n].toInt() == 0) {
            n++
        }
        val newLen = value.size - n
        val ret = ByteArray(newLen)
        var m = 0
        while (n < value.size) {
            ret[m++] = value[n++]
        }
        return ret
    }

    /**
     * Returns #6.24(bstr) of the given already encoded CBOR
     */
    @JvmStatic
    fun cborBuildTaggedByteString(encodedCbor: ByteArray): DataItem =
        (ByteString(encodedCbor) as DataItem).apply {
            setTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR)
        }


    /**
     * For a #6.24(bstr), extracts the bytes.
     */
    @JvmStatic
    fun cborExtractTaggedCbor(encodedTaggedBytestring: ByteArray): ByteArray =
        cborDecode(encodedTaggedBytestring).run {
            require(!(!hasTag() || tag.value != CBOR_SEMANTIC_TAG_ENCODED_CBOR)) { "ByteString is not tagged with tag 24" }
            castToByteString().bytes
        }

    /**
     * For a #6.24(bstr), extracts the bytes and decodes it and returns
     * the decoded CBOR as a DataItem.
     */
    @JvmStatic
    fun cborExtractTaggedAndEncodedCbor(item: DataItem): DataItem =
        item.castToByteString().run {
            require(!(!item.hasTag() || item.tag.value != CBOR_SEMANTIC_TAG_ENCODED_CBOR)) { "ByteString is not tagged with tag 24" }
            cborDecode(bytes)
        }

    /**
     * Returns the empty byte-array if no data is included in the structure.
     */
    @JvmStatic
    fun coseSign1GetData(coseSign1: DataItem): ByteArray {
        require(coseSign1.majorType == MajorType.ARRAY) { "Data item is not an array" }
        val items = coseSign1.castToArray().dataItems
        require(items.size >= 4) { "Expected at least four items in COSE_Sign1 array" }
        var payload = ByteArray(0)
        if (items[2].majorType == MajorType.SPECIAL) {
            require((items[2] as Special).specialType == SpecialType.SIMPLE_VALUE) { "Item 2 (payload) is a special but not a simple value" }
            val simple: SimpleValue = items[2].castToSimpleValue()
            require(simple.simpleValueType == SimpleValueType.NULL) { "Item 2 (payload) is a simple but not the value null" }
        } else if (items[2].majorType == MajorType.BYTE_STRING) {
            payload = items[2].castToByteString().bytes
        } else {
            throw IllegalArgumentException("Item 2 (payload) is not nil or byte-string")
        }
        return payload
    }

    /**
     * Returns the empty collection if no x5chain is included in the structure.
     *
     * Throws exception if the given bytes aren't valid COSE_Sign1.
     */
    @JvmStatic
    fun coseSign1GetX5Chain(
        coseSign1: DataItem
    ): List<X509Certificate> {
        val ret = mutableListOf<X509Certificate>()
        require(coseSign1.majorType == MajorType.ARRAY) { "Data item is not an array" }
        val items = coseSign1.castToArray().dataItems
        require(items.size >= 4) { "Expected at least four items in COSE_Sign1 array" }
        require(items[1].majorType == MajorType.MAP) { "Item 1 (unprotected headers) is not a map" }
        val map = items[1] as Map
        val x5chainItem = map[UnsignedInteger(COSE_LABEL_X5CHAIN)]
        if (x5chainItem != null) {
            try {
                val factory = CertificateFactory.getInstance("X.509")
                if (x5chainItem is ByteString) {
                    val certBais = ByteArrayInputStream(x5chainItem.castToByteString().bytes)
                    ret.add(factory.generateCertificate(certBais) as X509Certificate)
                } else if (x5chainItem is co.nstant.`in`.cbor.model.Array) {
                    for (certItem in x5chainItem.castToArray().dataItems) {
                        val certBais = ByteArrayInputStream(certItem.castToByteString().bytes)
                        ret.add(factory.generateCertificate(certBais) as X509Certificate)
                    }
                } else {
                    throw IllegalArgumentException("Unexpected type for x5chain value")
                }
            } catch (e: CertificateException) {
                throw IllegalArgumentException("Unexpected error", e)
            }
        }
        return ret
    }

    /* Encodes an integer according to Section 2.3.5 Field-Element-to-Octet-String Conversion
     * of SEC 1: Elliptic Curve Cryptography (https://www.secg.org/sec1-v2.pdf).
     */
    fun sec1EncodeFieldElementAsOctetString(
        octetStringSize: Int,
        fieldValue: BigInteger?
    ): ByteArray = BigIntegers.asUnsignedByteArray(octetStringSize, fieldValue)

    @JvmStatic
    fun cborBuildCoseKey(
        key: PublicKey,
        curve: EcCurve
    ): DataItem =
        when (curve) {
            EcCurve.ED25519, EcCurve.ED448 -> {
                val x = (key as BCEdDSAPublicKey).pointEncoding
                CborBuilder()
                    .addMap()
                    .put(COSE_KEY_KTY, COSE_KEY_TYPE_OKP)
                    .put(COSE_KEY_PARAM_CRV, curve.coseCurveIdentifier.toLong())
                    .put(COSE_KEY_PARAM_X, x)
                    .end()
                    .build().first()
            }

            EcCurve.X25519, EcCurve.X448 -> {
                val x = (key as BCXDHPublicKey).uEncoding
                CborBuilder()
                    .addMap()
                    .put(COSE_KEY_KTY, COSE_KEY_TYPE_OKP)
                    .put(COSE_KEY_PARAM_CRV, curve.coseCurveIdentifier.toLong())
                    .put(COSE_KEY_PARAM_X, x)
                    .end()
                    .build().first()
            }

            else -> {
                val ecKey = key as ECPublicKey
                val w = ecKey.w
                val keySizeBits: Int = curve.bitSize
                val x = sec1EncodeFieldElementAsOctetString((keySizeBits + 7) / 8, w.affineX)
                val y = sec1EncodeFieldElementAsOctetString((keySizeBits + 7) / 8, w.affineY)
                CborBuilder()
                    .addMap()
                    .put(COSE_KEY_KTY, COSE_KEY_TYPE_EC2)
                    .put(COSE_KEY_PARAM_CRV, curve.coseCurveIdentifier.toLong())
                    .put(COSE_KEY_PARAM_X, x)
                    .put(COSE_KEY_PARAM_Y, y)
                    .end()
                    .build().first()
            }
        }

    // Used for testing only, to create an invalid COSE_Key
    @JvmStatic
    fun cborBuildCoseKeyWithMalformedYPoint(key: PublicKey): DataItem {
        val ecKey =
            key as ECPublicKey
        val w = ecKey.w
        val malformedY = BigInteger.valueOf(42)
        val x =
            sec1EncodeFieldElementAsOctetString(32, w.affineX)
        val y =
            sec1EncodeFieldElementAsOctetString(32, malformedY)
        return CborBuilder()
            .addMap()
            .put(COSE_KEY_KTY, COSE_KEY_TYPE_EC2)
            .put(COSE_KEY_PARAM_CRV, COSE_KEY_PARAM_CRV_P256)
            .put(COSE_KEY_PARAM_X, x)
            .put(COSE_KEY_PARAM_Y, y)
            .end()
            .build().first()
    }

    @JvmStatic
    fun cborMapHasKey(map: DataItem, key: String): Boolean =
        map.castToMap()[key.toUnicodeString()] != null

    @JvmStatic
    fun cborMapHasKey(map: DataItem, key: Long): Boolean =
        map.castToMap()[key.toIntegerNumber()] != null


    @JvmStatic
    fun cborMapExtractNumber(map: DataItem, key: Long): Long =
        checkedLongValue(map.castToMap()[key.toIntegerNumber()])


    @JvmStatic
    fun cborMapExtractNumber(map: DataItem, key: String): Long =
        checkedLongValue(map.castToMap()[key.toUnicodeString()])

    @JvmStatic
    fun cborMapExtractString(map: DataItem, key: String): String =
        checkedStringValue(map.castToMap()[key.toUnicodeString()])

    @JvmStatic
    fun cborMapExtractString(map: DataItem, key: Long): String =
        checkedStringValue(map.castToMap()[key.toIntegerNumber()])

    @JvmStatic
    fun cborMapExtractArray(map: DataItem, key: String): List<DataItem> =
        map.castToMap()[key.toUnicodeString()].run { castToArray().dataItems }

    @JvmStatic
    fun cborMapExtractArray(map: DataItem, key: Long): List<DataItem> =
        map.castToMap()[key.toIntegerNumber()].run { castToArray().dataItems }

    @JvmStatic
    fun cborMapExtractMap(map: DataItem, key: String): DataItem =
        map.castToMap()[key.toUnicodeString()].run { castToMap() }

    @JvmStatic
    fun cborMapExtractMapStringKeys(map: DataItem): Collection<String> =
        map.castToMap().keys.map { checkedStringValue(it) }

    @JvmStatic
    fun cborMapExtractMapNumberKeys(map: DataItem): Collection<Long> =
        map.castToMap().keys.map { checkedLongValue(it) }

    @JvmStatic
    fun cborMapExtractByteString(map: DataItem, key: Long): ByteArray =
        map.castToMap()[key.toIntegerNumber()].run { castToByteString().bytes }

    @JvmStatic
    fun cborMapExtractByteString(map: DataItem, key: String): ByteArray =
        map.castToMap()[key.toUnicodeString()].run { castToByteString().bytes }

    @JvmStatic
    fun cborMapExtractBoolean(map: DataItem, key: String): Boolean =
        map.castToMap()[key.toUnicodeString()].run { castToSimpleValue().simpleValueType == SimpleValueType.TRUE }


    @JvmStatic
    fun cborMapExtractBoolean(map: DataItem, key: Long): Boolean =
        map.castToMap()[key.toIntegerNumber()].run { castToSimpleValue().simpleValueType == SimpleValueType.TRUE }

    @JvmStatic
    fun cborMapExtractDateTime(map: DataItem, key: String): Timestamp =
        map.castToMap()[key.toUnicodeString()].run { cborDecodeDateTime(castToUnicodeString()) }

    @JvmStatic
    fun cborMapExtract(map: DataItem, key: String): DataItem =
        map.castToMap()[key.toUnicodeString()]
            ?: throw IllegalArgumentException("Expected item for key $key")


    @JvmStatic
    fun coseKeyGetCurve(coseKey: DataItem): EcCurve =
        EcCurve.fromInt(cborMapExtractNumber(coseKey, COSE_KEY_PARAM_CRV).toInt())

    private fun coseKeyDecodeEc2(coseKey: DataItem): PublicKey {
        val crv: EcCurve =
            EcCurve.fromInt(cborMapExtractNumber(coseKey, COSE_KEY_PARAM_CRV).toInt())
        val keySizeOctets: Int = (crv.bitSize + 7) / 8
        val curveName: String = crv.SECGName
        val encodedX = cborMapExtractByteString(coseKey, COSE_KEY_PARAM_X)
        val encodedY = cborMapExtractByteString(coseKey, COSE_KEY_PARAM_Y)
        if (encodedX.size != keySizeOctets) {
            w(
                TAG, String.format(
                    Locale.US, "Expected %d bytes for X in COSE_Key, found %d",
                    keySizeOctets, encodedX.size
                )
            )
        }
        if (encodedY.size != keySizeOctets) {
            w(
                TAG, String.format(
                    Locale.US, "Expected %d bytes for Y in COSE_Key, found %d",
                    keySizeOctets, encodedY.size
                )
            )
        }
        val x = BigInteger(1, encodedX)
        val y = BigInteger(1, encodedY)
        return try {
            val params: AlgorithmParameters =
                AlgorithmParameters.getInstance(
                    "EC",
                    BouncyCastleProvider.PROVIDER_NAME
                )
            params.init(ECGenParameterSpec(curveName))
            val ecParameters =
                params.getParameterSpec(
                    ECParameterSpec::class.java
                )
            val ecPoint = ECPoint(x, y)
            val keySpec =
                ECPublicKeySpec(ecPoint, ecParameters)
            val kf = KeyFactory.getInstance("EC")
            kf.generatePublic(keySpec) as ECPublicKey
        } catch (e: Exception) {
            // any exception. such as NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, NoSuchProviderException
            throw IllegalStateException("Unexpected error", e)
        }
    }

    private fun coseKeyDecodeOkp(coseKey: DataItem): PublicKey {
        val crv: EcCurve =
            EcCurve.fromInt(cborMapExtractNumber(coseKey, COSE_KEY_PARAM_CRV).toInt())
        val keySizeOctets: Int = (crv.bitSize + 7) / 8
        val encodedX = cborMapExtractByteString(coseKey, COSE_KEY_PARAM_X)
        if (encodedX.size != keySizeOctets) {
            w(
                TAG, String.format(
                    Locale.US, "Expected %d bytes for X in COSE_Key, found %d",
                    keySizeOctets, encodedX.size
                )
            )
        }
        return try {
            // Unfortunately we need to create an X509 encoded version of the public
            // key material, for simplicity we just use prefixes.
            val prefix: ByteArray
            val kf: KeyFactory
            when (crv) {
                EcCurve.ED448 -> {
                    kf = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME)
                    prefix = ED448_X509_ENCODED_PREFIX
                }

                EcCurve.ED25519 -> {
                    kf = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME)
                    prefix = ED25519_X509_ENCODED_PREFIX
                }

                EcCurve.X25519 -> {
                    kf = KeyFactory.getInstance("XDH", BouncyCastleProvider.PROVIDER_NAME)
                    prefix = X25519_X509_ENCODED_PREFIX
                }

                EcCurve.X448 -> {
                    kf = KeyFactory.getInstance("XDH", BouncyCastleProvider.PROVIDER_NAME)
                    prefix = X448_X509_ENCODED_PREFIX
                }

                else -> throw IllegalArgumentException("Unsupported curve with id $crv")
            }
            val baos = ByteArrayOutputStream()
            baos.write(prefix)
            baos.write(encodedX)
            kf.generatePublic(X509EncodedKeySpec(baos.toByteArray()))
        } catch (e: Exception) {
            // any exception, such as NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchProviderException
            throw IllegalStateException("Unexpected error", e)
        }
    }

    private val ED25519_X509_ENCODED_PREFIX =
        byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
    private val X25519_X509_ENCODED_PREFIX =
        byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00)
    private val ED448_X509_ENCODED_PREFIX =
        byteArrayOf(0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00)
    private val X448_X509_ENCODED_PREFIX =
        byteArrayOf(0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00)

    @JvmStatic
    fun coseKeyDecode(coseKey: DataItem): PublicKey {
        val kty = cborMapExtractNumber(coseKey, COSE_KEY_KTY)
        return when (kty) {
            COSE_KEY_TYPE_EC2 -> coseKeyDecodeEc2(coseKey)
            COSE_KEY_TYPE_OKP -> coseKeyDecodeOkp(coseKey)
            else -> throw IllegalArgumentException("Expected COSE_KEY_TYPE_EC2 or COSE_KEY_TYPE_OKP, got $kty")
        }
    }

    @JvmStatic
    fun calcEMacKeyForReader(
        authenticationPublicKey: PublicKey,
        ephemeralReaderPrivateKey: PrivateKey,
        encodedSessionTranscript: ByteArray
    ): SecretKey =
        try {
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(ephemeralReaderPrivateKey)
            ka.doPhase(authenticationPublicKey, true)
            val sharedSecret = ka.generateSecret()
            val sessionTranscriptBytes =
                cborEncode(
                    cborBuildTaggedByteString(
                        encodedSessionTranscript
                    )
                )
            val salt =
                MessageDigest.getInstance("SHA-256").digest(sessionTranscriptBytes)

            val infoChars = "EMacKey"
            val info = infoChars.map { ch ->
                ch.code.toByte()
            }.toByteArray()

            val derivedKey = computeHkdf(
                "HmacSha256",
                sharedSecret,
                salt,
                info,
                32
            )
            SecretKeySpec(derivedKey, "")
        } catch (e: Exception) {
            // including InvalidKeyException, NoSuchAlgorithmException
            throw IllegalStateException("Error performing key agreement", e)
        }

    @JvmStatic
    fun cborPrettyPrint(dataItem: DataItem) = StringBuilder().run {
        cborPrettyPrintDataItem(this, 0, dataItem)
        toString()
    }

    @JvmStatic
    fun cborPrettyPrint(encodedBytes: ByteArray): String {
        val sb = StringBuilder()
        val bais = ByteArrayInputStream(encodedBytes)
        val dataItems = try {
            CborDecoder(bais).decode()
        } catch (e: CborException) {
            throw IllegalStateException(e)
        }
        var count = 0
        for (dataItem in dataItems) {
            if (count > 0) {
                sb.append(",\n")
            }
            cborPrettyPrintDataItem(sb, 0, dataItem)
            count++
        }
        return sb.toString()
    }

    // Returns true iff all elements in |items| are not compound (e.g. an array or a map).
    private fun cborAreAllDataItemsNonCompound(items: List<DataItem>): Boolean {
        for (item in items) {
            when (item.majorType) {
                MajorType.ARRAY, MajorType.MAP -> return false
                else -> {}
            }
        }
        return true
    }

    private fun cborPrettyPrintDataItem(
        sb: StringBuilder, indent: Int,
        dataItem: DataItem
    ) {
        val indentBuilder = StringBuilder()
        for (n in 0 until indent) {
            indentBuilder.append(' ')
        }
        val indentString = indentBuilder.toString()
        if (dataItem.hasTag()) {
            sb.append(String.format(Locale.US, "tag %d ", dataItem.tag.value))
        }
        when (dataItem.majorType) {
            MajorType.INVALID ->
                sb.append("<invalid>")

            MajorType.UNSIGNED_INTEGER -> {

                // Major type 0: an unsigned integer.
                val value = (dataItem as UnsignedInteger).value
                sb.append(value)
            }

            MajorType.NEGATIVE_INTEGER -> {

                // Major type 1: a negative integer.
                val value: BigInteger = (dataItem as NegativeInteger).value
                sb.append(value)
            }

            MajorType.BYTE_STRING -> {

                // Major type 2: a byte string.
                val value = (dataItem as ByteString).bytes
                sb.append("[")
                var count = 0
                for (b in value) {
                    if (count > 0) {
                        sb.append(", ")
                    }
                    sb.append(String.format("0x%02x", b))
                    count++
                }
                sb.append("]")
            }

            MajorType.UNICODE_STRING -> {

                // Major type 3: string of Unicode characters that is encoded as UTF-8 [RFC3629].
                val value = checkedStringValue(dataItem)
                // TODO: escape ' in |value|
                sb.append("'$value'")
            }

            MajorType.ARRAY -> {

                // Major type 4: an array of data items.
                val items = (dataItem as co.nstant.`in`.cbor.model.Array).dataItems
                if (items.size == 0) {
                    sb.append("[]")
                } else if (cborAreAllDataItemsNonCompound(items)) {
                    // The case where everything fits on one line.
                    sb.append("[")
                    var count = 0
                    for (item in items) {
                        cborPrettyPrintDataItem(sb, indent, item)
                        if (++count < items.size) {
                            sb.append(", ")
                        }
                    }
                    sb.append("]")
                } else {
                    sb.append("[\n$indentString")
                    for ((count, item) in items.withIndex()) {
                        sb.append("  ")
                        cborPrettyPrintDataItem(sb, indent + 2, item)
                        if (count + 1 < items.size) {
                            sb.append(",")
                        }
                        sb.append("\n" + indentString)
                    }
                    sb.append("]")
                }
            }

            MajorType.MAP -> {

                // Major type 5: a map of pairs of data items.
                val keys = (dataItem as Map).keys
                if (keys.isEmpty()) {
                    sb.append("{}")
                } else {
                    sb.append("{\n$indentString")
                    for ((count, key) in keys.withIndex()) {
                        sb.append("  ")
                        val value = dataItem[key]
                        cborPrettyPrintDataItem(sb, indent + 2, key)
                        sb.append(" : ")
                        cborPrettyPrintDataItem(sb, indent + 2, value)
                        if (count + 1 < keys.size) {
                            sb.append(",")
                        }
                        sb.append("\n" + indentString)
                    }
                    sb.append("}")
                }
            }

            MajorType.TAG -> throw IllegalStateException("Semantic tag data item not expected")
            MajorType.SPECIAL ->                 // Major type 7: floating point numbers and simple data types that need no
                // content, as well as the "break" stop code.
                if (dataItem is SimpleValue) {
                    when (dataItem.simpleValueType) {
                        SimpleValueType.FALSE -> sb.append("false")
                        SimpleValueType.TRUE -> sb.append("true")
                        SimpleValueType.NULL -> sb.append("null")
                        SimpleValueType.UNDEFINED -> sb.append("undefined")
                        SimpleValueType.RESERVED -> sb.append("reserved")
                        SimpleValueType.UNALLOCATED -> sb.append("unallocated")
                        null -> {} // Java case
                    }
                } else if (dataItem is DoublePrecisionFloat) {
                    val df = DecimalFormat(
                        "0",
                        DecimalFormatSymbols.getInstance(Locale.ENGLISH)
                    )
                    df.maximumFractionDigits = 340
                    sb.append(df.format(dataItem.value))
                } else if (dataItem is AbstractFloat) {
                    val df = DecimalFormat(
                        "0",
                        DecimalFormatSymbols.getInstance(Locale.ENGLISH)
                    )
                    df.maximumFractionDigits = 340
                    sb.append(df.format(dataItem.value.toDouble()))
                } else {
                    sb.append("break")
                }

            // Java case: "Enum argument can be null in Java, but exhaustive when contains no null branch"
            null -> {}
        }
    }

    @JvmStatic
    fun canonicalizeCbor(encodedCbor: ByteArray): ByteArray = cborEncode(cborDecode(encodedCbor))

    @JvmStatic
    fun replaceLine(
        text: String,
        lineNumber: Int,
        replacementLine: String
    ): String {
        var ln = lineNumber
        val lines = text.split("\n".toRegex()).dropLastWhile { it.isEmpty() }
            .toTypedArray()
        val numLines = lines.size
        if (ln < 0) {
            ln = numLines - -ln
        }
        val sb = StringBuilder()
        for (n in 0 until numLines) {
            if (n == ln) {
                sb.append(replacementLine)
            } else {
                sb.append(lines[n])
            }
            // Only add terminating newline if passed-in string ends in a newline.
            if (n == numLines - 1) {
                if (text.endsWith("\n")) {
                    sb.append('\n')
                }
            } else {
                sb.append('\n')
            }
        }
        return sb.toString()
    }

    /**
     * Helper function to create a CBOR data for requesting data items. The IntentToRetain
     * value will be set to false for all elements.
     *
     *
     * The returned CBOR data conforms to the following CDDL schema:
     *
     * <pre>
     * ItemsRequest = {
     * ? "docType" : DocType,
     * "nameSpaces" : NameSpaces,
     * ? "RequestInfo" : {* tstr =&gt; any} ; Additional info the reader wants to provide
     * }
     *
     * NameSpaces = {
     * + NameSpace =&gt; DataElements     ; Requested data elements for each NameSpace
     * }
     *
     * DataElements = {
     * + DataElement =&gt; IntentToRetain
     * }
     *
     * DocType = tstr
     *
     * DataElement = tstr
     * IntentToRetain = bool
     * NameSpace = tstr
    </pre> *
     *
     * @param entriesToRequest The entries to request, organized as a map of namespace
     * names with each value being a collection of data elements
     * in the given namespace.
     * @param docType          The document type or `null` if there is no document
     * type.
     * @return CBOR data conforming to the CDDL mentioned above.
     *
     * TODO: docType is no longer optional so change docType to be NonNull and update all callers.
     */
    @JvmStatic
    fun createItemsRequest(
        entriesToRequest: kotlin.collections.Map<String?, Collection<String?>>,
        docType: String?
    ): ByteArray {
        val builder = CborBuilder()
        val mapBuilder: MapBuilder<CborBuilder> = builder.addMap()
        if (docType != null) {
            mapBuilder.put("docType", docType)
        }
        val nsMapBuilder: MapBuilder<MapBuilder<CborBuilder>> = mapBuilder.putMap("nameSpaces")
        for (namespaceName in entriesToRequest.keys) {
            val entryNames = entriesToRequest[namespaceName]!!
            val entryNameMapBuilder: MapBuilder<MapBuilder<MapBuilder<CborBuilder>>> =
                nsMapBuilder.putMap(namespaceName)
            for (entryName in entryNames) {
                entryNameMapBuilder.put(entryName, false)
            }
        }
        return cborEncode(builder.build().first())
    }

    @JvmStatic
    fun getPopSha256FromAuthKeyCert(cert: X509Certificate): ByteArray? {
        val octetString = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.26") ?: return null
        return try {
            val asn1InputStream = ASN1InputStream(octetString)
            val cborBytes: ByteArray = (asn1InputStream.readObject() as ASN1OctetString).octets
            val bais = ByteArrayInputStream(cborBytes)
            val dataItems: List<DataItem> = CborDecoder(bais).decode()
            require(dataItems.size == 1) { "Expected 1 item, found ${dataItems.size}" }
            val array = dataItems[0].castToArray()
            val items = array.dataItems
            require(items.size >= 2) { "Expected at least 2 array items, found ${items.size}" }
            val id = checkedStringValue(items[0])
            require(id == "ProofOfBinding") { "Expected ProofOfBinding, got $id" }
            val popSha256 = items[1].castToByteString().bytes
            require(popSha256.size == 32) { "Expected bstr to be 32 bytes, it is ${popSha256.size}" }
            popSha256
        } catch (e: IOException) {
            throw IllegalArgumentException("Error decoding extension data", e)
        } catch (e: CborException) {
            throw IllegalArgumentException("Error decoding data", e)
        }
    }

    /**
     * Clears elementValue in IssuerSignedItemBytes CBOR.
     *
     * @param encodedIssuerSignedItem encoded CBOR conforming to IssuerSignedItem.
     * @return Same as given CBOR but with elementValue set to NULL.
     */
    @JvmStatic
    fun issuerSignedItemClearValue(encodedIssuerSignedItem: ByteArray): ByteArray {
        val encodedNullValue = cborEncode(SimpleValue.NULL)
        return issuerSignedItemSetValue(encodedIssuerSignedItem, encodedNullValue)
    }

    /**
     * Sets elementValue in IssuerSignedItem CBOR.
     *
     * Throws if the given encodedIssuerSignedItemBytes isn't IssuersignedItemBytes.
     *
     * @param encodedIssuerSignedItem      encoded CBOR conforming to IssuerSignedItem.
     * @param encodedElementValue          the value to set elementValue to.
     * @return Same as given CBOR but with elementValue set to given value.
     */
    @JvmStatic
    fun issuerSignedItemSetValue(
        encodedIssuerSignedItem: ByteArray,
        encodedElementValue: ByteArray
    ): ByteArray {
        val issuerSignedItemElem = cborDecode(encodedIssuerSignedItem)
        val issuerSignedItem = issuerSignedItemElem.castToMap()
        val elementValue = cborDecode(encodedElementValue)
        issuerSignedItem.put(UnicodeString("elementValue"), elementValue)

        // By using the non-canonical encoder the order is preserved.
        return cborEncode(issuerSignedItem)
    }

    @JvmStatic
    fun getPrivateKeyFromInteger(s: BigInteger): PrivateKey =
        try {
            val params = AlgorithmParameters.getInstance("EC")
            params.init(ECGenParameterSpec("secp256r1"))
            val ecParameters = params.getParameterSpec(
                ECParameterSpec::class.java
            )
            val privateKeySpec = ECPrivateKeySpec(s, ecParameters)
            val keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePrivate(privateKeySpec)
        } catch (e: Exception) {
            // including NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException
            throw IllegalStateException(e)
        }

    @JvmStatic
    fun getPublicKeyFromIntegers(
        x: BigInteger,
        y: BigInteger
    ): PublicKey =
        try {
            val params =
                AlgorithmParameters.getInstance("EC")
            params.init(ECGenParameterSpec("secp256r1"))
            val ecParameters =
                params.getParameterSpec(
                    ECParameterSpec::class.java
                )
            val ecPoint = ECPoint(x, y)
            val keySpec =
                ECPublicKeySpec(ecPoint, ecParameters)
            val kf = KeyFactory.getInstance("EC")
            kf.generatePublic(keySpec) as ECPublicKey
        } catch (e: Exception) {
            // including NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException
            throw IllegalStateException("Unexpected error", e)
        }

    // Returns null on End Of Stream.
    //
    @JvmStatic
    @Throws(IOException::class)
    fun readBytes(inputStream: InputStream, numBytes: Int): ByteBuffer? {
        val data = ByteBuffer.allocate(numBytes)
        var offset = 0
        var numBytesRemaining = numBytes
        while (numBytesRemaining > 0) {
            val numRead = inputStream.read(data.array(), offset, numBytesRemaining)
            if (numRead == -1) {
                return null
            }
            check(numRead != 0) { "read() returned zero bytes" }
            numBytesRemaining -= numRead
            offset += numRead
        }
        return data
    }

    // TODO: Maybe return List<DataItem> instead of reencoding.
    //
    @JvmStatic
    fun extractDeviceRetrievalMethods(
        encodedDeviceEngagement: ByteArray
    ): List<ByteArray> {
        val ret = mutableListOf<ByteArray>()
        val deviceEngagement = cborDecode(encodedDeviceEngagement)
        val methods = cborMapExtractArray(deviceEngagement, 2)
        for (method in methods) {
            ret.add(cborEncode(method))
        }
        return ret
    }

    fun getDeviceRetrievalMethodType(encodeDeviceRetrievalMethod: ByteArray): Long {
        val di =
            (cborDecode(encodeDeviceRetrievalMethod) as co.nstant.`in`.cbor.model.Array).dataItems
        return checkedLongValue(di[0])
    }

    @JvmStatic
    fun signPublicKeyWithPrivateKey(
        keyToSignAlias: String,
        keyToSignWithAlias: String
    ): X509Certificate {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)

            /* First note that KeyStore.getCertificate() returns a self-signed X.509 certificate
             * for the key in question. As per RFC 5280, section 4.1 an X.509 certificate has the
             * following structure:
             *
             *   Certificate  ::=  SEQUENCE  {
             *        tbsCertificate       TBSCertificate,
             *        signatureAlgorithm   AlgorithmIdentifier,
             *        signatureValue       BIT STRING  }
             *
             * Conveniently, the X509Certificate class has a getTBSCertificate() method which
             * returns the tbsCertificate blob. So all we need to do is just sign that and build
             * signatureAlgorithm and signatureValue and combine it with tbsCertificate. We don't
             * need a full-blown ASN.1/DER encoder to do this.
             */
            val selfSignedCert =
                ks.getCertificate(keyToSignAlias) as X509Certificate
            val tbsCertificate = selfSignedCert.tbsCertificate
            val keyToSignWithEntry =
                ks.getEntry(keyToSignWithAlias, null)
            val s =
                Signature.getInstance("SHA256withECDSA")
            s.initSign((keyToSignWithEntry as KeyStore.PrivateKeyEntry).privateKey)
            s.update(tbsCertificate)
            val signatureValue = s.sign()

            /* The DER encoding for a SEQUENCE of length 128-65536 - the length is updated below.
             *
             * We assume - and test for below - that the final length is always going to be in
             * this range. This is a sound assumption given we're using 256-bit EC keys.
             */
            val sequence = byteArrayOf(
                0x30, 0x82.toByte(), 0x00, 0x00
            )

            /* The DER encoding for the ECDSA with SHA-256 signature algorithm:
             *
             *   SEQUENCE (1 elem)
             *      OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA
             *      algorithm with SHA256)
             */
            val signatureAlgorithm = byteArrayOf(
                0x30,
                0x0a,
                0x06,
                0x08,
                0x2a,
                0x86.toByte(),
                0x48,
                0xce.toByte(),
                0x3d,
                0x04,
                0x03,
                0x02
            )

            /* The DER encoding for a BIT STRING with one element - the length is updated below.
             *
             * We assume the length of signatureValue is always going to be less than 128. This
             * assumption works since we know ecdsaWithSHA256 signatures are always 69, 70, or
             * 71 bytes long when DER encoded.
             */
            val bitStringForSignature = byteArrayOf(0x03, 0x00, 0x00)

            // Calculate sequence length and set it in |sequence|.
            val sequenceLength = (tbsCertificate.size
                    + signatureAlgorithm.size
                    + bitStringForSignature.size
                    + signatureValue.size)
            check(!(sequenceLength < 128 || sequenceLength > 65535)) { "Unexpected sequenceLength $sequenceLength" }
            sequence[2] = (sequenceLength shr 8).toByte()
            sequence[3] = (sequenceLength and 0xff).toByte()

            // Calculate signatureValue length and set it in |bitStringForSignature|.
            val signatureValueLength = signatureValue.size + 1
            check(signatureValueLength < 128) {
                ("Unexpected signatureValueLength "
                        + signatureValueLength)
            }
            bitStringForSignature[1] = signatureValueLength.toByte()

            // Finally concatenate everything together.
            val baos = ByteArrayOutputStream()
            baos.write(sequence)
            baos.write(tbsCertificate)
            baos.write(signatureAlgorithm)
            baos.write(bitStringForSignature)
            baos.write(signatureValue)
            val resultingCertBytes = baos.toByteArray()
            val cf =
                CertificateFactory.getInstance("X.509")
            val bais =
                ByteArrayInputStream(resultingCertBytes)
            cf.generateCertificate(bais) as X509Certificate
        } catch (e: Exception) {
            // including IOException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, CertificateException
            throw IllegalStateException("Error signing key with private key", e)
        }
    }

    // This returns a SessionTranscript which satisfy the requirement
    // that the uncompressed X and Y coordinates of the key for the
    // mDL's ephemeral key-pair appear somewhere in the encoded
    // DeviceEngagement.
    //
    // TODO: rename to buildFakeSessionTranscript().
    //
    @JvmStatic
    fun buildSessionTranscript(ephemeralKeyPair: KeyPair): ByteArray? {
        // Make the coordinates appear in an already encoded bstr - this
        // mimics how the mDL COSE_Key appear as encoded data inside the
        // encoded DeviceEngagement
        var baos = ByteArrayOutputStream()
        try {
            val w = (ephemeralKeyPair.public as ECPublicKey).w
            // X and Y are always positive so for interop we remove any leading zeroes
            // inserted by the BigInteger encoder.
            val x = stripLeadingZeroes(w.affineX.toByteArray())
            val y = stripLeadingZeroes(w.affineY.toByteArray())
            baos.write(byteArrayOf(42))
            baos.write(x)
            baos.write(y)
            baos.write(byteArrayOf(43, 44))
        } catch (e: IOException) {
            e.printStackTrace()
            return null
        }
        val blobWithCoords = baos.toByteArray()
        val encodedDeviceEngagementItem = cborBuildTaggedByteString(
            cborEncode(
                CborBuilder()
                    .addArray()
                    .add(blobWithCoords)
                    .end()
                    .build().first()
            )
        )
        val encodedEReaderKeyItem =
            cborBuildTaggedByteString(cborEncodeString("doesn't matter"))
        baos = ByteArrayOutputStream()
        try {
            val handoverSelectBytes = byteArrayOf(0x01, 0x02, 0x03)
            val handover: DataItem = CborBuilder()
                .addArray()
                .add(handoverSelectBytes)
                .add(SimpleValue.NULL)
                .end()
                .build().first()
            CborEncoder(baos).encode(
                CborBuilder()
                    .addArray()
                    .add(encodedDeviceEngagementItem)
                    .add(encodedEReaderKeyItem)
                    .add(handover)
                    .end()
                    .build()
            )
        } catch (e: CborException) {
            e.printStackTrace()
            return null
        }
        return baos.toByteArray()
    }

    /**
     * Helper to determine the length of a single encoded CBOR data item.
     *
     *
     * This is used for handling 18013-5:2021 L2CAP data where messages are not separated
     * by any framing.
     *
     * @param data data with a single encoded CBOR data item and possibly more
     * @return -1 if no single encoded CBOR data item could be found, otherwise the length of the
     * CBOR data that was decoded.
     */
    @JvmStatic
    fun cborGetLength(data: ByteArray?): Int {
        val bais = ByteArrayInputStream(data)
        val dataItem = try {
            CborDecoder(bais).decodeNext()
        } catch (e: CborException) {
            return -1
        }
        return if (dataItem == null) {
            -1
        } else cborEncode(dataItem).size
    }

    /**
     * Extracts the first CBOR data item from a stream of bytes.
     *
     *
     * If a data item was found, returns the bytes and removes it from the given output stream.
     *
     * @param pendingDataBaos A [ByteArrayOutputStream] with incoming bytes which must all
     * be valid CBOR.
     * @return the bytes of the first CBOR data item or `null` if not enough bytes have
     * been received.
     */
    @JvmStatic
    fun cborExtractFirstDataItem(pendingDataBaos: ByteArrayOutputStream): ByteArray? {
        val pendingData = pendingDataBaos.toByteArray()
        val dataItemLength = cborGetLength(pendingData)
        if (dataItemLength == -1) {
            return null
        }
        val dataItemBytes = ByteArray(dataItemLength)
        System.arraycopy(pendingDataBaos.toByteArray(), 0, dataItemBytes, 0, dataItemLength)
        pendingDataBaos.reset()
        pendingDataBaos.write(pendingData, dataItemLength, pendingData.size - dataItemLength)
        return dataItemBytes
    }

    @JvmStatic
    fun uuidToBytes(uuid: UUID): ByteArray {
        val data = ByteBuffer.allocate(16)
        data.order(ByteOrder.BIG_ENDIAN)
        data.putLong(uuid.mostSignificantBits)
        data.putLong(uuid.leastSignificantBits)
        return data.array()
    }

    @JvmStatic
    fun uuidFromBytes(bytes: ByteArray): UUID {
        check(bytes.size == 16) { "Expected 16 bytes, found ${bytes.size}" }
        val data = ByteBuffer.wrap(bytes, 0, 16)
        data.order(ByteOrder.BIG_ENDIAN)
        return UUID(data.getLong(0), data.getLong(8))
    }

    /**
     * Version comparison method for mdoc versions.
     *
     *
     * This compares mdoc version strings and returns a negative number if the first version
     * is considered less than the second version, 0 if they are considered equal, and positive
     * otherwise.
     *
     *
     * For example, called with `mdocVersionCompare("1.0", "1.1")` will return
     * a negative number.
     *
     * @param a a version string, for example "1.0"
     * @param b another version string, for example "1.1"
     * @return a positive number, negative number, or 0.
     */
    @JvmStatic
    fun mdocVersionCompare(a: String, b: String): Int {
        // TODO: this just lexicographically compares the strings as ISO 18013-5 doesn't currently
        //   define how to compare version strings.
        return a.compareTo(b)
    }

    // Returns how many bytes should be used for values in the Server2Client and
    // Client2Server characteristics.
    @JvmStatic
    fun bleCalculateAttributeValueSize(mtuSize: Int): Int {
        val characteristicValueSize: Int
        if (mtuSize > 515) {
            // Bluetooth Core specification Part F section 3.2.9 says "The maximum length of
            // an attribute value shall be 512 octets". ... this is enforced in Android as
            // of Android 13 with the effect being that the application only sees the first
            // 512 bytes.
            w(
                TAG, String.format(
                    Locale.US, "MTU size is %d, using 512 as "
                            + "characteristic value size", mtuSize
                )
            )
            characteristicValueSize = 512
        } else {
            characteristicValueSize = mtuSize - 3
            w(
                TAG, String.format(
                    Locale.US, "MTU size is %d, using %d as "
                            + "characteristic value size", mtuSize, characteristicValueSize
                )
            )
        }
        return characteristicValueSize
    }

    @JvmStatic
    fun createEphemeralKeyPair(curve: EcCurve): KeyPair {
        val stdName = when (curve) {
            EcCurve.P256 -> "secp256r1"
            EcCurve.P384 -> "secp384r1"
            EcCurve.P521 -> "secp521r1"
            EcCurve.BRAINPOOLP256R1 -> "brainpoolP256r1"
            EcCurve.BRAINPOOLP320R1 -> "brainpoolP320r1"
            EcCurve.BRAINPOOLP384R1 -> "brainpoolP384r1"
            EcCurve.BRAINPOOLP512R1 -> "brainpoolP512r1"
            EcCurve.X25519 -> "X25519"
            EcCurve.ED25519 -> "Ed25519"
            EcCurve.X448 -> "X448"
            EcCurve.ED448 -> "Ed448"
        }
        return try {
            val kpg: KeyPairGenerator
            if (stdName == "X25519") {
                kpg = KeyPairGenerator.getInstance(
                    "X25519",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                kpg.initialize(XDHParameterSpec(XDHParameterSpec.X25519))
            } else if (stdName == "Ed25519") {
                kpg = KeyPairGenerator.getInstance(
                    "Ed25519",
                    BouncyCastleProvider.PROVIDER_NAME
                )
            } else if (stdName == "X448") {
                kpg = KeyPairGenerator.getInstance(
                    "X448",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                kpg.initialize(XDHParameterSpec(XDHParameterSpec.X448))
            } else if (stdName == "Ed448") {
                kpg = KeyPairGenerator.getInstance(
                    "Ed448",
                    BouncyCastleProvider.PROVIDER_NAME
                )
            } else {
                kpg = KeyPairGenerator.getInstance(
                    "EC",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                kpg.initialize(ECGenParameterSpec(stdName))
            }
            kpg.generateKeyPair()
        } catch (e: Exception) {
            // any exception, such as NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException
            throw IllegalStateException("Error generating ephemeral key-pair", e)
        }
    }

    /*
                Extension functions that are used inside this Util object
     */

    // DataItem casting helpers, "castTo_"
    private fun DataItem.castToMap() = castTo(Map::class.java, this)
    private fun DataItem.castToByteString() = castTo(ByteString::class.java, this)
    private fun DataItem.castToSimpleValue() = castTo(SimpleValue::class.java, this)
    private fun DataItem.castToNumber() = castTo(Number::class.java, this)
    private fun DataItem.castToUnicodeString() = castTo(UnicodeString::class.java, this)
    private fun DataItem.castToArray() = castTo(co.nstant.`in`.cbor.model.Array::class.java, this)

    // type converters "to_"
    private fun String.toUnicodeString() = UnicodeString(this)
    private fun Long.toIntegerNumber() =
        if (this >= 0) UnsignedInteger(this) else NegativeInteger(this)
}