package com.android.identity.crypto

import com.android.identity.asn1.ASN1
import com.android.identity.asn1.ASN1BitString
import com.android.identity.asn1.ASN1Boolean
import com.android.identity.asn1.ASN1Encoding
import com.android.identity.asn1.ASN1Integer
import com.android.identity.asn1.ASN1Object
import com.android.identity.asn1.ASN1ObjectIdentifier
import com.android.identity.asn1.ASN1OctetString
import com.android.identity.asn1.ASN1Sequence
import com.android.identity.asn1.ASN1Set
import com.android.identity.asn1.ASN1String
import com.android.identity.asn1.ASN1TagClass
import com.android.identity.asn1.ASN1TaggedObject
import com.android.identity.asn1.ASN1Time
import com.android.identity.asn1.OID
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.DataItem
import com.android.identity.util.Logger
import kotlinx.datetime.Instant
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * A data type for a X509 certificate.
 *
 * @param encodedCertificate the bytes of the X.509 certificate.
 */
class X509Cert(
    val encodedCertificate: ByteArray
) {
    override fun equals(other: Any?): Boolean = other is X509Cert &&
            encodedCertificate contentEquals other.encodedCertificate

    override fun hashCode(): Int = encodedCertificate.contentHashCode()

    /**
     * Gets an [DataItem] with the encoded X.509 certificate.
     */
    fun toDataItem(): DataItem = Bstr(encodedCertificate)

    /**
     * Encode this certificate in PEM format
     *
     * @return a PEM encoded string.
     */
    @OptIn(ExperimentalEncodingApi::class)
    fun toPem(): String {
        val sb = StringBuilder()
        sb.append("-----BEGIN CERTIFICATE-----\n")
        sb.append(Base64.Mime.encode(encodedCertificate))
        sb.append("\n-----END CERTIFICATE-----\n")
        return sb.toString()
    }

    /**
     * Checks if the certificate was signed with a given key.
     *
     * @param publicKey the key to check the signature with.
     * @return `true` if the certificate was signed with the given key, `false` otherwise.
     */
    fun verify(publicKey: EcPublicKey): Boolean {
        val ecSignature = when (signatureAlgorithm) {
            Algorithm.ES256,
            Algorithm.ES384,
            Algorithm.ES512 -> {
                EcSignature.fromDerEncoded(publicKey.curve.bitSize, signature)
            }
            Algorithm.EDDSA -> {
                val len = signature.size
                val r = signature.sliceArray(IntRange(0, len/2 - 1))
                val s = signature.sliceArray(IntRange(len/2, len - 1))
                EcSignature(r, s)
            }
            else -> throw IllegalArgumentException("Unsupported algorithm $signatureAlgorithm")
        }
        return Crypto.checkSignature(
            publicKey,
            tbsCertificate,
            signatureAlgorithm,
            ecSignature
        )
    }

    private val parsedCert: ASN1Sequence by lazy {
        ASN1.decode(encodedCertificate)!! as ASN1Sequence
    }

    private val tbsCert: ASN1Sequence by lazy {
        parsedCert.elements[0] as ASN1Sequence
    }

    /**
     * The certificate version.
     *
     * This returns the encoded value and for X.509 Version 3 Certificate this value is 2.
     */
    val version: Int
        get() {
            val child = ASN1.decode((tbsCert.elements[0] as ASN1TaggedObject).content)
            val versionCode = (child as ASN1Integer).toLong().toInt()
            return versionCode
        }

    /**
     * The certificate serial number.
     */
    val serialNumber: ASN1Integer
        get() = (tbsCert.elements[1] as ASN1Integer)

    /**
     * The subject of the certificate.
     */
    val subject: X500Name
        get() = parseName(tbsCert.elements[5] as ASN1Sequence)

    /**
     * The issuer of the certificate.
     */
    val issuer: X500Name
        get() = parseName(tbsCert.elements[3] as ASN1Sequence)

    /**
     * The point in time where the certificate is valid from.
     */
    val validityNotBefore: Instant
        get() = ((tbsCert.elements[4] as ASN1Sequence).elements[0] as ASN1Time).value

    /**
     * The point in time where the certificate is valid until.
     */
    val validityNotAfter: Instant
        get() = ((tbsCert.elements[4] as ASN1Sequence).elements[1] as ASN1Time).value

    /**
     * The bytes of TBSCertificate.
     */
    val tbsCertificate: ByteArray
        get() = ASN1.encode(tbsCert)

    /**
     * The certificate signature.
     */
    val signature: ByteArray
        get() = (parsedCert.elements[2] as ASN1BitString).value

    /**
     * The signature algorithm for the certificate as OID string.
     */
    val signatureAlgorithmOid: String
        get() {
            val algorithmIdentifier = parsedCert.elements[1] as ASN1Sequence
            return (algorithmIdentifier.elements[0] as ASN1ObjectIdentifier).oid
        }

    /**
     * The signature algorithm for the certificate.
     *
     * @throws IllegalArgumentException if the OID for the algorithm doesn't correspond with a signature algorithm
     *   value in the [Algorithm] enumeration.
     */
    val signatureAlgorithm: Algorithm
        get() {
            return when (signatureAlgorithmOid) {
                OID.SIGNATURE_ECDSA_SHA256.oid -> Algorithm.ES256
                OID.SIGNATURE_ECDSA_SHA384.oid -> Algorithm.ES384
                OID.SIGNATURE_ECDSA_SHA512.oid -> Algorithm.ES512
                OID.ED25519.oid, OID.ED448.oid -> Algorithm.EDDSA  // ED25519, ED448
                OID.SIGNATURE_RS256.oid -> Algorithm.RS256
                OID.SIGNATURE_RS384.oid -> Algorithm.RS384
                OID.SIGNATURE_RS512.oid -> Algorithm.RS512
                else -> throw IllegalArgumentException(
                    "Unexpected algorithm OID $signatureAlgorithmOid")
            }
        }


    /**
     * The public key in the certificate, as an Elliptic Curve key.
     *
     * Note that this is only supported for curves in [Crypto.supportedCurves].
     *
     * @throws IllegalStateException if the public key for the certificate isn't an EC key or
     * its EC curve isn't supported by the platform.
     */
    val ecPublicKey: EcPublicKey
        get() {
            val subjectPublicKeyInfo = tbsCert.elements[6] as ASN1Sequence
            val algorithmIdentifier = subjectPublicKeyInfo.elements[0] as ASN1Sequence
            val algorithmOid = (algorithmIdentifier.elements[0] as ASN1ObjectIdentifier).oid
            val curve = when (algorithmOid) {
                // https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1
                OID.EC_PUBLIC_KEY.oid -> {
                    val ecCurveString = (algorithmIdentifier.elements[1] as ASN1ObjectIdentifier).oid
                    when (ecCurveString) {
                        "1.2.840.10045.3.1.7" -> EcCurve.P256
                        "1.3.132.0.34" -> EcCurve.P384
                        "1.3.132.0.35" -> EcCurve.P521
                        "1.3.36.3.3.2.8.1.1.7" -> EcCurve.BRAINPOOLP256R1
                        "1.3.36.3.3.2.8.1.1.9" -> EcCurve.BRAINPOOLP320R1
                        "1.3.36.3.3.2.8.1.1.11" -> EcCurve.BRAINPOOLP384R1
                        "1.3.36.3.3.2.8.1.1.13" -> EcCurve.BRAINPOOLP512R1
                        else -> throw IllegalStateException("Unexpected curve OID $ecCurveString")
                    }
                }
                "1.3.101.110" -> EcCurve.X25519
                "1.3.101.111" -> EcCurve.X448
                "1.3.101.112" -> EcCurve.ED25519
                "1.3.101.113" -> EcCurve.ED448
                else -> throw IllegalStateException("Unexpected OID $algorithmOid")
            }
            val keyMaterial = (subjectPublicKeyInfo.elements[1] as ASN1BitString).value
            return when (curve) {
                EcCurve.P256,
                EcCurve.P384,
                EcCurve.P521,
                EcCurve.BRAINPOOLP256R1,
                EcCurve.BRAINPOOLP320R1,
                EcCurve.BRAINPOOLP384R1,
                EcCurve.BRAINPOOLP512R1 -> {
                    EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(curve, keyMaterial)
                }
                EcCurve.ED25519,
                EcCurve.X25519,
                EcCurve.ED448,
                EcCurve.X448 -> {
                    EcPublicKeyOkp(curve, keyMaterial)
                }
            }
        }

    /**
     * The OIDs for X.509 extensions which are marked as critical.
     */
    val criticalExtensionOIDs: Set<String>
        get() = getExtensionOIDs(true)

    /**
     * The OIDs for X.509 extensions which are not marked as critical.
     */
    val nonCriticalExtensionOIDs: Set<String>
        get() = getExtensionOIDs(false)

    private fun getExtensionsSeq(): ASN1Sequence? {
        for (elem in tbsCert.elements) {
            if (elem is ASN1TaggedObject &&
                elem.cls == ASN1TagClass.CONTEXT_SPECIFIC &&
                elem.enc == ASN1Encoding.CONSTRUCTED &&
                elem.tag == 0x03) {
                return ASN1.decode(elem.content) as ASN1Sequence
            }
        }
        return null
    }

    private fun getExtensionOIDs(getCritical: Boolean): Set<String> {
        val extSeq = getExtensionsSeq() ?: return emptySet()
        val ret = mutableSetOf<String>()
        for (ext in extSeq.elements) {
            ext as ASN1Sequence
            val isCritical = if (ext.elements.size == 3) {
                (ext.elements[1] as ASN1Boolean).value
            } else {
                false
            }
            if ((isCritical && getCritical) || (!isCritical && !getCritical)) {
                ret.add((ext.elements[0] as ASN1ObjectIdentifier).oid)
            }
        }
        return ret
    }

    /**
     * Gets the bytes of a X.509 extension.
     *
     * @param oid the OID to get the extension from
     * @return the bytes of the extension or `null` if no such extension exist.
     */
    fun getExtensionValue(oid: String): ByteArray? {
        val extSeq = getExtensionsSeq() ?: return null
        for (ext in extSeq.elements) {
            ext as ASN1Sequence
            if ((ext.elements[0] as ASN1ObjectIdentifier).oid == oid) {
                if (ext.elements.size == 3) {
                    return (ext.elements[2] as ASN1OctetString).value
                } else {
                    return (ext.elements[1] as ASN1OctetString).value
                }
            }
        }
        return null
    }

    /**
     * The subject key identifier (OID 2.5.29.14), or `null` if not present in the certificate.
     */
    val subjectKeyIdentifier: ByteArray?
        get() {
            val extVal = getExtensionValue(OID.X509_EXTENSION_SUBJECT_KEY_IDENTIFIER.oid) ?: return null
            return (ASN1.decode(extVal) as ASN1OctetString).value
        }

    /**
     * The authority key identifier (OID 2.5.29.35), or `null` if not present in the certificate.
     */
    val authorityKeyIdentifier: ByteArray?
        get() {
            val extVal = getExtensionValue(OID.X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER.oid) ?: return null
            val seq = ASN1.decode(extVal) as ASN1Sequence
            val taggedObject = seq.elements[0] as ASN1TaggedObject
            check(taggedObject.cls == ASN1TagClass.CONTEXT_SPECIFIC) { "Expected context-specific tag" }
            check(taggedObject.enc == ASN1Encoding.PRIMITIVE)
            check(taggedObject.tag == 0) { "Expected tag 0" }
            // Note: tags in AuthorityKeyIdentifier are IMPLICIT b/c its definition appear in
            // the implicitly tagged ASN.1 module, see RFC 5280 Appendix A.2.
            //
            return taggedObject.content
        }

    /**
     * The key usage (OID 2.5.29.15) or the empty set if not present.
     */
    val keyUsage: Set<X509KeyUsage>
        get() {
            val extVal = getExtensionValue(OID.X509_EXTENSION_KEY_USAGE.oid) ?: return emptySet()
            check(criticalExtensionOIDs.contains(OID.X509_EXTENSION_KEY_USAGE.oid))
            return X509KeyUsage.decodeSet(ASN1.decode(extVal) as ASN1BitString)
        }

    companion object {
        private const val TAG = "X509Cert"

        /**
         * Creates a [X509Cert] from a PEM encoded string.
         *
         * @param pemEncoding the PEM encoded string.
         * @return a new [X509Cert].
         */
        @OptIn(ExperimentalEncodingApi::class)
        fun fromPem(pemEncoding: String): X509Cert {
            val encoded = Base64.Mime.decode(pemEncoding
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .trim())
            return X509Cert(encoded)
        }

        /**
         * Gets a [X509Cert] from a [DataItem].
         *
         * @param dataItem the data item, must have been encoded with [toDataItem].
         * @return the certificate.
         */
        fun fromDataItem(dataItem: DataItem): X509Cert {
            return X509Cert(dataItem.asBstr)
        }
    }

    /**
     * Builder for X.509 certificate.
     */
    class Builder(
        private val publicKey: EcPublicKey,
        private val signingKey: EcPrivateKey,
        private val signatureAlgorithm: Algorithm,
        private val serialNumber: ASN1Integer,
        private val subject: X500Name,
        private val issuer: X500Name,
        private val validFrom: Instant,
        private val validUntil: Instant,
    ) {
        private data class Extension(
            val critical: Boolean,
            val value: ByteArray
        )
        private val extensions = mutableMapOf<String, Extension>()

        private var includeSubjectKeyIdentifierFlag: Boolean = false
        private var includeAuthorityKeyIdentifierAsSubjectKeyIdentifierFlag: Boolean = false

        fun addExtension(oid: String, critical: Boolean, value: ByteArray): Builder {
            extensions.put(oid, Extension(critical, value))
            return this
        }

        /**
         * Generate and include the Subject Key Identifier extension .
         *
         * The extension will be marked as non-critical.
         *
         * @param `true` to include the Subject Key Identifier, `false to not.
         */
        fun includeSubjectKeyIdentifier(value: Boolean = true): Builder {
            includeSubjectKeyIdentifierFlag = value
            return this
        }

        /**
         * Set the Authority Key Identifier with keyIdentifier set to the same value as the
         * Subject Key Identifier.
         *
         * This is only meaningful when creating a self-signed certificate.
         *
         * The extension will be marked as non-critical.
         *
         * @param `true` to include the Authority Key Identifier, `false to not.
         */
        fun includeAuthorityKeyIdentifierAsSubjectKeyIdentifier(value: Boolean = true): Builder {
            includeAuthorityKeyIdentifierAsSubjectKeyIdentifierFlag = value
            return this
        }

        /**
         * Sets Authority Key Identifier extension to the given value.
         *
         * The extension will be marked as non-critical.
         */
        fun setAuthorityKeyIdentifierToCertificate(certificate: X509Cert): Builder {
            addExtension(
                OID.X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER.oid,
                false,
                // Note: AuthorityKeyIdentifier uses IMPLICIT tags
                ASN1.encode(
                    ASN1Sequence(listOf(
                        ASN1TaggedObject(
                            ASN1TagClass.CONTEXT_SPECIFIC,
                            ASN1Encoding.PRIMITIVE,
                            0,
                            certificate.subjectKeyIdentifier!!
                        )
                    ))
                )
            )
            return this
        }

        fun setKeyUsage(keyUsage: Set<X509KeyUsage>): Builder {
            addExtension(
                OID.X509_EXTENSION_KEY_USAGE.oid,
                true,
                ASN1.encode(X509KeyUsage.encodeSet(keyUsage))
            )
            return this
        }

        fun setBasicConstraints(
            ca: Boolean,
            pathLenConstraint: Int?,
        ): Builder {
            val seq = mutableListOf<ASN1Object>(
                ASN1Boolean(ca)
            )
            if (pathLenConstraint != null) {
                seq.add(ASN1Integer(pathLenConstraint.toLong()))
            }
            addExtension(
                OID.X509_EXTENSION_BASIC_CONSTRAINTS.oid,
                true,
                ASN1.encode(ASN1Sequence(seq))
            )
            return this
        }

        fun build(): X509Cert {
            val signatureAlgorithmSeq = signatureAlgorithm.getSignatureAlgorithmSeq(signingKey.curve)

            val subjectPublicKey = when (publicKey) {
                is EcPublicKeyDoubleCoordinate -> {
                    publicKey.asUncompressedPointEncoding
                }
                is EcPublicKeyOkp -> {
                    publicKey.x
                }
            }
            val subjectPublicKeyInfoSeq = ASN1Sequence(listOf(
                publicKey.curve.getCurveAlgorithmSeq(),
                ASN1BitString(0, subjectPublicKey)
            ))

            if (validFrom.nanosecondsOfSecond != 0) {
                Logger.w(TAG, "Truncating fractional seconds of validFrom")
            }
            if (validUntil.nanosecondsOfSecond != 0) {
                Logger.w(TAG, "Truncating fractional seconds of validUntil")
            }
            val validFromTruncated = Instant.fromEpochSeconds(validFrom.epochSeconds)
            val validUntilTruncated = Instant.fromEpochSeconds(validUntil.epochSeconds)
            val tbsCertObjs = mutableListOf(
                ASN1TaggedObject(
                    ASN1TagClass.CONTEXT_SPECIFIC,
                    ASN1Encoding.CONSTRUCTED,
                    0,
                    ASN1.encode(ASN1Integer(2L))
                ),
                serialNumber,
                signatureAlgorithmSeq,
                generateName(issuer),
                ASN1Sequence(listOf(
                    ASN1Time(validFromTruncated),
                    ASN1Time(validUntilTruncated)
                )),
                generateName(subject),
                subjectPublicKeyInfoSeq,
            )

            if (includeSubjectKeyIdentifierFlag) {
                // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
                addExtension(
                    OID.X509_EXTENSION_SUBJECT_KEY_IDENTIFIER.oid,
                    false,
                    ASN1.encode(ASN1OctetString(Crypto.digest(Algorithm.INSECURE_SHA1, subjectPublicKey)))
                )
            }

            if (includeAuthorityKeyIdentifierAsSubjectKeyIdentifierFlag) {
                addExtension(
                    OID.X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER.oid,
                    false,
                    // Note: AuthorityKeyIdentifier uses IMPLICIT tags
                    ASN1.encode(
                        ASN1Sequence(listOf(
                            ASN1TaggedObject(
                                ASN1TagClass.CONTEXT_SPECIFIC,
                                ASN1Encoding.PRIMITIVE,
                                0,
                                Crypto.digest(Algorithm.INSECURE_SHA1, subjectPublicKey)
                            )
                        ))
                    )
                )
            }

            if (extensions.size > 0) {
                val extensionObjs = mutableListOf<ASN1Object>()
                for ((oid, ext) in extensions) {
                    extensionObjs.add(
                        if (ext.critical) {
                            ASN1Sequence(
                                listOf(
                                    ASN1ObjectIdentifier(oid),
                                    ASN1Boolean(true),
                                    ASN1OctetString(ext.value)
                                )
                            )
                        } else {
                            ASN1Sequence(
                                listOf(
                                    ASN1ObjectIdentifier(oid),
                                    ASN1OctetString(ext.value)
                                )
                            )
                        }
                    )
                }
                tbsCertObjs.add(ASN1TaggedObject(
                    ASN1TagClass.CONTEXT_SPECIFIC,
                    ASN1Encoding.CONSTRUCTED,
                    3,
                    ASN1.encode(ASN1Sequence(extensionObjs))
                ))
            }

            val tbsCert = ASN1Sequence(tbsCertObjs)

            val encodedTbsCert = ASN1.encode(tbsCert)
            val signature = Crypto.sign(
                signingKey,
                signatureAlgorithm,
                encodedTbsCert
            )
            val encodedSignature = when (signatureAlgorithm) {
                Algorithm.ES256,
                Algorithm.ES384,
                Algorithm.ES512 -> signature.toDerEncoded()
                Algorithm.EDDSA -> signature.r + signature.s
                else -> throw IllegalArgumentException("Unsupported signature algorithm $signatureAlgorithm")
            }
            val cert = ASN1Sequence(listOf(
                tbsCert,
                signatureAlgorithmSeq,
                ASN1BitString(0, encodedSignature),
            ))
            return X509Cert(ASN1.encode(cert))
        }
    }
}

private fun Algorithm.getSignatureAlgorithmSeq(signingKeyCurve: EcCurve): ASN1Sequence {
    val signatureAlgorithmOid = when (this) {
        Algorithm.ES256 -> "1.2.840.10045.4.3.2"
        Algorithm.ES384 -> "1.2.840.10045.4.3.3"
        Algorithm.ES512 -> "1.2.840.10045.4.3.4"
        Algorithm.EDDSA -> {
            when (signingKeyCurve) {
                EcCurve.ED25519 -> "1.3.101.112"
                EcCurve.ED448 -> "1.3.101.113"
                else -> throw IllegalArgumentException(
                    "Unsupported curve ${signingKeyCurve} for $this")
            }
        }
        else -> {
            throw IllegalArgumentException("Unsupported signature algorithm $this")
        }
    }
    return ASN1Sequence(listOf(ASN1ObjectIdentifier(signatureAlgorithmOid)))
}

private fun EcCurve.getCurveAlgorithmSeq(): ASN1Sequence {
    val (algOid, paramOid) = when (this) {
        EcCurve.P256 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_P256.oid)
        EcCurve.P384 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_P384.oid)
        EcCurve.P521 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_P521.oid)
        EcCurve.BRAINPOOLP256R1 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_BRAINPOOLP256R1.oid)
        EcCurve.BRAINPOOLP320R1 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_BRAINPOOLP320R1.oid)
        EcCurve.BRAINPOOLP384R1 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_BRAINPOOLP384R1.oid)
        EcCurve.BRAINPOOLP512R1 -> Pair(OID.EC_PUBLIC_KEY.oid, OID.EC_CURVE_BRAINPOOLP512R1.oid)
        EcCurve.X25519 -> Pair(OID.X25519.oid, null)
        EcCurve.X448 -> Pair(OID.X448.oid, null)
        EcCurve.ED25519 -> Pair(OID.ED25519.oid, null)
        EcCurve.ED448 -> Pair(OID.ED448.oid, null)
    }
    if (paramOid != null) {
        return ASN1Sequence(listOf(
            ASN1ObjectIdentifier(algOid),
            ASN1ObjectIdentifier(paramOid)
        ))
    }
    return ASN1Sequence(listOf(
        ASN1ObjectIdentifier(algOid),
    ))
}

private fun parseName(obj: ASN1Sequence): X500Name {
    val components = mutableMapOf<String, ASN1String>()
    for (elem in obj.elements) {
        val dnSet = elem as ASN1Set
        val typeAndValue = dnSet.elements[0] as ASN1Sequence
        val oidObject = typeAndValue.elements[0] as ASN1ObjectIdentifier
        val nameObject = typeAndValue.elements[1] as ASN1String
        components.put(oidObject.oid, nameObject)
    }
    return X500Name(components)
}

private fun generateName(name: X500Name): ASN1Sequence {
    val objs = mutableListOf<ASN1Object>()
    for ((oid, value) in name.components) {
        objs.add(
            ASN1Set(listOf(
                ASN1Sequence(listOf(
                    ASN1ObjectIdentifier(oid),
                    value
                ))
            ))
        )
    }
    return ASN1Sequence(objs)
}
