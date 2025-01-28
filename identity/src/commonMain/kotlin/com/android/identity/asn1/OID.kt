package com.android.identity.asn1

/**
 * Registry of known OIDs.
 *
 * @property oid the OID.
 * @property description a textual description of the OID.
 */
enum class OID(
    val oid: String,
    val description: String
) {
    EC_PUBLIC_KEY("1.2.840.10045.2.1", "Elliptic curve public key cryptography"),
    EC_CURVE_P256("1.2.840.10045.3.1.7", "NIST Curve P-256"),
    EC_CURVE_P384("1.3.132.0.34", "EC Curve P-384"),
    EC_CURVE_P521("1.3.132.0.35", "EC Curve P-521"),
    EC_CURVE_BRAINPOOLP256R1("1.3.36.3.3.2.8.1.1.7", "EC Curve Brainpool P256r1"),
    EC_CURVE_BRAINPOOLP320R1("1.3.36.3.3.2.8.1.1.9", "EC Curve Brainpool P320r1"),
    EC_CURVE_BRAINPOOLP384R1("1.3.36.3.3.2.8.1.1.11", "EC Curve Brainpool P384r1"),
    EC_CURVE_BRAINPOOLP512R1("1.3.36.3.3.2.8.1.1.13", "EC Curve Brainpool P512r1"),

    SIGNATURE_ECDSA_SHA256("1.2.840.10045.4.3.2", "ECDSA coupled with SHA-256"),
    SIGNATURE_ECDSA_SHA384("1.2.840.10045.4.3.3", "ECDSA coupled with SHA-384"),
    SIGNATURE_ECDSA_SHA512("1.2.840.10045.4.3.4", "ECDSA coupled with SHA-512"),
    SIGNATURE_RS256("1.2.840.113549.1.1.11", "PKCS #1 v1.5 signature algorithm with SHA256 and RSA"),
    SIGNATURE_RS384("1.2.840.113549.1.1.12", "PKCS #1 v1.5 signature algorithm with SHA384 and RSA"),
    SIGNATURE_RS512("1.2.840.113549.1.1.13", "PKCS #1 v1.5 signature algorithm with SHA512 and RSA"),

    X25519("1.3.101.110", "X25519 algorithm used with the Diffie-Hellman operation"),
    X448("1.3.101.111", "X448 algorithm used with the Diffie-Hellman operation"),
    ED25519("1.3.101.112", "Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519"),
    ED448("1.3.101.113", "Edwards-curve Digital Signature Algorithm (EdDSA) Ed448"),

    COMMON_NAME("2.5.4.3", "commonName (X.520 DN component)"),
    SERIAL_NUMBER("2.5.4.5", "serialNumber (X.520 DN component)"),
    COUNTRY_NAME("2.5.4.6", "countryName (X.520 DN component)"),
    LOCALITY_NAME("2.5.4.7", "localityName (X.520 DN component)"),
    STATE_OR_PROVINCE_NAME("2.5.4.8", "stateOrProvinceName (X.520 DN component)"),
    ORGANIZATION_NAME("2.5.4.10", "organizationName (X.520 DN component)"),
    ORGANIZATIONAL_UNIT_NAME("organizationalUnitName (X.520 DN component)", ""),

    X509_EXTENSION_KEY_USAGE("2.5.29.15", "keyUsage (X.509 extension)"),
    X509_EXTENSION_EXTENDED_KEY_USAGE("2.5.29.37", "extKeyUsage (X.509 extension)"),
    X509_EXTENSION_BASIC_CONSTRAINTS("2.5.29.19", "basicConstraints (X.509 extension)"),
    X509_EXTENSION_SUBJECT_KEY_IDENTIFIER("2.5.29.14", "subjectKeyIdentifier (X.509 extension)"),
    X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER("2.5.29.35", "authorityKeyIdentifier (X.509 extension)"),
    X509_EXTENSION_ISSUER_ALT_NAME("2.5.29.18", "issuerAltName (X.509 extension)"),
    X509_EXTENSION_CRL_DISTRIBUTION_POINTS("2.5.29.31", "cRLDistributionPoints (X.509 extension)"),

    ISO_18013_5_MDL_DS("1.0.18013.5.1.2", "Mobile Driving Licence (mDL) Document Signer (DS)"),

    ;

    companion object {
        private val stringToOid: Map<String, OID> by lazy {
            OID.entries.associateBy({it.oid}, {it})
        }

        fun lookupByOid(oid: String): OID? = stringToOid[oid]
    }
}