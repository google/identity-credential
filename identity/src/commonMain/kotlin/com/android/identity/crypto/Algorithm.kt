package com.android.identity.crypto

/**
 * Algorithm identifiers.
 *
 * All algorithm identifiers are from the
 * [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml).
 */
enum class Algorithm(val coseAlgorithmIdentifier: Int) {
    /** Used to indicate the algorithm is unset.  */
    UNSET(Int.MAX_VALUE),

    /** The algorithm identifier for signatures using ECDSA with SHA-256  */
    ES256(-7),

    /** The algorithm identifier for signatures using ECDSA with SHA-384  */
    ES384(-35),

    /** The algorithm identifier for signatures using ECDSA with SHA-512  */
    ES512(-36),

    /** The algorithm identifier for signatures using EdDSA  */
    EDDSA(-8),

    /** SHA-1 Hash (insecure, shouldn't be used) */
    INSECURE_SHA1(-14),

    /** SHA-2 256-bit Hash */
    SHA256(-16),

    /** SHA-2 384-bit Hash */
    SHA384(-43),

    /** SHA-2 512-bit Hash */
    SHA512(-44),

    /** HMAC w/ SHA-256 */
    HMAC_SHA256(5),

    /** HMAC w/ SHA-384 */
    HMAC_SHA384(6),

    /** HMAC w/ SHA-512 */
    HMAC_SHA512(7),

    /** AES-GCM mode w/ 128-bit key, 128-bit tag */
    A128GCM(1),

    /** AES-GCM mode w/ 192-bit key, 128-bit tag */
    A192GCM(2),

    /** AES-GCM mode w/ 256-bit key, 128-bit tag */
    A256GCM(3),

    /**
     * Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM,
     * the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
     *
     * Note that this value is still TBD and the proposed value is from
     * [Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing and Encryption (COSE)](https://www.ietf.org/archive/id/draft-ietf-cose-hpke-07.html#IANA)
     *
     */
    HPKE_BASE_P256_SHA256_AES128GCM(35),

    /** RSASSA-PKCS1-v1_5 using SHA-256 */
    RS256(-257),

    /** RSASSA-PKCS1-v1_5 using SHA-384 */
    RS384(-258),

    /** RSASSA-PKCS1-v1_5 using SHA-512 */
    RS512(-259),

    ;

    /**
     * Converts the given algorithm to a corresponding value from the
     * [JSON Web Signature and Encryption Algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
     * registry.
     *
     * @throws IllegalArgumentException if there is no corresponding value.
     */
    val jwseAlgorithmIdentifier: String
        get() = coseToJwse[this] ?: throw IllegalArgumentException("No JWSE Algorithm for $this")

    /**
     * Converts the given algorithm to a corresponding value from the
     * [Named Information Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg)
     * registry.
     *
     * @throws IllegalArgumentException if there is no corresponding value.
     */
    val hashAlgorithmIdentifier: String
        get() = coseToHash[this] ?: throw IllegalArgumentException("No hash algorithm identifier for $this")

    companion object {
        private val coseToJwse = mapOf(
            ES256 to "ES256",
            ES384 to "ES384",
            ES512 to "ES512",
            EDDSA to "EdDSA",
            HMAC_SHA256 to "HS256",
            HMAC_SHA384 to "HS384",
            HMAC_SHA512 to "HS512",
            A128GCM to "A128GCM",
            A192GCM to "A192GCM",
            A256GCM to "A256GCM",
        )

        private val jwseToCose = mapOf(
            "ES256" to ES256,
            "ES384" to ES384,
            "ES512" to ES512,
            "EdDSA" to EDDSA,
            "HS256" to HMAC_SHA256,
            "HS384" to HMAC_SHA384,
            "HS512" to HMAC_SHA512,
            "A128GCM" to A128GCM,
            "A192GCM" to A192GCM,
            "A256GCM" to A256GCM,
        )

        private val coseToHash = mapOf(
            SHA256 to "sha-256",
            SHA384 to "sha-384",
            SHA512 to "sha-512",
        )

        private val hashToCose = mapOf(
            "sha-256" to SHA256,
            "sha-384" to SHA384,
            "sha-512" to SHA512,
        )

        /**
         * Creates a [Algorithm] from an identifier.
         *
         * @throws IllegalArgumentException if the identifier isn't in the [Algorithm] enumeration.
         */
        fun fromInt(coseAlgorithmIdentifier: Int): Algorithm =
            Algorithm.values().find { it.coseAlgorithmIdentifier == coseAlgorithmIdentifier }
                ?: throw IllegalArgumentException("No algorithm with COSE identifier $coseAlgorithmIdentifier")

        /**
         * Creates an [Algorithm] with a value corresponding to the given value from the
         * [JSON Web Signature and Encryption Algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
         * registry.
         *
         * @throws IllegalArgumentException if there is no corresponding value.
         */
        fun fromJwseAlgorithmIdentifier(jwseAlgorithmIdentifier: String): Algorithm =
            jwseToCose[jwseAlgorithmIdentifier]
                ?: throw IllegalArgumentException("No COSE Algorithm for $jwseAlgorithmIdentifier")

        /**
         * Creates an [Algorithm] with a value corresponding to the given value from the
         * [Named Information Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg)
         * registry.
         *
         * @throws IllegalArgumentException if there is no corresponding value.
         */
        fun fromHashAlgorithmIdentifier(hashAlgorithmIdentifier: String): Algorithm =
            hashToCose[hashAlgorithmIdentifier]
                ?: throw IllegalArgumentException("No hash algorithm for $hashAlgorithmIdentifier")
    }

}