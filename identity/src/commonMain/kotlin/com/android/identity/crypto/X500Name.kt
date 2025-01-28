package com.android.identity.crypto

import com.android.identity.asn1.ASN1
import com.android.identity.asn1.ASN1String
import com.android.identity.asn1.ASN1StringTag
import com.android.identity.asn1.OID
import com.android.identity.util.toHex

/**
 * This represents a X.501 Name as used for X.509 certificates.
 *
 * @property components a map from OID to the value.
 */
class X500Name(val components: Map<String, ASN1String>) {

    override fun equals(other: Any?): Boolean = other is X500Name && name == other.name

    override fun hashCode(): Int = name.hashCode()

    /**
     *  The X.501 Name encoded according to
     *  [RFC 2253](https://datatracker.ietf.org/doc/html/rfc2253).
     */
    val name: String
        get() {
            val sb = StringBuilder()
            for (oid in components.keys.reversed()) {
                if (!sb.isEmpty()) {
                    sb.append(',')
                }
                val value = components[oid]!!
                val oidName = knownOids.get(oid)
                if (oidName != null) {
                    sb.append("$oidName=${value.value}")
                } else {
                    // From https://datatracker.ietf.org/doc/html/rfc2253#section-2.4
                    //
                    //   If the AttributeValue is of a type which does not have a string
                    //   representation defined for it, then it is simply encoded as an
                    //   octothorpe character ('#' ASCII 35) followed by the hexadecimal
                    //   representation of each of the bytes of the BER encoding of the X.500
                    //   AttributeValue.  This form SHOULD be used if the AttributeType is of
                    //   the dotted-decimal form.
                    //
                    sb.append("$oid=#${ASN1.encode(value).toHex()}")
                }
            }
            return sb.toString()
        }

    companion object {
        // From RFC 5280 Annex A, could add more as needed.
        //
        private val knownOids = mapOf<String, String>(
            OID.COMMON_NAME.oid to "CN",
            OID.COUNTRY_NAME.oid to "C",
            OID.LOCALITY_NAME.oid to "L",
            OID.STATE_OR_PROVINCE_NAME.oid to "ST",
            OID.ORGANIZATION_NAME.oid to "O",
            OID.ORGANIZATIONAL_UNIT_NAME.oid to "OU",
            OID.SERIAL_NUMBER.oid to "SN",
        )

        private val knownNames: Map<String, String> by lazy {
            knownOids.entries.associateBy({it.value}, {it.key})
        }

        /**
         * Builds a [X500Name] from the encoded form.
         *
         * For example, if passing the string `CN=David,ST=US-MA,O=Google,OU=Android,C=US` a
         * [X500Name] instance with the the [X500Name.components] property containing the
         * following entries
         *
         * ```
         * val components = mapOf<String, ASN1String>(
         *   "2.5.4.6" to ASN1String("US"),
         *   "2.5.4.11" to ASN1String("Android"),
         *   "2.5.4.10" to ASN1String("Google"),
         *   "2.5.4.8" to ASN1String("US-MA"),
         *   "2.5.4.3" to ASN1String("David"),
         * )
         * ```
         *
         * @param name an encoded form of a X.501 Name according to
         *   [RFC 2253](https://datatracker.ietf.org/doc/html/rfc2253).
         * @throws IllegalArgumentException if one of the keys isn't known.
         */
        fun fromName(name: String): X500Name {
            val components = mutableMapOf<String, ASN1String>()
            for (part in name.split(",").reversed()) {
                val pos = part.indexOf('=')
                if (pos < 0) {
                    throw IllegalArgumentException("No equal sign found in component")
                }
                val key = part.substring(0, pos)
                val value = part.substring(pos + 1)
                val oidForKey = knownNames[key]
                if (oidForKey == null) {
                    throw IllegalArgumentException("Unknown OID for $key")
                }
                components.put(oidForKey, ASN1String(value))
            }
            return X500Name(components)
        }
    }
}