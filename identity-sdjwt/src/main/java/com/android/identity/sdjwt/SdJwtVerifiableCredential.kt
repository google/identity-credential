package com.android.identity.sdjwt

import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcSignature
import com.android.identity.sdjwt.presentation.KeyBindingBody
import com.android.identity.sdjwt.presentation.KeyBindingHeader
import com.android.identity.sdjwt.presentation.SdJwtVerifiablePresentation
import com.android.identity.sdjwt.vc.JwtBody
import com.android.identity.sdjwt.vc.JwtHeader
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.SecureArea
import com.android.identity.util.fromBase64Url
import com.android.identity.util.toBase64Url
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.json.JsonElement

/**
 * A selectively-disclosable JWT verifiable credential.
 *
 * It has the following format:
 *
 * <header>.<body>.<signature>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~
 *
 * The header is the base64-encoding of a JSON structure that contains the
 * typ: vc+sd-jwt entry, and an alg entry that specifies how the signature was generated.
 *
 * It is separated from the body by a period. The body is the base64-encoding of a JSON
 * structure that includes the undisclosed (hashed) identity attributes, along with
 * expiration time, and a public key (of the credential holder), and information about the
 * credential issuer.
 *
 * It in turn is separated by a period from the base64-encoded signature created by the
 * issuer.
 *
 * Finally, it includes the base64-encoded disclosures (hash pre-images) of the attributes
 * whose hashes are included in the body. Disclosures are delimited from each other
 * by a tilde (~)
 *
 *  @param header the base64-encoded header of the SD-JWT
 *  @param body the base64-encoded body of the SD-JWT
 *  @param signature the base64-encoded signature (by the issuer, over the header and body)
 *         of the SD-JWT
 *  @param disclosures the disclosures included in the SD-JWT
 */
class SdJwtVerifiableCredential(
    val header: String,
    val body: String,
    val signature: String,
    val disclosures: List<Disclosure>
) {
    override fun toString() = "$header.$body.$signature~${disclosures.joinToString("~", postfix = "~")}"

    /**
     * Create a copy of this SD-JWT that discloses only certain attributes.
     */
    fun discloseOnly(attributes: Set<String>): SdJwtVerifiableCredential {
        val newDisclosures = disclosures
            .filter { it.key in attributes }
        return SdJwtVerifiableCredential(header, body, signature, newDisclosures)
    }

    /**
     * Find out the value of an attribute, if it is contained in this SD-JWT
     *
     * @param attribute the attribute whose value should be obtained
     */
    fun getAttributeValue(attribute: String): JsonElement {
        val matchingDisclosures = disclosures.filter { it.key == attribute }
        if (matchingDisclosures.isEmpty()) {
            throw AttributeNotDisclosedException("attribute $attribute not included in disclosures")
        }

        val disclosure = matchingDisclosures[0]
        val disclosureHash = disclosure.hash

        val disclosureHashes = JwtBody.fromString(body).disclosureHashes

        if (!disclosureHashes.contains(disclosureHash)) {
            throw DisclosureError("attribute $attribute not included in disclosures. Looking for hash $disclosureHash, but couldn't find it")
        }

        return disclosure.value
    }

    val sdHashAlg get() = JwtBody.fromString(body).sdHashAlg

    /**
     * Verify the issuer signature on this SD-JWT. This method constructs the right
     * to-be-verified ByteArray and signature ByteArray, and posses those to a lambda
     * that is supposed to do the actual signature verification. The lambda will also
     * be passed the header and body of the SD-JWT, which can aid in figuring out
     * which key to use when verifying the signature.
     *
     * This method can be used when the Verifier uses non-standard crypto providers and
     * can't use the easier version of [verifyIssuerSignature].
     *
     * @param verify lambda that will have to do the signature verification. It will be
     *        passed:
     *        @param header: JwtHeader the header of the JWT
     *        @param body: JwtBody the body of the JWT
     *        @param toBeVerified ByteArray the ByteArray over which the signature was generated
     *        @param signature ByteArray the signature that needs to be checked
     *        The lambda must return true if the signature verifies, and false otherwise.
     */
    fun verifyIssuerSignature(verify: (JwtHeader, JwtBody, ByteArray, EcSignature) -> Boolean) {
        val headerObj = JwtHeader.fromString(header)
        val bodyObj = JwtBody.fromString(body)

        val toBeVerified = "$header.$body".toByteArray(Charsets.US_ASCII)
        val signature = EcSignature.fromCoseEncoded(signature.fromBase64Url())

        if(!verify(headerObj, bodyObj, toBeVerified, signature)) {
            throw IllegalStateException("Signature verification failed")
        }
    }

    /**
     * Simplified version of [verifyIssuerSignature]. In this version, the default
     * registered crypto provider will be used to check the signature on the SD-JWT.
     * The caller passes in a public key (which presumably was obtained after inspecting
     * the SD-JWT for the 'iss' claim), and the implementation uses the 'alg' parameter
     * in the SD-JWT header to determing the signature algorithm to use.
     */
    fun verifyIssuerSignature(key: EcPublicKey) {
        verifyIssuerSignature { header, _, toBeVerified, signature ->
            Crypto.checkSignature(key, toBeVerified, header.algorithm, signature)
        }
    }

    suspend fun createPresentation(secureArea: SecureArea?,
                           alias: String?,
                           keyUnlockData: KeyUnlockData?,
                           alg: Algorithm,
                           nonce: String,
                           audience: String,
                           creationTime: Instant = Clock.System.now()): SdJwtVerifiablePresentation {
        val (keyBindingHeaderStr, keyBindingBodyStr, signatureStr) =
            if (secureArea != null && alias != null) {
                val keyBindingHeaderStr = KeyBindingHeader(alg).toString()
                val sdHash = Crypto.digest(this.sdHashAlg, toString().toByteArray()).toBase64Url()
                val keyBindingBodyStr = KeyBindingBody(nonce, audience, creationTime, sdHash).toString()

                val toBeSigned = "$keyBindingHeaderStr.$keyBindingBodyStr".toByteArray(Charsets.US_ASCII)
                val signature = secureArea.sign(alias, alg, toBeSigned, keyUnlockData)
                val signatureStr = signature.toCoseEncoded().toBase64Url()
                listOf(keyBindingHeaderStr, keyBindingBodyStr, signatureStr)
            } else {
                // Non-keybound credentials don't need to sign the key binding JWT.
                listOf("", "", "")
            }

        return SdJwtVerifiablePresentation(
            this,
            keyBindingHeaderStr,
            keyBindingBodyStr,
            signatureStr
        )
    }

    companion object {
        fun fromString(sdJwt: String): SdJwtVerifiableCredential {
            val splits = sdJwt.split("~")

            // first item is a JWT
            val jwtSplits = splits[0].split(".")
            if (jwtSplits.size != 3) {
                throw MalformedJwtError("JWT in SD-JWT didn't consist of three parts: ${splits[0]}")
            }

            val (header, body, signature) = jwtSplits

            val digestAlg = JwtBody.fromString(body).sdHashAlg

            val disclosures = splits
                .drop(1) // drop the JWT preceding the disclosures
                .dropLast(1) // drop the last empty segment, created by the trailing ~
                .map { Disclosure(it, digestAlg) }

            return SdJwtVerifiableCredential(header, body, signature, disclosures)
        }
    }

    /**
     * Used when an attribute is not mentioned in the disclosures
     */
    class AttributeNotDisclosedException(message: String): Exception(message)

    /**
     * Used when an attribute is in the disclosures, but doesn't map to a hash
     * in the SD-JWT.
     */
    class DisclosureError(message: String): Exception(message)

    /**
     * Used when a SD-JWT VC can't be parsed from a string
     */
    class MalformedJwtError(message: String): Exception(message)
}