package com.android.identity.sdjwt.credential

import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.document.Document
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea

/**
 * A SD-JWT VC credential, according to [draft-ietf-oauth-sd-jwt-vc-03]
 * (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) that is bound to a key
 * stored in a [SecureArea].
 */
class KeyBoundSdJwtVcCredential : SecureAreaBoundCredential, SdJwtVcCredential {
    companion object {
        private const val TAG = "SdJwtVcCredential"

        suspend fun create(
            document: Document,
            asReplacementForIdentifier: String?,
            domain: String,
            secureArea: SecureArea,
            vct: String,
            createKeySettings: CreateKeySettings
        ): KeyBoundSdJwtVcCredential {
            return KeyBoundSdJwtVcCredential(
                document,
                asReplacementForIdentifier,
                domain,
                secureArea,
                vct
            ).apply {
                generateKey(createKeySettings)
            }
        }
    }

    /**
     * The Verifiable Credential Type - or `vct` - as defined in section 3.2.2.1.1 of
     * [draft-ietf-oauth-sd-jwt-vc-03]
     * (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
     */
    override lateinit var vct: String
        private set

    /**
     * Constructs a new [KeyBoundSdJwtVcCredential].
     *
     * [generateKey] providing [CreateKeySettings] must be called before using this object.
     *
     * @param document the document to add the credential to.
     * @param asReplacementForIdentifier identifier of the credential this credential will replace,
     *     if not null
     * @param domain the domain of the credential
     * @param secureArea the secure area for the authentication key associated with this credential.
     * @param vct the Verifiable Credential Type.
     */
    private constructor(
        document: Document,
        asReplacementForIdentifier: String?,
        domain: String,
        secureArea: SecureArea,
        vct: String,
    ) : super(document, asReplacementForIdentifier, domain, secureArea) {
        this.vct = vct
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * [deserialize] providing serialized data must be called before using this object.
     *
     * @param document the [Document] that the credential belongs to.
     */
    constructor(
        document: Document
    ) : super(document) {
    }

    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        vct = dataItem["vct"].asTstr
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("vct", vct)
    }
}