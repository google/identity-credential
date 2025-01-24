package com.android.identity.sdjwt.credential

import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.credential.Credential
import com.android.identity.document.Document

class KeylessSdJwtVcCredential : Credential, SdJwtVcCredential {
    override lateinit var vct: String
        private set

    /**
     * Constructs a new [KeyBoundSdJwtVcCredential].
     *
     * @param document the document to add the credential to.
     * @param asReplacementFor the credential this credential will replace, if not null
     * @param domain the domain of the credential
     * @param vct the Verifiable Credential Type.
     */
    constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String,
        vct: String,
    ) : super(document, asReplacementFor, domain) {
        this.vct = vct
        // Only the leaf constructors for keyless credentials should add the credential to
        // the document.
        check (this::class == KeylessSdJwtVcCredential::class)
        addToDocument()
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * [deserialize] providing actual serialized data must be called before using this object.
     *
     * @param document the [Document] that the credential belongs to.
     */
    constructor(document: Document) : super(document)

    override suspend fun deserialize(dataItem: DataItem) {
        vct = dataItem["vct"].asTstr
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("vct", vct)
    }
}