package com.android.identity.preconsent_mdl

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.document.Document
import com.android.identity.document.DocumentMetadata
import com.android.identity.document.NameSpacedData
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.isNotEmpty

class PreconsentDocumentMetadata(
    serializedData: ByteString?,
    private val saveFn: suspend (data: ByteString) -> Unit
): DocumentMetadata {

    private lateinit var data: Data

    init {
        if (serializedData != null && serializedData.isNotEmpty()) {
            data = Data.fromCbor(serializedData.toByteArray())
        }
    }

    override val provisioned: Boolean
        get() = true

    override val displayName: String
        get() = data.displayName

    override val typeDisplayName: String
        get() = data.typeDisplayName

    override val cardArt: ByteString?
        get() = data.cardArt

    override val issuerLogo: ByteString?
        get() = data.issuerLogo

    val namespacedData: NameSpacedData
        get() = data.namespacedData

    override suspend fun documentDeleted() {
    }

    suspend fun init(data: Data) {
        this.data = data
        saveFn(ByteString(data.toCbor()))
    }

    @CborSerializable
    data class Data(
        val displayName: String,
        val typeDisplayName: String,
        val cardArt: ByteString?,
        val issuerLogo: ByteString?,
        val namespacedData: NameSpacedData
    ) {
        companion object
    }

    companion object {
        suspend fun create(
            documentId: String,
            serializedData: ByteString?,
            saveFn: suspend (data: ByteString) -> Unit
        ): PreconsentDocumentMetadata {
            return PreconsentDocumentMetadata(serializedData, saveFn)
        }
    }
}

val Document.preconsentMetadata: PreconsentDocumentMetadata
    get() = metadata as PreconsentDocumentMetadata
