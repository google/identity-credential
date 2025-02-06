package com.android.identity.testapp

import com.android.identity.document.Document
import com.android.identity.document.DocumentMetadata
import com.android.identity.document.NameSpacedData
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.isEmpty

class TestDocumentMetadata private constructor(
    data: ByteString?,
    private val saveFn: suspend (data: ByteString) -> Unit
) : DocumentMetadata {
    override val provisioned: Boolean
        get() = true
    override lateinit var displayName: String
        private set
    override lateinit var typeDisplayName: String
        private set
    override lateinit var cardArt: ByteString
        private set
    override val issuerLogo: ByteString?
        get() = null

    override var nameSpacedData: NameSpacedData
        private set

    init {
        nameSpacedData = if (data == null || data.isEmpty()) {
            NameSpacedData.Builder().build()
        } else {
            NameSpacedData.fromEncodedCbor(data.toByteArray())
        }
    }

    suspend fun initialize(
        displayName: String,
        typeDisplayName: String,
        cardArt: ByteString,
        nameSpacedData: NameSpacedData
    ) {
        this.displayName = displayName
        this.typeDisplayName = typeDisplayName
        this.cardArt = cardArt
        this.nameSpacedData = nameSpacedData
        saveFn(ByteString(nameSpacedData.encodeAsCbor()))
    }

    override suspend fun documentDeleted() {
    }

    companion object {
        suspend fun create(
            documentId: String,
            serializedData: ByteString?,
            saveFn: suspend (data: ByteString) -> Unit
        ): TestDocumentMetadata {
            return TestDocumentMetadata(serializedData, saveFn)
        }
    }
}

val Document.testMetadata: TestDocumentMetadata
    get() = metadata as TestDocumentMetadata