package com.android.identity.mdoc.response

import com.android.identity.document.Document
import com.android.identity.document.DocumentMetadata
import com.android.identity.document.NameSpacedData
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.isEmpty
import kotlin.concurrent.Volatile

class TestDocumentMetadata private constructor(
    data: ByteString?,
    private val saveFn: suspend (data: ByteString) -> Unit
) : DocumentMetadata {
    override val provisioned: Boolean
        get() = false
    override val displayName: String
        get() = "Test Doc"
    override val typeDisplayName: String
        get() = "Test"
    override val cardArt: ByteString?
        get() = null
    override val issuerLogo: ByteString?
        get() = null

    @Volatile
    override var nameSpacedData: NameSpacedData
        private set

    init {
        nameSpacedData = if (data == null || data.isEmpty()) {
            NameSpacedData.Builder().build()
        } else {
            NameSpacedData.fromEncodedCbor(data.toByteArray())
        }
    }

    suspend fun setNameSpacedData(nameSpacedData: NameSpacedData) {
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