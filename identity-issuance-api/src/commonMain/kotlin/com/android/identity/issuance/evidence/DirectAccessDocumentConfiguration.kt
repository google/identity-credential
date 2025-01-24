package com.android.identity.issuance.evidence

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.document.NameSpacedData

@CborSerializable
data class DirectAccessDocumentConfiguration(
    /**
     * The mdoc DocType.
     */
    val docType: String,

    /**
     * Static data for use with [DirectAccessCredential] instances.
     */
    val staticData: NameSpacedData,
)
