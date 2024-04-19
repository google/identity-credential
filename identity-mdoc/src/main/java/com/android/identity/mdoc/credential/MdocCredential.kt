/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.mdoc.credential

import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.credential.Credential
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.document.Document
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea

/**
 * An mdoc credential, according to [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
 *
 * In this type, the key in [SecureAreaBoundCredential] plays the role of *DeviceKey* and the
 * issuer-signed data includes the *Mobile Security Object* which includes the authentication
 * key and is signed by the issuer. This is used for anti-cloning and to return data signed
 * by the device.
 */
class MdocCredential : SecureAreaBoundCredential {
    companion object {
        private const val TAG = "MdocCredential"
    }

    /**
     * Constructs a new [MdocCredential].
     *
     * @param document the document to add the credential to.
     * @param asReplacementFor the credential this credential will replace, if not null
     * @param domain the domain of the credential
     * @param secureArea the secure area for the authentication key associated with this credential.
     * @param createKeySettings the settings used to create new credentials.
     * @param docType the docType of the credential
     */
    constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String,
        secureArea: SecureArea,
        createKeySettings: CreateKeySettings,
        docType: String
    ) : super(document, asReplacementFor, domain, secureArea, createKeySettings) {
        this.docType = docType
        // Only the leaf constructor should add the credential to the document.
        if (this::class == MdocCredential::class) {
            addToDocument()
        }
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * @param document the [Document] that the credential belongs to.
     * @param dataItem the serialized data.
     */
    constructor(
        document: Document,
        dataItem: DataItem,
    ) : super(document, dataItem) {
        docType = dataItem["docType"].asTstr
    }

    /**
     * The docType of the credential as defined in
     * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
     */
    val docType: String

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("docType", docType)
    }
}
