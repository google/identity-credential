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
package com.android.identity.credential

import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.document.Document
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.SecureArea

/**
 * Base class for credentials bound to a [SecureArea].
 *
 * This associates a key from a [SecureArea] to a [Credential]
 */
open class SecureAreaBoundCredential : Credential {
    companion object {
        private const val TAG = "SecureAreaBoundCredential"
        // This is to avoid collisions with other uses of the Secure Area.
        private const val SECURE_AREA_ALIAS_PREFIX = "SecureAreaBoundCredential_"
    }

    /**
     * Constructs a new [SecureAreaBoundCredential].
     *
     * [generateKey] providing [CreateKeySettings] must be called before using this object.
     *
     * @param document the document to add the credential to.
     * @param asReplacementFor the credential this credential will replace, if not null
     * @param domain the domain of the credential
     * @param secureArea the secure area for the authentication key associated with this credential.
     */
    constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String,
        secureArea: SecureArea,
    ) : super(document, asReplacementFor, domain) {
        this.secureArea = secureArea
    }

    /**
     * Generates an authentication key to which this credential is bound and adds the credential
     * to the document.
     *
     * @param createKeySettings [CreateKeySettings] that are used to create the key.
     */
    suspend fun generateKey(createKeySettings: CreateKeySettings) {
        document.checkLocked()
        alias = secureArea.createKey(null, createKeySettings)
        addToDocument()
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * @param document the [Document] that the credential belongs to.
     *
     * [deserialize] must be called before using this object.
     */
    constructor(
        document: Document,
    ) : super(document)

    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        alias = dataItem["alias"].asTstr
        val secureAreaIdentifier = dataItem["secureAreaIdentifier"].asTstr
        secureArea = document.secureAreaRepository.getImplementation(secureAreaIdentifier)
            ?: throw IllegalStateException("Unknown Secure Area $secureAreaIdentifier")
    }

    /**
     * The secure area for the authentication key associated with this credential.
     *
     * This can be used together with the alias returned by [alias].
     */
    lateinit var secureArea: SecureArea
        private set

    /**
     * The alias for the authentication key associated with this credential.
     *
     * This can be used together with the [SecureArea] returned by [secureArea]
     */
    lateinit var alias: String

    override suspend fun isInvalidated(): Boolean = secureArea.getKeyInvalidated(alias)

    /**
     * The attestation for the [SecureArea] key associated with this credential.
     *
     * The application should send this attestation to the issuer which should create
     * issuer-provided data (if using ISO/IEC 18013-5:2021 this would include the MSO).
     * Once received, the application should call [Credential.certify] to certify
     * the [Credential].
     */
    suspend fun getAttestation(): KeyAttestation = secureArea.getKeyInfo(alias).attestation

    override suspend fun delete() {
        document.checkLocked()
        secureArea.deleteKey(alias)
        super.delete()
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        document.checkLocked()
        super.addSerializedData(builder)
        builder.put("secureAreaIdentifier", secureArea.identifier)
            .put("alias", alias)
    }
}