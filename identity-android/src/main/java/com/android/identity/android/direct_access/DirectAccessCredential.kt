/*
 * Copyright 2025 The Android Open Source Project
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
package com.android.identity.android.direct_access

import android.os.Build
import androidx.annotation.RequiresApi
import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.credential.Credential
import com.android.identity.credential.CredentialFactory
import com.android.identity.crypto.X509CertChain
import com.android.identity.document.Document
import com.android.identity.document.DocumentStore
import com.android.identity.securearea.KeyAttestation
import kotlinx.datetime.Instant

/**
 * An mdoc credential, according to
 * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html), which can be
 * stored in the DirectAccess applet. This credential makes use of the
 * [DirectAccess] class to integrate with the applet.
 *
 * Creation of a [DirectAccessCredential] is very similar to any other
 * [Credential] with the following exceptions:
 *
 * First, a slot must be reserved in the Direct Access applet for the [Document]
 * this credential is associated with. This can be done using
 * [DirectAccess.allocateDocumentSlot]. Once allocated, the slot must be passed
 * into the [DirectAccessCredential] constructor when creating new credentials.
 *
 * Secondly, certifying the credential requires the following format for
 * `issuerProvidedAuthenticationData`:
 *
 * The |issuerProvidedAuthenticationData| parameter must be CBOR conforming to
 * the following CDDL:
 *  ```
 *   issuerProvidedAuthenticationData = {
 *     "docType": tstr, // TODO: remove once applet is updated
 *     "issuerNameSpaces": IssuerNameSpaces,
 *     "issuerAuth" : IssuerAuth,
 *     "readerAccess" : ReaderAccess // TODO: update applet for name change to "authorizedReaderRoots"
 *   }
 *
 *   IssuerNameSpaces = {
 *     NameSpace => [ + IssuerSignedItemBytes ]
 *   }
 *
 *   ReaderAccess = [ * COSE_Key ]
 *   ```
 *
 * This data will be stored on the Secure Area and used for MDOC presentations
 * using NFC data transfer in low-power mode.
 *
 * The `readerAccess` field contains a list of keys used for implementing
 * reader authentication. If this list is empty, reader authentication
 * is not required. Otherwise the request must be be signed and the request is
 * authenticated if, and only if, a public key from the X.509 certificate
 * chain for the key signing the request exists in the `readerAccess` list.
 *
 * If reader authentication fails, the returned DeviceResponse shall return
 * error code 10 for the requested docType in the "documentErrors" field.
 *
 * Lastly, in order to use the credential, it must be set as the active credential
 * in the Direct Access applet using [setAsActiveCredential] once the credential
 * is certified.
 */
@RequiresApi(Build.VERSION_CODES.P)
class DirectAccessCredential: Credential {
    companion object {
        private const val TAG = "DirectAccessCredential"
    }

    /**
     * Constructs a new [DirectAccessCredential].
     *
     * @param document the document to add the credential to.
     * @param asReplacementForIdentifier identifier of the credential this credential will replace,
     *      if not null
     * @param domain the domain of the credential
     * @param docType the docType of the credential
     * @param documentSlot the slot in the Direct Access applet that the document
     *      associated with this credential is stored in
     */
    constructor(
        document: Document,
        asReplacementForIdentifier: String?,
        domain: String,
        docType: String,
        documentSlot: Int
    ) : super(document, asReplacementForIdentifier, domain) {
        this.docType = docType
        this.documentSlot = documentSlot

        DirectAccess.createCredential(this.documentSlot).let {
            signingCert = it.first
            encryptedPresentationData = it.second
        }
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * [deserialize] providing actual serialized data must be called before
     * using this object.
     *
     * @param document the [Document] that the credential belongs to.
     */
    constructor(
        document: Document
    ) : super(document) {}

    /**
     * Constructs a Credential from serialized data, ie. the inverse of
     * [addSerializedData].
     *
     * This is required for all [Credential] implementations since it's used by
     * [CredentialFactory.createCredential] when loading a [Document] instance
     * from disk. Since the credential is serialized by the [Document] and stored
     * in [DocumentStore] in its serialized CBOR form, creation of a
     * [DirectAccessCredential] via deserialization does not require
     * integration with [DirectAccess].
     *
     * @param document the [Document] that the credential belongs to.
     * @param dataItem the serialized data.
     */
    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        docType = dataItem["docType"].asTstr
        documentSlot = dataItem["documentSlot"].asNumber.toInt()
        encryptedPresentationData = dataItem["encryptedPresentationData"].asBstr
        signingCert = X509CertChain.fromDataItem(dataItem["signingCert"])
    }

    /**
     * The docType of the credential as defined in
     * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
     */
    lateinit var docType: String

    /**
     * The attestation for the key associated with this credential.
     *
     * The application should send this attestation to the issuer which should
     * create issuer-provided data (if using ISO/IEC 18013-5:2021 this would
     * include the MSO). Once received, the application should call
     * [Credential.certify] to certify the [Credential].
     */
    val attestation: KeyAttestation
        get() {
            return KeyAttestation(signingCert.certificates.first().ecPublicKey, signingCert)
        }

    var documentSlot: Int = 0
    private lateinit var encryptedPresentationData: ByteArray
    private lateinit var signingCert: X509CertChain

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("docType", docType)
        builder.put("documentSlot", documentSlot)
        builder.put("encryptedPresentationData", encryptedPresentationData)
        builder.put("signingCert", signingCert.toDataItem())
    }

    override fun onDocumentDeletion() {
        DirectAccess.clearDocumentSlot(documentSlot)
    }

    override suspend fun certify(
        issuerProvidedAuthenticationData: ByteArray,
        validFrom: Instant,
        validUntil: Instant
    ) {
        // update presentation package
        encryptedPresentationData = DirectAccess.certifyCredential(documentSlot,
            issuerProvidedAuthenticationData, encryptedPresentationData)
        // TODO: Add applet functionality such that validFrom and validUntil are passed to the applet
        // and considered when presenting
        super.certify(issuerProvidedAuthenticationData, validFrom, validUntil)
    }

    /**
     * Sets the credential as the active credential in the direct access applet
     * (ie. this credential would be the one used during presentation).
     */
    fun setAsActiveCredential() {
        DirectAccess.setActiveCredential(documentSlot, encryptedPresentationData)
    }
}
