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
import com.android.identity.crypto.X509CertChain
import com.android.identity.document.Document
import com.android.identity.securearea.KeyAttestation
import kotlinx.datetime.Instant

/**
 * An mdoc credential, according to [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html),
 * which can be stored in the DirectAccess applet. This credential makes use of the [DirectAccess]
 * class to integrate with the applet.
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
     * @param asReplacementFor the credential this credential will replace, if not null
     * @param domain the domain of the credential
     * @param docType the docType of the credential
     * @param documentSlot the slot in the Direct Access applet that the document associated with
     *                     this credential is stored in
     */
    constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String,
        docType: String,
        documentSlot: Int
    ) : super(document, asReplacementFor, domain) {
        this.docType = docType
        this.documentSlot = documentSlot

        DirectAccess.createCredential(this.documentSlot).let {
            signingCert = it.first
            encryptedPresentationData = it.second
        }

        // Only the leaf constructor should add the credential to the document.
        if (this::class == DirectAccessCredential::class) {
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
        documentSlot = dataItem["documentSlot"].asNumber.toInt()
        encryptedPresentationData = dataItem["encryptedPresentationData"].asBstr
        signingCert = X509CertChain.fromDataItem(dataItem["signingCert"])
    }

    /**
     * The docType of the credential as defined in
     * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
     */
    val docType: String

    /**
     * The attestation for the key associated with this credential.
     *
     * The application should send this attestation to the issuer which should create
     * issuer-provided data (if using ISO/IEC 18013-5:2021 this would include the MSO).
     * Once received, the application should call [Credential.certify] to certify
     * the [Credential].
     */
    val attestation: KeyAttestation
        get() {
            return KeyAttestation(signingCert.certificates.first().ecPublicKey, signingCert)
        }

    val documentSlot: Int
    private var encryptedPresentationData: ByteArray
    private val signingCert: X509CertChain

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("docType", docType)
        builder.put("documentSlot", documentSlot)
        builder.put("encryptedPresentationData", encryptedPresentationData)
        builder.put("signingCert", signingCert.toDataItem())
    }

    // Provisions credential data for a specific signing key request.
    //
    // The |credentialData| parameter must be CBOR conforming to the following CDDL:
    //
    //   CredentialData = {
    //     "docType": tstr, // todo remove once applet is updated
    //     "issuerNameSpaces": IssuerNameSpaces,
    //     "issuerAuth" : IssuerAuth,
    //     "readerAccess" : ReaderAccess // todo update applet for name change to "authorizedReaderRoots"
    //   }
    //
    //   IssuerNameSpaces = {
    //     NameSpace => [ + IssuerSignedItemBytes ]
    //   }
    //
    //   ReaderAccess = [ * COSE_Key ]
    //
    // This data will be stored on the Secure Area and used for MDOC presentations
    // using NFC data transfer in low-power mode.
    //
    // The `readerAccess` field contains a list of keys used for implementing
    // reader authentication. If this list is non-empty, reader authentication
    // is not required. Otherwise the request must be be signed and the request is
    // authenticated if, and only if, a public key from the X.509 certificate
    // chain for the key signing the request exists in the `readerAccess` list.
    //
    // If reader authentication fails, the returned DeviceResponse shall return
    // error code 10 for the requested docType in the "documentErrors" field.
    override fun certify(
        issuerProvidedAuthenticationData: ByteArray,
        validFrom: Instant,
        validUntil: Instant
    ) {
        // update presentation package
        encryptedPresentationData = DirectAccess.certifyCredential(documentSlot,
            issuerProvidedAuthenticationData, encryptedPresentationData)
        // TODO add applet functionality such that validFrom and validUntil are passed to the applet
        // and considered when presenting
        super.certify(issuerProvidedAuthenticationData, validFrom, validUntil)
    }

    /**
     * Sets the credential as the active credential in the direct access applet (ie. this credential
     * would be the one used during presentation).
     */
    fun setAsActiveCredential() {
        DirectAccess.setActiveCredential(documentSlot, encryptedPresentationData)
    }
}
