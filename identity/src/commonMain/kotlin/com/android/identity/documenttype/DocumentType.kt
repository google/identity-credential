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

package com.android.identity.documenttype

import com.android.identity.cbor.DataItem

/**
 * Class representing the metadata of a Document Type
 *
 * Currently mdoc and W3C Verifiable Document data models
 * are supported. More document formats may be added in
 * the future.
 *
 * A Document Type has different attributes. Each attribute
 * has a displayName which is short (1-3 words) and suitable
 * for displaying in the UI. There is also a description
 * which is a longer description of the attribute, typically
 * no more than one paragraph.
 *
 * @param displayName the name suitable for display, e.g. "Driving License".
 * @param cannedRequests sample [DocumentCannedRequest] for the Document Type.
 * @param mdocDocumentType metadata of an mDoc Document Type (optional).
 * @param vcDocumentType metadata of a W3C VC Document Type (optional).
 *
 */
class DocumentType private constructor(
    val displayName: String,
    val cannedRequests: List<DocumentCannedRequest>,
    val mdocDocumentType: MdocDocumentType?,
    val vcDocumentType: VcDocumentType?
) {

    /**
     * Builder class for class [DocumentType]
     *
     * @param displayName the name suitable for display of the Document Type.
     * @param mdocBuilder a builder for the [MdocDocumentType].
     * @param vcBuilder a builder for the [VcDocumentType].
     */
    data class Builder(
        val displayName: String,
        var mdocBuilder: MdocDocumentType.Builder? = null,
        var vcBuilder: VcDocumentType.Builder? = null
    ) {
        private val sampleRequests = mutableListOf<DocumentCannedRequest>()

        /**
         * Initialize the [mdocBuilder].
         *
         * @param mdocDocType the DocType of the mDoc.
         */
        fun addMdocDocumentType(mdocDocType: String) = apply {
            mdocBuilder = MdocDocumentType.Builder(mdocDocType)
        }

        /**
         * Initialize the [vcBuilder].
         *
         * @param vcType the type of the VC Document Type.
         */
        fun addVcDocumentType(vcType: String) = apply {
            vcBuilder = VcDocumentType.Builder(vcType)
        }

        /**
         * Add an attribute for both mDoc and VC, using the same identifier.
         *
         * @param type the datatype of this attribute.
         * @param identifier the identifier of this attribute for both mDoc and VC.
         * @param displayName a name suitable for display of the attribute.
         * @param description a description of the attribute.
         * @param mandatory indication whether the mDoc attribute is mandatory.
         * @param mdocNamespace the namespace of the mDoc attribute.
         * @param icon the icon, if available.
         * @param sampleValue a sample value for the attribute, if available.
         */
        fun addAttribute(
            type: DocumentAttributeType,
            identifier: String,
            displayName: String,
            description: String,
            mandatory: Boolean,
            mdocNamespace: String,
            icon: Icon? = null,
            sampleValue: DataItem? = null,
        ) = apply {
            addMdocAttribute(type, identifier, displayName, description, mandatory,
                mdocNamespace, icon, sampleValue)
            addVcAttribute(type, identifier, displayName, description, icon, sampleValue)
        }

        /**
         * Add an attribute for both mDoc and VC, using a different identifier.
         *
         * @param type the datatype of this attribute.
         * @param mdocIdentifier the identifier of this attribute for mDoc.
         * @param vcIdentifier the identifier of this attribute for VC.
         * @param displayName a name suitable for display of the attribute.
         * @param description a description of the attribute.
         * @param mandatory indication whether the mDoc attribute is mandatory.
         * @param mdocNamespace the namespace of the mDoc attribute.
         * @param icon the icon, if available.
         * @param sampleValue a sample value for the attribute, if available.
         */
        fun addAttribute(
            type: DocumentAttributeType,
            mdocIdentifier: String,
            vcIdentifier: String,
            displayName: String,
            description: String,
            mandatory: Boolean,
            mdocNamespace: String,
            icon: Icon? = null,
            sampleValue: DataItem? = null
        ) = apply {
            addMdocAttribute(
                type,
                mdocIdentifier,
                displayName,
                description,
                mandatory,
                mdocNamespace,
                icon,
                sampleValue
            )
            addVcAttribute(type, vcIdentifier, displayName, description, icon, sampleValue)
        }

        /**
         * Add an attribute for mDoc only.
         *
         * @param type the datatype of this attribute.
         * @param identifier the identifier of this attribute.
         * @param displayName a name suitable for display of the attribute.
         * @param description a description of the attribute.
         * @param mandatory indication whether the mDoc attribute is mandatory.
         * @param mdocNamespace the namespace of the mDoc attribute.
         * @param icon the icon, if available.
         * @param sampleValue a sample value for the attribute, if available.
         */
        fun addMdocAttribute(
            type: DocumentAttributeType,
            identifier: String,
            displayName: String,
            description: String,
            mandatory: Boolean,
            mdocNamespace: String,
            icon: Icon? = null,
            sampleValue: DataItem? = null
        ) = apply {
            mdocBuilder?.addDataElement(
                mdocNamespace,
                type,
                identifier,
                displayName,
                description,
                mandatory,
                icon,
                sampleValue
            ) ?: throw Exception("The mDoc Document Type was not initialized")
        }

        /**
         * Add an attribute for VC only.
         *
         * @param type the datatype of this attribute.
         * @param identifier the identifier of this attribute.
         * @param displayName a name suitable for display of the attribute.
         * @param description a description of the attribute.
         * @param icon the icon, if available.
         * @param sampleValue a sample value for the attribute, if available.
         */
        fun addVcAttribute(
            type: DocumentAttributeType,
            identifier: String,
            displayName: String,
            description: String,
            icon: Icon? = null,
            sampleValue: DataItem? = null
        ) = apply {
            vcBuilder?.addClaim(type, identifier, displayName, description, icon, sampleValue)
                ?: throw Exception("The VC Document Type was not initialized")
        }

        /**
         * Adds a sample request to the document.
         *
         * @param id an identifier for the request.
         * @param displayName a short name explaining the request.
         * @param mdocDataElements the mdoc data elements in the request, per namespace, with
         * the intent to retain value. If the list of a namespace is empty, all defined data
         * elements will be included with intent to retain set to false.
         * @param vcClaims the VC claims in the request. If the list is empty, all defined
         * claims will be included.
         */
        fun addSampleRequest(
            id: String,
            displayName: String,
            mdocDataElements: Map<String, Map<String, Boolean>>? = null,
            vcClaims: List<String>? = null
        ) = apply {
            val mdocRequest = if (mdocDataElements == null) {
                null
            } else {
                val nsRequests = mutableListOf<MdocNamespaceRequest>()
                for ((namespace, dataElements) in mdocDataElements) {
                    val mdocNsBuilder = mdocBuilder!!.namespaces[namespace]!!
                    val map = mutableMapOf<MdocDataElement, Boolean>()
                    if (dataElements.isEmpty()) {
                        mdocNsBuilder.dataElements.values.map { map.put(it, false) }
                    } else {
                        for ((dataElement, intentToRetain) in dataElements) {
                            map.put(mdocNsBuilder.dataElements[dataElement]!!, intentToRetain)
                        }
                    }
                    nsRequests.add(MdocNamespaceRequest(namespace, map))
                }
                MdocCannedRequest(mdocBuilder!!.docType, nsRequests)
            }
            val vcRequest = if (vcClaims == null) {
                null
            } else {
                val claims = if (vcClaims.isEmpty()) {
                    vcBuilder!!.claims.values.toList()
                } else {
                    val list = mutableListOf<DocumentAttribute>()
                    for (claimName in vcClaims) {
                        list.add(vcBuilder!!.claims[claimName]!!)
                    }
                    list
                }
                VcCannedRequest(vcBuilder!!.type, claims)
            }
            sampleRequests.add(DocumentCannedRequest(id, displayName, mdocRequest, vcRequest))
        }

        /**
         * Build the [DocumentType].
         */
        fun build() = DocumentType(
            displayName,
            sampleRequests,
            mdocBuilder?.build(),
            vcBuilder?.build())
    }
}