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

import com.android.identity.cbor.Bstr
import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.document.Document
import com.android.identity.document.DocumentStore
import com.android.identity.document.DocumentUtil
import com.android.identity.securearea.SecureArea
import com.android.identity.util.ApplicationData
import com.android.identity.util.Logger
import com.android.identity.util.SimpleApplicationData
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Base class for credentials.
 *
 * When a [Credential] is created, it is not certified. In order to use the [Credential]
 * for presentation, call [Credential.certify] to certify the credential. This is usually
 * done by sending metadata about the [Credential] to the issuer and getting issuer-signed
 * data back, including the validity-period the credential.
 *
 * An unique identifier for the credential is available in the [Credential.identifier]
 * property which is set at credential creation time.
 *
 * Since credentials can be valid for only a limited time, applications are likely wanting
 * to replace them on a regular basis. To this end, the [Credential] class has the
 * [Credential.replacement] and [Credential.replacementFor] properties. For a high-level
 * helper using this infrastructure, see [DocumentUtil.managedCredentialHelper].
 *
 * Each credential has a _domain_ associated with it which is a textual string chosen
 * by the application. This can be used to group credentials together and update a
 * single domain independently of another one. For example, a [Document] may have
 * - 10 [MDocCredential]s for normal use in the domain "mdoc", each requiring user authentication
 *   to present.
 * - 10 [MDocCredential]s for age-attestation in the domain "mdoc_age_attestation" which
 *   are provisioned with only age attributes and the portrait image. These don't require user
 *   authentication to present.
 * At presentation time the application can pick a credential from "mdoc_age_attestation" domain
 * if the verifier's request only includes age attestation. Since user authentication is not
 * required to present these, this could be used to implement a pre-consent flow where the
 * information is shared at the moment the user taps their device against the verifier.
 *
 * A credential may be invalidated and this is tracked in the [Credential.isInvalidated]
 * property. For example this may happen if underlying key material for the credential
 * is no longer usable, see [SecureArea.getKeyInvalidated] for example.
 *
 * [Credential] may be subclassed (for example, see [SecureAreaBoundCredential] and
 * [MdocCredential]) and applications and libraries may bring their own implementations. An
 * application will need to register its implementations with the [CredentialFactory] instance
 * they use with their [DocumentStore] instance.
 *
 * Each concrete implementation of [Credential] must have `constructor(document: Document,
 * dataItem: DataItem)` to construct an instance from serialized data. This is used by
 * [CredentialFactory.createCredential] which is used when loading a [Document] instance from disk
 * and deserializing its [Credential] instances.
 *
 * Most [DocumentStore], [Document], and [Credential] APIs require caller to first
 * obtain a [DocumentStore] lock by running the code that accesses these APIs inside
 * [DocumentStore.withLock] (or a convenience shortcut [Document.withLock]). Note that
 * there is a single lock for all documents and credentials in a [DocumentStore]
 * instance and only a single coroutine can hold the lock at the same time.
 */
open class Credential {
    companion object {
        private const val TAG = "Credential"
        private const val CREDENTIAL_ID_PREFIX = "Credential"

        private var uniqueIdentifierCounter = 0
    }

    /**
     * Constructs a new [Credential].
     *
     * @param document the document to add the credential to.
     * @param asReplacementFor the credential this credential will replace, if not null.
     * @param domain the domain of the credential.
     */
    protected constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String
    ) {
        check(asReplacementFor?.replacement == null) {
            "The given credential already has an existing pending credential intending to replace it"
        }
        this.domain = domain
        this.identifier = createUniqueIdentifier()
        this.document = document
        replacementForIdentifier = asReplacementFor?.identifier
        asReplacementFor?.replacementIdentifier = this.identifier
        _applicationData = SimpleApplicationData { document.requestSave() }
    }

    /**
     * Should be called by derived class either in constructor for a new credential (for keyless
     * credentials) or once the key is generated (for key-bound credentials).
     */
    protected fun addToDocument() {
        credentialCounter = document.addCredential(this)
        document.requestSave()
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * [deserialize] providing actual serialized data must be called before using this object.
     *
     * @param document the [Document] that the credential belongs to.
     */
    protected constructor(
        document: Document,
    ) {
        this.document = document
    }

    /**
     * Initialize this object using serialized data.
     */
    open suspend fun deserialize(dataItem: DataItem) {
        document.checkLocked()
        val applicationDataDataItem = dataItem["applicationData"]
        check(applicationDataDataItem is Bstr) { "applicationData not found or not byte[]" }
        _applicationData = SimpleApplicationData
            .decodeFromCbor(applicationDataDataItem.value) {
                document.requestSave()
            }
        identifier = dataItem["identifier"].asTstr
        domain = dataItem["domain"].asTstr
        usageCount = dataItem["usageCount"].asNumber.toInt()
        isCertified = dataItem["isCertified"].asBoolean

        if (isCertified) {
            _issuerProvidedData = dataItem["data"].asBstr
            _validFrom = Instant.fromEpochMilliseconds(dataItem["validFrom"].asNumber)
            _validUntil = Instant.fromEpochMilliseconds(dataItem["validUntil"].asNumber)
        } else {
            _issuerProvidedData = null
            _validFrom = null
            _validUntil = null
        }

        replacementIdentifier = dataItem.getOrNull("replacementAlias")?.asTstr
        replacementForIdentifier = dataItem.getOrNull("replacementForAlias")?.asTstr

        credentialCounter = dataItem["credentialCounter"].asNumber
    }

    // Creates an alias which is guaranteed to be unique for all time (assuming the system clock
    // only goes forwards)
    private fun createUniqueIdentifier(): String {
        val now = Clock.System.now()
        return "${CREDENTIAL_ID_PREFIX}_${now.epochSeconds}_${now.nanosecondsOfSecond}_${uniqueIdentifierCounter++}"
    }

    /**
     * A stable identifier for the Credential instance.
     */
    lateinit var identifier: String
        private set

    /**
     * The domain of the credential.
     */
    lateinit var domain: String
        private set

    /**
     * How many times the credential has been used in an identity presentation.
     */
    var usageCount = 0
        protected set

    /**
     * Indicates whether the credential has been certified yet.
     */
    var isCertified = false
        protected set

    /**
     * Indicates whether the credential has been invalidated.
     */
    open suspend fun isInvalidated(): Boolean = false

    /**
     * Application specific data.
     *
     * Use this object to store additional data an application may want to associate
     * with the credential. Setters and associated getters are
     * enumerated in the [ApplicationData] interface.
     */
    val applicationData: ApplicationData
        get() = _applicationData
    private lateinit var _applicationData: SimpleApplicationData

    /**
     * The issuer-provided data associated with the credential.
     *
     * @throws IllegalStateException if the credential is not yet certified.
     */
    val issuerProvidedData: ByteArray
        get() = _issuerProvidedData
            ?: throw IllegalStateException("This credential is not yet certified")
    private var _issuerProvidedData: ByteArray? = null

    /**
     * The point in time the issuer-provided data is valid from.
     *
     * @throws IllegalStateException if the credential is not yet certified.
     */
    val validFrom: Instant
        get() = _validFrom
            ?: throw IllegalStateException("This credential is not yet certified")
    private var _validFrom: Instant? = null

    /**
     * The point in time the issuer-provided data is valid until.
     *
     * @throws IllegalStateException if the credential is not yet certified.
     */
    val validUntil: Instant
        get() = _validUntil
            ?: throw IllegalStateException("This credential is not yet certified")
    private var _validUntil: Instant? = null

    /**
     * The credential counter.
     *
     * This is the value of the Document's Credential Counter at the time this credential was
     * created.
     */
    var credentialCounter: Long = -1
        protected set

    /**
     * The [Document] that the credential belongs to.
     */
    val document: Document

    internal var replacementIdentifier: String? = null
    internal var replacementForIdentifier: String? = null

    /**
     * The credential that will be replaced by this credential once it's been certified.
     */
    val replacementFor: Credential?
        get() = document.certifiedCredentials.firstOrNull { it.identifier == replacementForIdentifier }
            .also {
                if (it == null && replacementForIdentifier != null) {
                    Logger.w(
                        TAG, "Credential with alias $replacementForIdentifier which " +
                                "is intended to be replaced does not exist"
                    )
                }
            }

    /**
     * The credential that will replace this credential once certified or `null` if no
     * credential is designated to replace this credential.
     */
    val replacement: Credential?
        get() = document.pendingCredentials.firstOrNull { it.identifier == replacementIdentifier }
            .also {
                if (it == null && replacementIdentifier != null) {
                    Logger.w(
                        TAG, "Pending credential with identifier $replacementIdentifier which " +
                                "is intended to replace this credential does not exist"
                    )
                }
            }

    /**
     * Deletes the credential.
     *
     * After deletion, this object should no longer be used.
     */
    open suspend fun delete() {
        document.checkLocked()
        document.removeCredential(this)
    }

    /**
     * Increases usage count of the credential.
     *
     * This should be called when a crdential has been presented to a verifier.
     */
    suspend fun increaseUsageCount() {
        document.checkLocked()
        usageCount += 1
        document.saveDocument(false)
    }

    /**
     * Certifies the credential.
     *
     * @param issuerProvidedAuthenticationData the issuer-provided static authentication data.
     * @param validFrom the point in time before which the data is not valid.
     * @param validUntil the point in time after which the data is not valid.
     */
    suspend fun certify(
        issuerProvidedAuthenticationData: ByteArray,
        validFrom: Instant,
        validUntil: Instant
    ) {
        document.checkLocked()
        check(!isCertified) { "Credential is already certified" }
        isCertified = true
        _issuerProvidedData = issuerProvidedAuthenticationData
        _validFrom = validFrom
        _validUntil = validUntil

        replacementFor?.delete()
        replacementForIdentifier = null

        document.certifyPendingCredential(this)
    }

    /**
     * Method which can be overridden by [Credential] subclasses to add any additional information
     * when serializing a credential.
     *
     * @param builder a [MapBuilder] which can be used to add data.
     */
    open fun addSerializedData(builder: MapBuilder<CborBuilder>) {}

    /**
     * Serializes the credential.
     *
     * @return a [DataItem] with all of the credential information.
     */
    fun toCbor(): DataItem {
        document.checkLocked()
        val builder = CborMap.builder()
        builder.put("identifier", identifier)
            .put("credentialType", this::class.simpleName!!)  // used by CredentialFactory
            .put("domain", domain)
            .put("usageCount", usageCount.toLong())
            .put("isCertified", isCertified)
            .put("applicationData", _applicationData.encodeAsCbor())
            .put("credentialCounter", credentialCounter)

        if (replacementForIdentifier != null) {
            builder.put("replacementForAlias", replacementForIdentifier!!)
        }
        if (replacementIdentifier != null) {
            builder.put("replacementAlias", replacementIdentifier!!)
        }

        if (isCertified) {
            builder.put("data", issuerProvidedData)
                .put("validFrom", validFrom.toEpochMilliseconds())
                .put("validUntil", validUntil.toEpochMilliseconds())
        }

        addSerializedData(builder)
        return builder.end().build()
    }
}