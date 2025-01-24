package com.android.identity.issuance.funke

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.document.NameSpacedData
import com.android.identity.documenttype.DocumentType
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUCertificateOfResidence
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.documenttype.knowntypes.UtopiaMovieTicket
import com.android.identity.documenttype.knowntypes.UtopiaNaturalization
import com.android.identity.flow.annotation.FlowJoin
import com.android.identity.flow.annotation.FlowMethod
import com.android.identity.flow.annotation.FlowState
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.Resources
import com.android.identity.issuance.ApplicationSupport
import com.android.identity.issuance.CredentialConfiguration
import com.android.identity.issuance.CredentialData
import com.android.identity.issuance.CredentialFormat
import com.android.identity.issuance.DocumentCondition
import com.android.identity.issuance.DocumentConfiguration
import com.android.identity.issuance.DocumentState
import com.android.identity.issuance.IssuingAuthority
import com.android.identity.issuance.IssuingAuthorityConfiguration
import com.android.identity.issuance.IssuingAuthorityException
import com.android.identity.issuance.IssuingAuthorityNotification
import com.android.identity.issuance.MdocDocumentConfiguration
import com.android.identity.issuance.RegistrationResponse
import com.android.identity.issuance.SdJwtVcDocumentConfiguration
import com.android.identity.securearea.config.SecureAreaConfigurationAndroidKeystore
import com.android.identity.securearea.config.SecureAreaConfigurationCloud
import com.android.identity.issuance.WalletApplicationCapabilities
import com.android.identity.issuance.common.AbstractIssuingAuthorityState
import com.android.identity.flow.cache
import com.android.identity.flow.server.getTable
import com.android.identity.issuance.fromCbor
import com.android.identity.issuance.wallet.ApplicationSupportState
import com.android.identity.issuance.wallet.AuthenticationState
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.sdjwt.SdJwtVerifiableCredential
import com.android.identity.sdjwt.vc.JwtBody
import com.android.identity.securearea.KeyPurpose
import com.android.identity.storage.StorageTableSpec
import com.android.identity.util.Logger
import com.android.identity.util.fromBase64Url
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.readBytes
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration.Companion.seconds

@FlowState(
    flowInterface = IssuingAuthority::class
)
@CborSerializable
class FunkeIssuingAuthorityState(
    // NB: since this object is used to emit notifications, it cannot change, as its state
    // serves as notification key. So it generally should not have var members, only val.
    val clientId: String,
    val credentialIssuerUri: String, // credential offer issuing authority path
    val credentialConfigurationId: String,
    val issuanceClientId: String // client id in OpenID4VCI protocol
) : AbstractIssuingAuthorityState() {

    init {
        // It should not be possible, but double-check.
        check(credentialIssuerUri.indexOf('#') < 0)
        check(credentialConfigurationId.indexOf('#') < 0)
    }

    companion object {
        private const val TAG = "FunkeIssuingAuthorityState"

        val documentTableSpec = StorageTableSpec(
            name = "Openid4VciIssuerDocument",
            supportExpiration = false,
            supportPartitions = true
        )

        suspend fun getConfiguration(
            env: FlowEnvironment,
            issuerUrl: String,
            credentialConfigurationId: String
        ): IssuingAuthorityConfiguration {
            val id = "openid4vci#$issuerUrl#$credentialConfigurationId"
            return env.cache(IssuingAuthorityConfiguration::class, id) { _, resources ->
                val metadata = Openid4VciIssuerMetadata.get(env, issuerUrl)
                val config = metadata.credentialConfigurations[credentialConfigurationId]
                    ?: throw IllegalArgumentException("Unknown configuration '$credentialConfigurationId' at '$issuerUrl'")
                if (!config.isSupported) {
                    throw IllegalArgumentException("Unsupported configuration '$credentialConfigurationId' at '$issuerUrl'")
                }
                val httpClient = env.getInterface(HttpClient::class)!!
                val display = if (metadata.display.isEmpty()) null else metadata.display[0]
                val configDisplay = if (config.display.isEmpty()) null else config.display[0]
                var logo: ByteArray? = null
                if (display?.logoUrl != null) {
                    val logoRequest = httpClient.get(display.logoUrl) {}
                    if (logoRequest.status == HttpStatusCode.OK &&
                        logoRequest.contentType()?.contentType == "image") {
                        logo = logoRequest.readBytes()
                    } else {
                        Logger.e(TAG, "Could not fetch logo from '${display.logoUrl}")
                    }
                }
                if (logo == null) {
                    val logoPath = "funke/logo.png"
                    logo = resources.getRawResource(logoPath)!!.toByteArray()
                }

                val docType = documentTypeRepository.documentTypes.firstOrNull { documentType ->
                    return@firstOrNull when (config.format) {
                        is Openid4VciFormatMdoc ->
                            documentType.mdocDocumentType?.docType == config.format.docType
                        is Openid4VciFormatSdJwt ->
                            documentType.vcDocumentType?.type == config.format.vct
                        null -> false
                    }
                }

                val documentType = docType?.displayName ?: "Generic EAA"
                val documentDescription = configDisplay?.text ?: documentType
                val issuingAuthorityDescription = "$documentDescription (${config.format?.id})"

                var cardArt: ByteArray? = null
                if (configDisplay?.logoUrl != null) {
                    val artRequest = httpClient.get(configDisplay.logoUrl) {}
                    if (artRequest.status == HttpStatusCode.OK &&
                        artRequest.contentType()?.contentType == "image") {
                        cardArt = artRequest.readBytes()
                    } else {
                        Logger.e(TAG,
                            "Could not fetch credential image from '${configDisplay.logoUrl}")
                    }
                }
                if (cardArt == null) {
                    val artPath = "generic/card_art.png"
                    cardArt = resources.getRawResource(artPath)!!.toByteArray()
                }
                val requireUserAuthenticationToViewDocument = false
                val keyAttestation = config.proofType is Openid4VciProofTypeKeyAttestation
                IssuingAuthorityConfiguration(
                    identifier = id,
                    issuingAuthorityName = display?.text ?: issuerUrl,
                    issuingAuthorityLogo = logo,
                    issuingAuthorityDescription = issuingAuthorityDescription,
                    pendingDocumentInformation = DocumentConfiguration(
                        displayName = documentDescription,
                        typeDisplayName = documentType,
                        cardArt = cardArt,
                        requireUserAuthenticationToViewDocument = requireUserAuthenticationToViewDocument,
                        mdocConfiguration = null,
                        sdJwtVcDocumentConfiguration = null
                    ),
                    // Without key attestation user has to do biometrics approval for every
                    // credential being issued, so request only one. With key attestation we can
                    // use batch issuance (useful for unlinkability).
                    numberOfCredentialsToRequest =
                        if (keyAttestation) { 3 } else { 1 },
                    // With key attestation credentials can be requested in the background as they
                    // are used up, so direct wallet to avoid reusing them (for unlinkability).
                    maxUsesPerCredentials =
                        if (keyAttestation) { 1 } else { Int.MAX_VALUE },
                    minCredentialValidityMillis = 30 * 24 * 3600L,
                )
            }
        }

        val documentTypeRepository = DocumentTypeRepository().apply {
            addDocumentType(EUPersonalID.getDocumentType())
            addDocumentType(DrivingLicense.getDocumentType())
            addDocumentType(PhotoID.getDocumentType())
            addDocumentType(EUCertificateOfResidence.getDocumentType())
            addDocumentType(UtopiaNaturalization.getDocumentType())
            addDocumentType(UtopiaMovieTicket.getDocumentType())
        }
    }

    @FlowMethod
    suspend fun getConfiguration(env: FlowEnvironment): IssuingAuthorityConfiguration {
        return getConfiguration(env, credentialIssuerUri, credentialConfigurationId)
    }

    @FlowMethod
    suspend fun register(env: FlowEnvironment): FunkeRegistrationState {
        val documentId = createIssuerDocument(env,
            FunkeIssuerDocument(RegistrationResponse(false))
        )
        return FunkeRegistrationState(documentId)
    }

    @FlowJoin
    suspend fun completeRegistration(env: FlowEnvironment, registrationState: FunkeRegistrationState) {
        updateIssuerDocument(
            env,
            registrationState.documentId,
            FunkeIssuerDocument(registrationState.response!!))
    }

    @FlowMethod
    suspend fun getState(env: FlowEnvironment, documentId: String): DocumentState {
        val now = Clock.System.now()

        if (!issuerDocumentExists(env, documentId)) {
            return DocumentState(
                now,
                DocumentCondition.NO_SUCH_DOCUMENT,
                0,
                0
            )
        }

        val issuerDocument = loadIssuerDocument(env, documentId)

        if (issuerDocument.state == DocumentCondition.PROOFING_PROCESSING) {
            issuerDocument.state = if (issuerDocument.access != null) {
                DocumentCondition.CONFIGURATION_AVAILABLE
            } else {
                DocumentCondition.PROOFING_FAILED
            }
            updateIssuerDocument(env, documentId, issuerDocument)
        }

        // This information is helpful for when using the admin web interface.
        Logger.i(
            TAG, "Returning state for clientId=$clientId documentId=$documentId")

        // We create and sign Credential requests immediately so numPendingCredentialRequests is
        // always 0
        return DocumentState(
            now,
            issuerDocument.state,
            0,
            issuerDocument.credentials.size
        )
    }

    @FlowMethod
    suspend fun proof(env: FlowEnvironment, documentId: String): FunkeProofingState {
        val storage = env.getTable(AuthenticationState.walletAppCapabilitiesTableSpec)
        val applicationCapabilities = storage.get(clientId)?.let {
            WalletApplicationCapabilities.fromCbor(it.toByteArray())
        } ?: throw IllegalStateException("WalletApplicationCapabilities not found")
        return FunkeProofingState(
            clientId = clientId,
            credentialConfigurationId = credentialConfigurationId,
            issuanceClientId = issuanceClientId,
            documentId = documentId,
            credentialIssuerUri = credentialIssuerUri,
            applicationCapabilities = applicationCapabilities
        )
    }

    @FlowJoin
    suspend fun completeProof(env: FlowEnvironment, state: FunkeProofingState) {
        val issuerDocument = loadIssuerDocument(env, state.documentId)
        issuerDocument.state = DocumentCondition.PROOFING_PROCESSING
        issuerDocument.access = state.access
        issuerDocument.secureAreaIdentifier = state.secureAreaIdentifier
        updateIssuerDocument(env, state.documentId, issuerDocument)
    }

    @FlowMethod
    suspend fun getDocumentConfiguration(
        env: FlowEnvironment,
        documentId: String
    ): DocumentConfiguration {
        val issuerDocument = loadIssuerDocument(env, documentId)
        check(issuerDocument.state == DocumentCondition.CONFIGURATION_AVAILABLE)
        issuerDocument.state = DocumentCondition.READY
        if (issuerDocument.documentConfiguration == null) {
            val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
            if (metadata.authorizationServerList.isNotEmpty() &&
                metadata.authorizationServerList[0].useGermanEId) {
                val isCloudSecureArea =
                    issuerDocument.secureAreaIdentifier!!.startsWith("CloudSecureArea?")
                issuerDocument.documentConfiguration =
                    generateFunkeDocumentConfiguration(env, isCloudSecureArea)
            } else {
                issuerDocument.documentConfiguration =
                    generateGenericDocumentConfiguration(env)
            }
            val credentialConfiguration =
                metadata.credentialConfigurations[credentialConfigurationId]!!
            // For keyless credentials, just obtain them right away
            if (credentialConfiguration.proofType == Openid4VciNoProof &&
                issuerDocument.credentials.isEmpty()) {
                obtainCredentialsKeyless(env, documentId, issuerDocument)
            }
        }
        updateIssuerDocument(env, documentId, issuerDocument)
        return issuerDocument.documentConfiguration!!
    }

    @FlowMethod
    suspend fun requestCredentials(
        env: FlowEnvironment,
        documentId: String
    ): AbstractRequestCredentials {
        val document = loadIssuerDocument(env, documentId)
        val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
        val credentialConfiguration = metadata.credentialConfigurations[credentialConfigurationId]!!

        refreshAccessIfNeeded(env, documentId, document)

        val cNonce = document.access!!.cNonce!!
        val purposes = setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)
        val configuration = if (document.secureAreaIdentifier!!.startsWith("CloudSecureArea?")) {
            CredentialConfiguration(
                challenge = ByteString(cNonce.toByteArray()),
                keyAssertionRequired = true,
                secureAreaConfiguration = SecureAreaConfigurationCloud(
                    purposes = KeyPurpose.encodeSet(purposes),
                    curve = EcCurve.P256.coseCurveIdentifier,
                    cloudSecureAreaId = document.secureAreaIdentifier!!,
                    passphraseRequired = true,
                    useStrongBox = true,
                    userAuthenticationRequired = true,
                    userAuthenticationTimeoutMillis = 0,
                    userAuthenticationTypes = 3, // LSKF + Biometrics
                )
            )
        } else {
            CredentialConfiguration(
                challenge = ByteString(cNonce.toByteArray()),
                keyAssertionRequired = true,
                secureAreaConfiguration = SecureAreaConfigurationAndroidKeystore(
                    purposes = KeyPurpose.encodeSet(purposes),
                    curve = EcCurve.P256.coseCurveIdentifier,
                    useStrongBox = true,
                    userAuthenticationRequired = true,
                    userAuthenticationTimeoutMillis = 0,
                    userAuthenticationTypes = 3 // LSKF + Biometrics
                )
            )
        }
        return when (credentialConfiguration.proofType) {
            is Openid4VciProofTypeKeyAttestation ->
                RequestCredentialsUsingKeyAttestation(clientId, documentId, configuration)
            is Openid4VciProofTypeJwt ->
                RequestCredentialsUsingProofOfPossession(
                    clientId = clientId,
                    issuanceClientId = issuanceClientId,
                    documentId = documentId,
                    credentialConfiguration = configuration,
                    credentialIssuerUri = credentialIssuerUri
                )
            Openid4VciNoProof ->
                throw IllegalStateException("requestCredentials call is unexpected for keyless credentials")
            null -> throw IllegalStateException("Unexpected state")
        }
    }

    @FlowJoin
    suspend fun completeRequestCredentials(env: FlowEnvironment, state: AbstractRequestCredentials) {
        // Create appropriate request to OpenID4VCI issuer to issue credential(s)
        val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
        val credentialConfiguration = metadata.credentialConfigurations[credentialConfigurationId]!!

        val credentialTasks = when (state) {
            is RequestCredentialsUsingProofOfPossession ->
                listOf(createRequestUsingProofOfPossession(state, credentialConfiguration))
            is RequestCredentialsUsingKeyAttestation ->
                createRequestUsingKeyAttestation(env, state, credentialConfiguration)
            else -> throw IllegalStateException("Unsupported RequestCredential type")
        }

        val document = loadIssuerDocument(env, state.documentId)

        for ((request, publicKeys) in credentialTasks) {
            // Send the request
            val credentials = obtainCredentials(env, metadata, request, state.documentId, document)

            check(credentials.size == publicKeys.size)
            document.credentials.addAll(credentials.zip(publicKeys).map {
                val credential = it.first.jsonPrimitive.content
                val publicKey = it.second
                when (credentialConfiguration.format) {
                    is Openid4VciFormatSdJwt -> {
                        val sdJwt = SdJwtVerifiableCredential.fromString(credential)
                        val jwtBody = JwtBody.fromString(sdJwt.body)
                        CredentialData(
                            publicKey,
                            jwtBody.timeValidityBegin ?: jwtBody.timeSigned ?: Clock.System.now(),
                            jwtBody.timeValidityEnd ?: Instant.DISTANT_FUTURE,
                            CredentialFormat.SD_JWT_VC,
                            credential.toByteArray()
                        )
                    }

                    is Openid4VciFormatMdoc -> {
                        val credentialBytes = credential.fromBase64Url()
                        val credentialData = StaticAuthDataParser(credentialBytes).parse()
                        val issuerAuthCoseSign1 = Cbor.decode(credentialData.issuerAuth).asCoseSign1
                        val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
                        val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)
                        val mso = MobileSecurityObjectParser(encodedMso).parse()
                        CredentialData(
                            publicKey,
                            mso.validFrom,
                            mso.validUntil,
                            CredentialFormat.MDOC_MSO,
                            credentialBytes
                        )
                    }

                    null -> throw IllegalStateException("Unexpected credential format")
                }
            })
        }

        updateIssuerDocument(env, state.documentId, document, true)
    }

    private suspend fun obtainCredentialsKeyless(
        env: FlowEnvironment,
        documentId: String,
        issuerDocument: FunkeIssuerDocument,
    ) {
        val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
        val credentialConfiguration = metadata.credentialConfigurations[credentialConfigurationId]!!
        val request = buildJsonObject {
            putFormat(credentialConfiguration.format!!)
        }
        val credentials = obtainCredentials(
            env,
            metadata,
            request,
            documentId,
            issuerDocument
        )
        check(credentials.size == 1)
        val credential = credentials[0].jsonPrimitive.content
        val sdJwt = SdJwtVerifiableCredential.fromString(credential)
        val jwtBody = JwtBody.fromString(sdJwt.body)
        issuerDocument.credentials.add(
            CredentialData(
                null,
                jwtBody.timeValidityBegin ?: jwtBody.timeSigned ?: Clock.System.now(),
                jwtBody.timeValidityEnd ?: Instant.DISTANT_FUTURE,
                CredentialFormat.SD_JWT_VC,
                credential.toByteArray()
            )
        )
    }

    private suspend fun obtainCredentials(
        env: FlowEnvironment,
        metadata: Openid4VciIssuerMetadata,
        request: JsonObject,
        documentId: String,
        document: FunkeIssuerDocument
    ): JsonArray {
        val access = document.access!!
        val dpop = FunkeUtil.generateDPoP(
            env,
            clientId,
            metadata.credentialEndpoint,
            access.dpopNonce,
            access.accessToken
        )
        Logger.e(TAG,"Credential request: $request")

        val httpClient = env.getInterface(HttpClient::class)!!
        val credentialResponse = httpClient.post(metadata.credentialEndpoint) {
            headers {
                append("Authorization", "DPoP ${access.accessToken}")
                append("DPoP", dpop)
                append("Content-Type", "application/json")
            }
            setBody(request.toString())
        }
        access.cNonce = null  // used up

        if (credentialResponse.headers.contains("DPoP-Nonce")) {
            access.dpopNonce = credentialResponse.headers["DPoP-Nonce"]!!
        }

        if (credentialResponse.status != HttpStatusCode.OK) {
            val errResponseText = String(credentialResponse.readBytes())
            Logger.e(TAG,"Credential request error: ${credentialResponse.status} $errResponseText")

            // Currently in Funke case this gets document in permanent bad state, notification
            // is not needed as an exception will generate notification on the client side.
            document.state = DocumentCondition.DELETION_REQUESTED
            updateIssuerDocument(env, documentId, document, false)

            throw IssuingAuthorityException("Error getting a credential issued")
        }
        Logger.i(TAG, "Got successful response for credential request")
        val responseText = String(credentialResponse.readBytes())

        val response = Json.parseToJsonElement(responseText) as JsonObject
        return if (response.contains("credential")) {
            JsonArray(listOf(response["credential"]!!))
        } else {
            response["credentials"] as JsonArray
        }
    }

    private fun createRequestUsingProofOfPossession(
        state: RequestCredentialsUsingProofOfPossession,
        configuration: Openid4VciCredentialConfiguration
    ): Pair<JsonObject, List<EcPublicKey>> {
        val proofs = state.credentialRequests!!.map {
            JsonPrimitive(it.proofOfPossessionJwtHeaderAndBody + "." + it.proofOfPossessionJwtSignature)
        }
        val publicKeys = state.credentialRequests!!.map {
            it.request.secureAreaBoundKeyAttestation.publicKey
        }

        val request = buildJsonObject {
            if (proofs.size == 1) {
                put("proof", buildJsonObject {
                    put("jwt", proofs[0])
                    put("proof_type", JsonPrimitive("jwt"))
                })
            } else {
                put("proofs", buildJsonObject {
                    put("jwt", JsonArray(proofs))
                })
            }
            putFormat(configuration.format!!)
        }

        return Pair(request, publicKeys)
    }

    private suspend fun createRequestUsingKeyAttestation(
        env: FlowEnvironment,
        state: RequestCredentialsUsingKeyAttestation,
        configuration: Openid4VciCredentialConfiguration
    ): List<Pair<JsonObject, List<EcPublicKey>>> {
        // NB: applicationSupport will only be non-null in the environment when running this code
        // locally in the Android Wallet app.
        val applicationSupport = env.getInterface(ApplicationSupport::class)
        return state.credentialRequestSets.map { credentialRequestSet ->
            val jwtKeyAttestation = if (applicationSupport != null) {
                applicationSupport.createJwtKeyAttestation(
                    keyAttestations = credentialRequestSet.keyAttestations,
                    keysAssertion = credentialRequestSet.keysAssertion
                )
            } else {
                ApplicationSupportState(clientId).createJwtKeyAttestation(
                    env = env,
                    keyAttestations = credentialRequestSet.keyAttestations,
                    keysAssertion = credentialRequestSet.keysAssertion
                )
            }
            val request = buildJsonObject {
                put("proof", buildJsonObject {
                    put("attestation", JsonPrimitive(jwtKeyAttestation))
                    put("proof_type", JsonPrimitive("attestation"))
                })
                putFormat(configuration.format!!)
            }
            Pair(request, credentialRequestSet.keyAttestations.map { it.publicKey })
        }
    }

    @FlowMethod
    suspend fun getCredentials(env: FlowEnvironment, documentId: String): List<CredentialData> {
        val document = loadIssuerDocument(env, documentId)
        val credentials = mutableListOf<CredentialData>()
        credentials.addAll(document.credentials)
        document.credentials.clear()
        updateIssuerDocument(env, documentId, document, false)
        return credentials
    }

    @FlowMethod
    suspend fun developerModeRequestUpdate(
        env: FlowEnvironment,
        documentId: String,
        requestRemoteDeletion: Boolean,
        notifyApplicationOfUpdate: Boolean
    ) {
    }

    private suspend fun issuerDocumentExists(env: FlowEnvironment, documentId: String): Boolean {
        if (clientId.isEmpty()) {
            throw IllegalStateException("Client not authenticated")
        }
        val storage = env.getTable(documentTableSpec)
        val encodedCbor = storage.get(partitionId = clientId, key = documentId)
        return encodedCbor != null
    }

    private suspend fun loadIssuerDocument(env: FlowEnvironment, documentId: String): FunkeIssuerDocument {
        if (clientId.isEmpty()) {
            throw IllegalStateException("Client not authenticated")
        }
        val storage = env.getTable(documentTableSpec)
        val encodedCbor = storage.get(partitionId = clientId, key = documentId)
            ?: throw Error("No such document")
        return FunkeIssuerDocument.fromCbor(encodedCbor.toByteArray())
    }

    private suspend fun createIssuerDocument(env: FlowEnvironment, document: FunkeIssuerDocument): String {
        if (clientId.isEmpty()) {
            throw IllegalStateException("Client not authenticated")
        }
        val storage = env.getTable(documentTableSpec)
        val bytes = document.toCbor()
        return storage.insert(key = null, partitionId = clientId, data = ByteString(bytes))
    }

    private suspend fun deleteIssuerDocument(env: FlowEnvironment,
                                             documentId: String,
                                             emitNotification: Boolean = true) {
        if (clientId.isEmpty()) {
            throw IllegalStateException("Client not authenticated")
        }
        val storage = env.getTable(documentTableSpec)
        storage.delete(partitionId = clientId, key = documentId)
        if (emitNotification) {
            emit(env, IssuingAuthorityNotification(documentId))
        }
    }

    private suspend fun updateIssuerDocument(
        env: FlowEnvironment,
        documentId: String,
        document: FunkeIssuerDocument,
        emitNotification: Boolean = true,
    ) {
        if (clientId.isEmpty()) {
            throw IllegalStateException("Client not authenticated")
        }
        val storage = env.getTable(documentTableSpec)
        val bytes = document.toCbor()
        storage.update(partitionId = clientId, key = documentId, data = ByteString(bytes))
        if (emitNotification) {
            Logger.i(TAG, "Emitting notification for $documentId")
            emit(env, IssuingAuthorityNotification(documentId))
        }
    }

    private suspend fun generateFunkeDocumentConfiguration(
        env: FlowEnvironment,
        isCloudSecureArea: Boolean
    ): DocumentConfiguration {
        val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
        val config = metadata.credentialConfigurations[credentialConfigurationId]!!
        val resources = env.getInterface(Resources::class)!!
        return when (config.format) {
            is Openid4VciFormatSdJwt -> {
                val art = resources.getRawResource(
                    if (isCloudSecureArea) {
                        "funke/card_art_funke_sdjwt_c1.png"
                    } else {
                        "funke/card_art_funke_sdjwt_c.png"
                    })!!
                DocumentConfiguration(
                    "Funke",
                    "Personal ID (SD-JWT)",
                    art.toByteArray(),
                    false,
                    null,
                    SdJwtVcDocumentConfiguration(
                        vct = config.format.vct,
                        keyBound = config.proofType != Openid4VciNoProof
                    )
                )
            }
            is Openid4VciFormatMdoc -> {
                val art = resources.getRawResource(
                    if (isCloudSecureArea) {
                        "funke/card_art_funke_mdoc_c1.png"
                    } else {
                        "funke/card_art_funke_mdoc_c.png"
                    })!!
                DocumentConfiguration(
                    "Funke",
                    "Personal ID (MDOC)",
                    art.toByteArray(),
                    false,
                    MdocDocumentConfiguration(
                        config.format.docType,
                        staticData = fillInSampleData(
                            documentTypeRepository.getDocumentTypeForMdoc(config.format.docType)!!
                        ).build()
                    ),
                    null
                )
            }
            else -> throw IllegalStateException("Invalid credential format")
        }
    }

    private suspend fun generateGenericDocumentConfiguration(
        env: FlowEnvironment
    ): DocumentConfiguration {
        val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
        val config = metadata.credentialConfigurations[credentialConfigurationId]!!
        val base = getConfiguration(env).pendingDocumentInformation
        return when (config.format) {
            is Openid4VciFormatSdJwt -> {
                DocumentConfiguration(
                    base.displayName,
                    base.typeDisplayName,
                    base.cardArt,
                    base.requireUserAuthenticationToViewDocument,
                    null,
                    SdJwtVcDocumentConfiguration(
                        vct = config.format.vct,
                        keyBound = config.proofType != Openid4VciNoProof
                    )
                )
            }
            is Openid4VciFormatMdoc -> {
                val documentType = documentTypeRepository.getDocumentTypeForMdoc(config.format.docType)
                val staticData = if (documentType != null) {
                    fillInSampleData(documentType).build()
                } else {
                    NameSpacedData.Builder().build()
                }
                DocumentConfiguration(
                    base.displayName,
                    base.typeDisplayName,
                    base.cardArt,
                    base.requireUserAuthenticationToViewDocument,
                    MdocDocumentConfiguration(
                        config.format.docType,
                        staticData = staticData
                    ),
                    null
                )
            }
            else -> throw IllegalStateException("Invalid credential format")
        }
    }

    private fun fillInSampleData(documentType: DocumentType): NameSpacedData.Builder {
        val builder = NameSpacedData.Builder()
        for ((namespaceName, namespace) in documentType.mdocDocumentType!!.namespaces) {
            for ((dataElementName, dataElement) in namespace.dataElements) {
                if (dataElement.attribute.sampleValue != null) {
                    builder.putEntry(
                        namespaceName,
                        dataElementName,
                        Cbor.encode(dataElement.attribute.sampleValue!!)
                    )
                }
            }
        }
        return builder
    }

    private suspend fun refreshAccessIfNeeded(
        env: FlowEnvironment,
        documentId: String,
        document: FunkeIssuerDocument
    ) {
        val metadata = Openid4VciIssuerMetadata.get(env, credentialIssuerUri)
        var access = document.access!!
        val nowPlusSlack = Clock.System.now() + 30.seconds
        if (access.cNonce != null && nowPlusSlack < access.accessTokenExpiration) {
            // No need to refresh.
            return
        }

        val refreshToken = access.refreshToken
        access = FunkeUtil.obtainToken(
            env = env,
            clientId = clientId,
            issuanceClientId = issuanceClientId,
            tokenUrl = access.tokenEndpoint,
            refreshToken = refreshToken,
            accessToken = access.accessToken
        )
        check(access.cNonce != null)
        document.access = access
        Logger.i(TAG, "Refreshed access tokens")
        if (access.refreshToken == null) {
            Logger.w(TAG, "Kept original refresh token (no updated refresh token received)")
            access.refreshToken = refreshToken
        }
        updateIssuerDocument(env, documentId, document, false)
    }
}