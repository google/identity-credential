package com.android.identity_credential.wallet.presentation

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Text
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.lifecycleScope
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.Simple
import com.android.identity.credential.Credential
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.X509Cert
import com.android.identity.document.Document
import com.android.identity.document.DocumentRequest
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.issuance.CredentialFormat
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.sdjwt.SdJwtVerifiableCredential
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.WalletApplication
import com.android.identity.request.Claim
import com.android.identity.request.Requester
import com.android.identity.request.VcClaim
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.request.MdocClaim
import com.android.identity.request.MdocRequest
import com.android.identity.request.VcRequest
import com.android.identity.sdjwt.credential.SdJwtVcCredential
import com.android.identity_credential.wallet.ui.theme.IdentityCredentialTheme
// TODO: replace the nimbusds library usage with non-java-based alternative
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import io.ktor.client.HttpClient
import io.ktor.client.call.NoTransformationFoundException
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.http.formUrlEncode
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.InternalAPI
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random

@Serializable
internal data class PresentationSubmission(
    @Required val id: String,
    @Required
    @SerialName("definition_id")
    val definitionId: String,
    @Required
    @SerialName("descriptor_map")
    val descriptorMaps: List<DescriptorMap>,
)

@Serializable
internal data class DescriptorMap(
    @Required val id: String,
    @Required val format: String,
    @Required val path: String,
)

internal data class AuthorizationRequest (
    var presentationDefinition: JsonObject,
    var clientId: String,
    var nonce: String,
    var responseUri: String,
    var state: String?,
    var clientMetadata: JsonObject,
    var certificateChain: List<X509Cert>?
)

class NoMatchingDocumentException(message: String): Exception(message) {}

class OpenID4VPPresentationActivity : FragmentActivity() {
    companion object {
        private const val TAG = "OpenID4VPPresentationActivity"
    }

    private enum class Phase {
        NOT_CONNECTED,
        TRANSACTING,
        SHOW_RESULT,
        POST_RESULT,
        CANCELED,
    }

    private var phase = MutableLiveData<Phase>(Phase.TRANSACTING)

    private var resultStringId: Int = 0
    private var resultDrawableId: Int = 0
    private var successRedirectUri: Uri? = null
    private var resultDelay: Long = 1500

    @Composable
    private fun Result(phase: Phase) {
        AnimatedVisibility(
            visible = phase == Phase.SHOW_RESULT,
            enter = fadeIn(),
            exit = fadeOut(),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxHeight()
                    .padding(horizontal = 32.dp),
                verticalArrangement = Arrangement.Center
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(elevation = 8.dp, shape = RoundedCornerShape(28.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (resultDrawableId != 0) {
                        Image(
                            modifier = Modifier.padding(top = 30.dp),
                            painter = painterResource(resultDrawableId),
                            contentDescription = null,
                            contentScale = ContentScale.None,
                        )
                    }
                    if (resultStringId != 0) {
                        Text(
                            text = stringResource(resultStringId),
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 20.dp, bottom = 40.dp),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }
    }

    private val walletApp: WalletApplication by lazy {
        application as WalletApplication
    }

    override fun onDestroy() {
        Logger.i(TAG, "onDestroy")
        super.onDestroy()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        phase.value = Phase.TRANSACTING
        resultStringId = 0
        resultDrawableId = 0
        successRedirectUri = null

        val authorizationRequest = Uri.parse(intent.toUri(0)).toString()

        setContent {
            val phaseState: Phase by phase.observeAsState(Phase.TRANSACTING)
            IdentityCredentialTheme {
                Result(phaseState)
            }
        }

        lifecycleScope.launch {
            try {
                createAndSendResponse(authorizationRequest)
                resultStringId = R.string.presentation_result_success_message
                resultDrawableId = R.drawable.presentment_result_status_success
                phase.value = Phase.SHOW_RESULT
            } catch (e: UserCanceledPromptException) {
                Logger.e(TAG, "User canceled the prompt")
                phase.value = Phase.CANCELED
            } catch (e: NoMatchingDocumentException) {
                Logger.e(TAG, "No matching document", e)
                resultStringId = R.string.presentation_result_no_matching_document_message
                resultDrawableId = R.drawable.presentment_result_status_error
                resultDelay = 3000
                phase.value = Phase.SHOW_RESULT
            } catch (e: Throwable) {
                Logger.e(TAG, "Error presenting", e)
                resultStringId = R.string.presentation_result_error_message
                resultDrawableId = R.drawable.presentment_result_status_error
                phase.value = Phase.SHOW_RESULT
            }
        }

        phase.observe(this as LifecycleOwner) {
            when (it!!) {
                Phase.NOT_CONNECTED -> {
                    Logger.i(TAG, "Phase: Not Connected")
                    finish()
                }

                Phase.TRANSACTING -> {
                }

                Phase.SHOW_RESULT -> {
                    Logger.i(TAG, "Phase: Showing result")
                    lifecycleScope.launch {
                        // the amount of time to show the result for
                        delay(resultDelay)
                        phase.value = Phase.POST_RESULT
                    }
                }

                Phase.POST_RESULT -> {
                    Logger.i(TAG, "Phase: Post showing result")
                    lifecycleScope.launch {
                        // delay before finishing activity, to ensure the result is fading out
                        delay(500)
                        // Once faded out, switch back to browser if the transaction succeeded
                        if (successRedirectUri != null) {
                            startActivity(
                                Intent(
                                    Intent.ACTION_VIEW,
                                    Uri.parse(successRedirectUri.toString())
                                )
                            )
                        }
                        phase.value = Phase.NOT_CONNECTED
                    }
                }

                Phase.CANCELED -> {
                    Logger.i(TAG, "Phase: Canceled")
                    phase.value = Phase.NOT_CONNECTED
                }
            }
        }

    }

    private fun firstMatchingDocument(
        credentialFormat: CredentialFormat,
        docType: String
    ): Document? {
        val settingsModel = walletApp.settingsModel
        val documentStore = walletApp.documentStore

        // prefer the credential which is on-screen if possible
        val credentialIdFromPager: String? = settingsModel.focusedCardId.value
        if (credentialIdFromPager != null
            // Sometimes the focused card ID references an old deleted card, in which case
            // lookupDocument will return null, so we still need to check for that:
            && walletApp.documentStore.lookupDocument(credentialIdFromPager) != null
            && canDocumentSatisfyRequest(credentialIdFromPager, credentialFormat, docType)
        ) {
            return documentStore.lookupDocument(credentialIdFromPager)
        }

        val docId = documentStore.listDocuments().firstOrNull { credentialId ->
            canDocumentSatisfyRequest(credentialId, credentialFormat, docType)
        }
        return docId?.let { documentStore.lookupDocument(it) }
    }

    private fun canDocumentSatisfyRequest(
        credentialId: String,
        credentialFormat: CredentialFormat,
        docType: String
    ): Boolean {
        val document = walletApp.documentStore.lookupDocument(credentialId)!!
        val documentConfiguration = document.documentConfiguration
        return when (credentialFormat) {
            CredentialFormat.MDOC_MSO -> documentConfiguration.mdocConfiguration?.docType == docType
            CredentialFormat.SD_JWT_VC ->
                if (docType == "") {
                    documentConfiguration.sdJwtVcDocumentConfiguration != null
                } else {
                    documentConfiguration.sdJwtVcDocumentConfiguration?.vct == docType
                }
        }
    }

    private suspend fun getKeySet(httpClient: HttpClient, clientMetadata: JsonObject): JWKSet {
        val jwks = clientMetadata["jwks"]
        if (jwks != null) {
            return JWKSet.parse(Json.encodeToString(jwks))
        }
        val jwksUri = clientMetadata["jwks_uri"].toString().run { substring(1, this.length - 1) }
        val unparsed = httpClient.get(Url(jwksUri)).body<String>()
        return JWKSet.parse(unparsed)
    }

    /**
     * [OutgoingContent] for `application/x-www-form-urlencoded` formatted requests that use
     * US-ASCII encoding.
     */
    internal class FormData(
        val formData: Parameters,
    ) : OutgoingContent.ByteArrayContent() {
        private val content = formData.formUrlEncode().toByteArray(Charsets.US_ASCII)

        override val contentLength: Long = content.size.toLong()
        override val contentType: ContentType = ContentType.Application.FormUrlEncoded

        override fun bytes(): ByteArray = content
    }

    private fun getCredentialAndClaims(
        document: Document,
        credentialFormat: CredentialFormat,
        inputDescriptor: JsonObject,
        now: Instant
    ): Pair<Credential, List<Claim>> {
        return when(credentialFormat) {
            CredentialFormat.MDOC_MSO -> {
                val credential =
                    document.findCredential(WalletApplication.CREDENTIAL_DOMAIN_MDOC, now)
                        ?: throw IllegalStateException("No credentials available")
                val (docType, requestedData) = parseInputDescriptorForMdoc(inputDescriptor)
                val claims = MdocUtil.generateClaims(
                    docType,
                    requestedData,
                    walletApp.documentTypeRepository,
                    credential as MdocCredential
                )
                return Pair(credential, claims)
            }
            CredentialFormat.SD_JWT_VC -> {
                val (vct, requestedClaims) = parseInputDescriptorForVc(inputDescriptor)
                val credential =
                    document.findCredential(WalletApplication.CREDENTIAL_DOMAIN_SD_JWT_VC, now)
                        ?: throw IllegalStateException("No credentials available")
                val claims = VcClaim.Companion.generateClaims(
                    vct,
                    requestedClaims,
                    walletApp.documentTypeRepository,
                    credential as SdJwtVcCredential
                )
                return Pair(credential, claims)
            }
        }
    }

    private fun parseInputDescriptorForMdoc(
        inputDescriptor: JsonObject
    ): Pair<String, Map<String, List<Pair<String, Boolean>>>> {
        val requestedData = mutableMapOf<String, MutableList<Pair<String, Boolean>>>()

        val docType = inputDescriptor["id"]!!.jsonPrimitive.content
        val constraints = inputDescriptor["constraints"]!!.jsonObject
        val fields = constraints["fields"]!!.jsonArray

        for (field: JsonElement in fields) {
            val fieldObj = field.jsonObject
            val path = fieldObj["path"]!!.jsonArray[0].toString()
            val parsed = parsePathItem(path)
            val nameSpaceName = parsed.first
            val dataElementName = parsed.second
            val intentToRetain = (fieldObj["intent_to_retain"].toString() == "true")

            requestedData.getOrPut(nameSpaceName) { mutableListOf() }
                .add(Pair(dataElementName, intentToRetain))
        }

        return Pair(docType, requestedData)
    }

    private fun parseInputDescriptorForVc(
        inputDescriptor: JsonObject
    ): Pair<String, List<String>> {
        val requestedClaims = mutableListOf<String>()
        // Set the default vct if we don't detect it below.
        var vct = EUPersonalID.EUPID_VCT

        val constraints = inputDescriptor["constraints"]!!.jsonObject
        val fields = constraints["fields"]!!.jsonArray
        for (field: JsonElement in fields) {
            val fieldObj = field.jsonObject
            val path = fieldObj["path"]!!.jsonArray[0].toString()
            val parsed = parsePathItem(path)
            val claimName = parsed.second
            requestedClaims.add(claimName)

            if (path == "\"\$.vct\"") {
                val filter = fieldObj["filter"]!!.jsonObject
                vct = filter["const"]!!.toString().run { substring(1, this.length - 1) }
            }
        }
        return Pair(vct, requestedClaims)
    }

    // Returns `false` if canceled by the user
    //
    @OptIn(InternalAPI::class, ExperimentalEncodingApi::class)
    private suspend fun createAndSendResponse(authRequest: String) {
        val httpClient = HttpClient {
            install(ContentNegotiation) { json() }
            expectSuccess = true
        }
        Logger.i(TAG, "authRequest: $authRequest")

        val uri = Uri.parse(authRequest)
        val authorizationRequest = getAuthorizationRequest(uri, httpClient)
        val credentialFormat = getFormat(authorizationRequest.clientMetadata, authorizationRequest.presentationDefinition)
        val presentationSubmission = createPresentationSubmission(authorizationRequest, credentialFormat)
        val inputDescriptors =
            authorizationRequest.presentationDefinition["input_descriptors"]!!.jsonArray

        // For now, we only respond to the first credential being requested.
        //
        // NOTE: openid4vp spec gives a non-normative example of multiple input descriptors
        // as "alternatives credentials", see
        //
        //  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-6
        //
        // Also note identity.foundation says all input descriptors MUST be satisfied, see
        //
        //  https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor
        //
        val inputDescriptorObj = inputDescriptors[0].jsonObject
        val docType = if (credentialFormat == CredentialFormat.MDOC_MSO) {
            inputDescriptorObj["id"]!!.toString().run { substring(1, this.length - 1) }
        } else {
            try {
                val (vct, _) = parseInputDescriptorForVc(inputDescriptorObj)
                vct
            } catch (e: NullPointerException) {
                Logger.d(TAG, "Error: Expected input descriptor field is missing: ${e.message}")
                ""
            }
        }

        val documentRequest = formatAsDocumentRequest(inputDescriptorObj)
        val document = firstMatchingDocument(credentialFormat, docType)
            ?: run { throw NoMatchingDocumentException("No matching credentials in wallet for " +
                    "docType $docType and credentialFormat $credentialFormat") }

        // begin collecting and creating data needed for the response
        val secureRandom = Random.Default
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        val generatedNonce = Base64.UrlSafe.encode(bytes)
        val sessionTranscript = createSessionTranscript(
            clientId = authorizationRequest.clientId,
            responseUri = authorizationRequest.responseUri,
            authorizationRequestNonce = authorizationRequest.nonce,
            mdocGeneratedNonce = generatedNonce
        )

        if (authorizationRequest.clientMetadata["authorization_signed_response_alg"] != null) {
            TODO("Support signing the authorization response")
        }

        val now = Clock.System.now()
        val (credentialToUse, consentFields) = getCredentialAndClaims(
            document,
            credentialFormat,
            inputDescriptorObj,
            now)

        var trustPoint: TrustPoint? = null
        if (authorizationRequest.certificateChain != null) {
            val trustResult = walletApp.readerTrustManager.verify(
                authorizationRequest.certificateChain!!
            )
            if (!trustResult.isTrusted) {
                Logger.w(TAG, "Reader root not trusted")
                if (trustResult.error != null) {
                    Logger.w(TAG, "trustResult.error", trustResult.error!!)
                }
            }
            if (trustResult.isTrusted && trustResult.trustPoints.size > 0) {
                trustPoint = trustResult.trustPoints[0]
            }
        }

        val vpTokenByteArray = generateVpToken(consentFields, credentialToUse, trustPoint, authorizationRequest, sessionTranscript)
        Logger.i(TAG, "Setting vp_token: ${vpTokenByteArray.decodeToString()}")
        val vpToken = if (credentialToUse is MdocCredential) {
            Base64.UrlSafe.encode(vpTokenByteArray).replace("=", "")
        } else vpTokenByteArray.decodeToString()
        val claimSet = JWTClaimsSet.parse(Json.encodeToString(buildJsonObject {
            // put("id_token", idToken) // depends on response type, only supporting vp_token for now
            put("state", authorizationRequest.state)
            put("vp_token", vpToken)
            put("presentation_submission", Json.encodeToJsonElement(presentationSubmission))
        }))

        // If the request provided the right fields so we can encrypt the response, encrypt it.
        val jwtResponse =
            maybeEncryptJwtResponse(claimSet, authorizationRequest, generatedNonce, httpClient)

        // send response
        Logger.i(TAG, "Sending response to ${authorizationRequest.responseUri}")
        val requestState: String? = authorizationRequest.state
        val response = httpClient.post(authorizationRequest.responseUri) {
            body = FormData(Parameters.build {
                val serializedJwtResposne = jwtResponse.serialize()
                Logger.i(TAG, "Sending serialized JWT response: $serializedJwtResposne")
                append("response", serializedJwtResposne)
                requestState?.let {
                    append("state", it)
                }
            })
        }
        Logger.i(TAG, "Response: $response")

        // receive redirectUri and launch with browser
        when (response.status) {
            HttpStatusCode.OK -> {
                val responseBody = response.body<JsonObject?>()
                val redirectUri =
                    try {
                        responseBody
                            ?.get("redirect_uri")
                            ?.takeIf { it is JsonPrimitive }
                            ?.jsonPrimitive?.contentOrNull
                            ?.let { Uri.parse(it) }
                    } catch (t: NoTransformationFoundException) {
                        null
                    }
                successRedirectUri = redirectUri
            }
            else -> Logger.d(TAG, "Response $response unexpected")
        }
    }

    private suspend fun maybeEncryptJwtResponse(
        claimSet: JWTClaimsSet?,
        authorizationRequest: AuthorizationRequest,
        generatedNonce: String,
        httpClient: HttpClient
    ): JWT {
        val encryptedResponseAlg =
            authorizationRequest.clientMetadata["authorization_encrypted_response_alg"]
                ?.toString()
                ?.run { substring(1, this.length - 1) }
        return if (encryptedResponseAlg == null) {
            PlainJWT(claimSet)
        } else {
            val apv = Base64URL.encode(authorizationRequest.nonce)
            val apu = Base64URL.encode(generatedNonce)
            val responseEncryptionAlg = JWEAlgorithm.parse(encryptedResponseAlg)
            val responseEncryptionMethod =
                EncryptionMethod.parse(
                    authorizationRequest.clientMetadata
                        ["authorization_encrypted_response_enc"]!!.toString()
                        .run { substring(1, this.length - 1) })
            val jweHeader = JWEHeader.Builder(responseEncryptionAlg, responseEncryptionMethod)
                .apply {
                    apv?.let(::agreementPartyVInfo)
                    apu?.let(::agreementPartyUInfo)
                }
                .build()
            val keySet = getKeySet(httpClient, authorizationRequest.clientMetadata)
            val jweEncrypter: ECDHEncrypter? = keySet.keys.mapNotNull { key ->
                runCatching { ECDHEncrypter(key as ECKey) }.getOrNull()
                    ?.let { encrypter -> key to encrypter }
            }
                .toMap().firstNotNullOfOrNull { it.value }
            EncryptedJWT(jweHeader, claimSet).apply { encrypt(jweEncrypter) }
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun generateVpToken(
        claims: List<Claim>,
        credential: Credential,
        trustPoint: TrustPoint?,
        authorizationRequest: AuthorizationRequest,
        sessionTranscript: ByteArray // TODO: Only needed for mdoc. Generate internally.
    ): ByteArray {
        // TODO: Need to catch UserCanceledPromptException and tell the verifier that
        //  the user declined to share data.
        //
        return when (credential) {
            is MdocCredential -> {
                val request = MdocRequest(
                    requester = Requester(),  // TODO: pass origin
                    claims = claims as List<MdocClaim>,
                    docType = credential.docType
                )
                val documentResponse = showMdocPresentmentFlow(
                    activity = this,
                    request = request,
                    trustPoint = trustPoint,
                    document = ConsentDocument(
                        name = credential.document.documentConfiguration.displayName,
                        description = credential.document.documentConfiguration.typeDisplayName,
                        cardArt = credential.document.documentConfiguration.cardArt,
                    ),
                    credential = credential,
                    encodedSessionTranscript = sessionTranscript,
                )

                val deviceResponseGenerator = DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
                deviceResponseGenerator.addDocument(documentResponse)

                // build response
                val deviceResponseCbor = deviceResponseGenerator.generate()
                deviceResponseCbor
            }
            is SdJwtVcCredential -> {
                val request = VcRequest(
                    requester = Requester(),  // TODO: pass origin
                    claims = claims as List<VcClaim>,
                    vct = credential.vct
                )
                showSdJwtPresentmentFlow(
                    activity = this,
                    request = request,
                    trustPoint = trustPoint,
                    document = ConsentDocument(
                        name = credential.document.documentConfiguration.displayName,
                        description = credential.document.documentConfiguration.typeDisplayName,
                        cardArt = credential.document.documentConfiguration.cardArt,
                    ),
                    credential = credential,
                    nonce = authorizationRequest.nonce,
                    clientId = authorizationRequest.clientId
                )
            }
            else -> {
                throw IllegalArgumentException("Unhandled credential type")
            }
        }
    }
}

// returns <namespace, dataElem>
internal fun parsePathItem(item: String): Pair<String, String> {
    // formats can be
    // bracketed: "$['namespace']['dataElem']"
    // bracketed direct: "$['dataElem']"
    // or dotted direct: "$.dataElem"
    val regex = Regex(
        "(?:\"\\$(?:\\['(?<namespace>.+?)'\\])?\\['(?<dataElem1>.+?)'\\]\")|" +
        "(?:\"\\$\\.(?<dataElem2>.+)\")")
    val groups = regex.matchEntire(item)?.groups as? MatchNamedGroupCollection
    if (groups == null) {
        throw IllegalArgumentException("Unable to parse path item: $item")
    }
    // TODO: Remove the fake credentialSubject namespace that's needed for the consent screen.
    val namespace = groups.get("namespace")?.value ?: "credentialSubject"
    val dataElem = groups.get("dataElem1")?.value ?: groups.get("dataElem2")?.value!!
    return Pair(namespace, dataElem)
}

// defined in ISO 18013-7 Annex B
private fun createSessionTranscript(
    clientId: String,
    responseUri: String,
    authorizationRequestNonce: String,
    mdocGeneratedNonce: String
): ByteArray {
    val clientIdToHash = Cbor.encode(CborArray.builder()
        .add(clientId)
        .add(mdocGeneratedNonce)
        .end()
        .build())
    val clientIdHash = Crypto.digest(Algorithm.SHA256, clientIdToHash)

    val responseUriToHash = Cbor.encode(CborArray.builder()
        .add(responseUri)
        .add(mdocGeneratedNonce)
        .end()
        .build())
    val responseUriHash = Crypto.digest(Algorithm.SHA256, responseUriToHash)

    val oid4vpHandover = CborArray.builder()
        .add(clientIdHash)
        .add(responseUriHash)
        .add(authorizationRequestNonce)
        .end()
        .build()

    return Cbor.encode(
        CborArray.builder()
            .add(Simple.NULL)
            .add(Simple.NULL)
            .add(oid4vpHandover)
            .end()
            .build()
    )
}

private suspend fun getAuthorizationRequest(
    requestUri: Uri,
    httpClient: HttpClient
): AuthorizationRequest {
    // simplified same-device flow:
    val presentationDefinition = requestUri.getQueryParameter("presentation_definition")?.let { Json.parseToJsonElement(it).jsonObject }
    if (presentationDefinition != null) {
        return AuthorizationRequest(
            presentationDefinition = presentationDefinition,
            clientId = requestUri.getQueryParameter("client_id")!!,
            nonce = requestUri.getQueryParameter("nonce")!!,
            responseUri = requestUri.getQueryParameter("response_uri")!!,
            state = requestUri.getQueryParameter("state"),
            clientMetadata = requestUri.getQueryParameter("client_metadata")!!
                .run { Json.parseToJsonElement(this).jsonObject },
            certificateChain = null
        )
    }

    val clientId = requestUri.getQueryParameter("client_id")
    val requestValue = requestUri.getQueryParameter("request")
    if (requestValue != null) {
        return getAuthRequestFromJwt(SignedJWT.parse(requestValue), clientId)
    }

    // more complex same-device flow as outline in Annex B -> request_uri is
    // needed to retrieve Request Object from provided url
    val requestUriValue = requestUri.getQueryParameter("request_uri")
        ?: throw IllegalArgumentException("request_uri is not set")

    val httpResponse = httpClient.get(urlString = requestUriValue!!) {
        accept(ContentType.parse("application/oauth-authz-req+jwt"))
        accept(ContentType.parse("application/jwt"))
    }.body<String>()
    Logger.i(TAG, "Signed JWT response: $httpResponse")

    val signedJwt = SignedJWT.parse(httpResponse)
    Logger.i(TAG, "SignedJWT header: ${signedJwt.header}")
    Logger.i(TAG, "SignedJWT payload: ${signedJwt.payload}")
    return getAuthRequestFromJwt(signedJwt, clientId)
}

internal fun getAuthRequestFromJwt(signedJWT: SignedJWT, clientId: String?): AuthorizationRequest {
    if (clientId != null &&
        signedJWT.jwtClaimsSet.getStringClaim("client_id") != clientId) {
        throw IllegalArgumentException("Client ID doesn't match")
    }
    Logger.i(TAG, "signedJWT client_id: ${signedJWT.jwtClaimsSet.getStringClaim("client_id")}")
    val x5c = signedJWT.header?.x509CertChain ?: throw IllegalArgumentException("Error retrieving cert chain")
    val pubCertChain = x5c.mapNotNull { runCatching { X509Cert(it.decode()) }.getOrNull() }
    if (pubCertChain.isEmpty()) {
        throw IllegalArgumentException("Invalid x5c")
    }

    // verify JWT signature
    try {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
            // see also: DefaultJOSEObjectTypeVerifier.JWT
            jwsTypeVerifier =
                DefaultJOSEObjectTypeVerifier(
                    JOSEObjectType("oauth-authz-req+jwt"),
                    JOSEObjectType.JWT,
                    JOSEObjectType(""),
                    null,
                )
            jwsKeySelector = JWSKeySelector<SecurityContext> { _, _ -> listOf(pubCertChain[0].javaX509Certificate.publicKey) }
            jwtClaimsSetVerifier = TimeChecks()
        }
        jwtProcessor.process(signedJWT, null)
    } catch (e: Throwable) {
        e.printStackTrace()
        throw RuntimeException(e)
    }

    // build auth request
    val jsonStr = Gson().toJson(signedJWT.jwtClaimsSet.getJSONObjectClaim("presentation_definition"))
    val presentationDefinition = Json.parseToJsonElement(jsonStr).jsonObject
    Logger.i(TAG, "presentation_definition: $jsonStr")
    Logger.i(TAG, "Claims Set: ${signedJWT.jwtClaimsSet}")

    // Check the response mode. This is required as part of mdoc profile; NOTE that sd-jwt profile
    // requires direct_post.
    val responseMode = signedJWT.jwtClaimsSet.getStringClaim("response_mode")
    val allowedResponseModes = setOf("direct_post", "direct_post.jwt")
    if (!allowedResponseModes.contains(responseMode)) {
        throw IllegalArgumentException("Response mode $responseMode is unsupported. " +
                "Supported modes are: ${allowedResponseModes.sorted().joinToString()}")
    }
    if (signedJWT.jwtClaimsSet.getStringClaim("response_type") != "vp_token") { // not supporting id_token atm
        throw IllegalArgumentException("Response types other than vp_token are unsupported.")
    }

    val responseUri = getResponseUri(signedJWT.jwtClaimsSet)
    return AuthorizationRequest(
        presentationDefinition = presentationDefinition,
        clientId = signedJWT.jwtClaimsSet.getStringClaim("client_id"),
        nonce = signedJWT.jwtClaimsSet.getStringClaim("nonce"),
        responseUri = responseUri,
        state = signedJWT.jwtClaimsSet.getStringClaim("state"),
        clientMetadata = Json.parseToJsonElement(Gson().toJson(signedJWT.jwtClaimsSet.getJSONObjectClaim("client_metadata"))).jsonObject,
        certificateChain = pubCertChain
    )
}

private fun getResponseUri(claimsSet: JWTClaimsSet): String {
    val uri = claimsSet.getStringClaim("response_uri") ?:
        claimsSet.getStringClaim("redirect_uri")
    if (!uri.startsWith("http://") &&
        !uri.startsWith("https://")) {
        // TODO: This is overly permissive, but it's required for some verifiers. Remove it?
        Logger.w(TAG, "Response URI is not absolute. Modifying to add https://")
        return "https://$uri"
    }
    return uri
}

private class TimeChecks : JWTClaimsSetVerifier<SecurityContext> {
    @Throws(BadJWTException::class)
    override fun verify(claimsSet: JWTClaimsSet, context: SecurityContext?) {
        val now = Clock.System.now()

        val expiration = claimsSet.expirationTime
        var exp: Instant? = null
        if (expiration != null) {
            exp = Instant.fromEpochMilliseconds(expiration.time)
            if (exp <= now) {
                throw BadJWTException("Expired JWT ($exp <= $now)")
            }
        }

        val issuance = claimsSet.issueTime
        var iat: Instant? = null
        if (issuance != null) {
            iat = Instant.fromEpochMilliseconds(issuance.time)
            if (now < iat) {
                throw BadJWTException("JWT issued in the future ($now < $iat)")
            }

            if (exp != null) {
                if (exp <= iat) {
                    throw BadJWTException("JWT issued after expiration ($exp <= $iat")
                }
            }
        }

        val notBefore = claimsSet.notBeforeTime
        if (notBefore != null) {
            val nbf = Instant.fromEpochMilliseconds(notBefore.time)
            if (nbf >= now) {
                throw BadJWTException("JWT not yet active ($nbf >= $now)")
            }

            if (exp != null) {
                if (nbf >= exp) {
                    throw BadJWTException("JWT active after expiration ($nbf >= $exp)")
                }
            }

            if (iat != null) {
                if (nbf < iat) {
                    throw BadJWTException("JWT active before issuance ($nbf < $iat)")
                }
            }
        }
    }
}

private fun getFormat(
    clientMetadata: JsonObject,
    presentationDefinition: JsonObject
): CredentialFormat {
    // Since we only return a single format, we order acceptedFormats such that preferred formats
    // are first.
    val acceptedFormats = listOf(
        "mso_mdoc" to CredentialFormat.MDOC_MSO,
        "jwt_vc" to CredentialFormat.SD_JWT_VC,
        "vc+sd-jwt" to CredentialFormat.SD_JWT_VC)

    // If the clientMetadata has a exactly one format, return that.
    if (clientMetadata.containsKey("vp_formats")) {
        val vpFormats = clientMetadata["vp_formats"]!!.jsonObject.keys
        if (vpFormats.size == 1) {
            for ((format, credentialFormat) in acceptedFormats) {
                if (vpFormats.contains(format)) {
                    return credentialFormat
                }
            }
            throw IllegalArgumentException("No supported formats found in: ${vpFormats.sorted().joinToString()}")
        }
    }

    // If clientMetadata has 0 or 2+ formats, use presentation_definition -> input_descriptors
    // -> format.
    val inputDescriptors = presentationDefinition["input_descriptors"]!!.jsonArray
    val vpFormats = HashSet<String>()

    for (inputDescriptor: JsonElement in inputDescriptors) {
        val inputDescriptorObj = inputDescriptor.jsonObject
        val formatName = inputDescriptorObj["format"]?.jsonObject?.keys?.first()
        if (formatName != null) {
            vpFormats.add(formatName)
        }
    }

    for ((format, credentialFormat) in acceptedFormats) {
        if (vpFormats.contains(format)) {
            return credentialFormat
        }
    }
    throw IllegalArgumentException("No vp_formats found in client_metadata and no supported " +
            "formats found in input_descriptors: ${vpFormats.sorted().joinToString()}")
}

internal fun createPresentationSubmission(
    authRequest: AuthorizationRequest,
    credentialFormat: CredentialFormat
): PresentationSubmission {
    val vpFormats = when (credentialFormat) {
        CredentialFormat.MDOC_MSO -> setOf("jwt_vc", "vc+sd-jwt")
        CredentialFormat.SD_JWT_VC -> setOf("mso_mdoc")
    }

    val descriptorMaps = ArrayList<DescriptorMap>()
    val inputDescriptors = authRequest.presentationDefinition["input_descriptors"]!!.jsonArray

    for (inputDescriptor: JsonElement in inputDescriptors) {
        val inputDescriptorObj = inputDescriptor.jsonObject
        val docType = inputDescriptorObj["id"]!!.toString().run { substring(1, this.length - 1) }
        val formatName = inputDescriptorObj["format"]?.jsonObject?.keys?.first()
        if (formatName != null && vpFormats.contains(formatName)) {
            descriptorMaps.add(DescriptorMap(
                id = docType,
                format = formatName,
                path = "$"
            ))
        }
    }

    return PresentationSubmission(
        id = UUID.randomUUID().toString(),
        definitionId = authRequest.presentationDefinition["id"]!!.toString().run { substring(1, this.length - 1) },
        descriptorMaps = descriptorMaps
    )
}

internal fun formatAsDocumentRequest(inputDescriptor: JsonObject): DocumentRequest {
    val requestedDataElements = ArrayList<DocumentRequest.DataElement>()
    val constraints = inputDescriptor["constraints"]!!.jsonObject
    val fields = constraints["fields"]!!.jsonArray

    for (field: JsonElement in fields) {
        val fieldObj = field.jsonObject
        val path = fieldObj["path"]!!.jsonArray[0].toString()
        val intentToRetain = fieldObj["intent_to_retain"].toString()
        val parsed = parsePathItem(path)
        requestedDataElements.add(DocumentRequest.DataElement(
            nameSpaceName = parsed.first,
            dataElementName = parsed.second,
            intentToRetain = intentToRetain == "true"
        ))
    }
    return DocumentRequest(requestedDataElements)
}

/**
 * Helper function to generate a list of entries for the consent prompt for VCs.
 *
 * TODO: Move to VcConsentField when making identity-sdjwt a Kotlin Multiplatform library.
 *
 * @param vct the Verifiable Credential Type.
 * @param claims the list of claims.
 * @param documentTypeRepository a [DocumentTypeRepository] used to determine the display name.
 * @param vcCredential if set, the returned list is filtered so it only references claims
 *     available in the credential.
 */
private fun VcClaim.Companion.generateClaims(
    vct: String,
    claims: List<String>,
    documentTypeRepository: DocumentTypeRepository,
    vcCredential: SdJwtVcCredential?,
): List<VcClaim> {
    val vcType = documentTypeRepository.getDocumentTypeForVc(vct)?.vcDocumentType
    val ret = mutableListOf<VcClaim>()
    for (claimName in claims) {
        val attribute = vcType?.claims?.get(claimName)
        ret.add(
            VcClaim(
                attribute?.displayName ?: claimName,
                attribute,
                claimName
            )
        )
    }
    return filterConsentFields(ret, vcCredential)
}

private fun filterConsentFields(
    list: List<VcClaim>,
    credential: SdJwtVcCredential?
): List<VcClaim> {
    if (credential == null) {
        return list
    }
    val sdJwt = SdJwtVerifiableCredential.fromString(
        String(credential.issuerProvidedData, Charsets.US_ASCII))

    val availableClaims = mutableSetOf<String>()
    for (disclosure in sdJwt.disclosures) {
        availableClaims.add(disclosure.key)
    }
    return list.filter { vcConsentField ->
        availableClaims.contains(vcConsentField.claimName)
    }
}
