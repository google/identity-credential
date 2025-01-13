package com.android.identity_credential.wallet.ui.destination.provisioncredential

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.util.Base64
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.android.identity.android.mdoc.util.CredmanUtil
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.request.Claim
import com.android.identity.request.Requester
import com.android.identity.credential.Credential
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.issuance.IssuingAuthorityException
import com.android.identity.issuance.evidence.EvidenceRequestCompletionMessage
import com.android.identity.issuance.evidence.EvidenceRequestCreatePassphrase
import com.android.identity.issuance.evidence.EvidenceRequestGermanEid
import com.android.identity.issuance.evidence.EvidenceRequestIcaoNfcTunnel
import com.android.identity.issuance.evidence.EvidenceRequestIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceRequestMessage
import com.android.identity.issuance.evidence.EvidenceRequestNotificationPermission
import com.android.identity.issuance.evidence.EvidenceRequestOpenid4Vp
import com.android.identity.issuance.evidence.EvidenceRequestCredentialOffer
import com.android.identity.issuance.evidence.EvidenceRequestQuestionMultipleChoice
import com.android.identity.issuance.evidence.EvidenceRequestQuestionString
import com.android.identity.issuance.evidence.EvidenceRequestSelfieVideo
import com.android.identity.issuance.evidence.EvidenceRequestSetupCloudSecureArea
import com.android.identity.issuance.evidence.EvidenceRequestWeb
import com.android.identity.issuance.evidence.EvidenceResponseCreatePassphrase
import com.android.identity.issuance.evidence.EvidenceResponseQuestionMultipleChoice
import com.android.identity.issuance.evidence.EvidenceResponseQuestionString
import com.android.identity.issuance.evidence.EvidenceResponseSetupCloudSecureArea
import com.android.identity.issuance.remote.WalletServerProvider
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.request.MdocClaim
import com.android.identity.request.MdocRequest
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.util.fromBase64Url
import com.android.identity.util.toBase64Url
import com.android.identity_credential.wallet.PermissionTracker
import com.android.identity_credential.wallet.ProvisioningViewModel
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.WalletApplication
import com.android.identity_credential.wallet.navigation.WalletDestination
import com.android.identity_credential.wallet.presentation.showMdocPresentmentFlow
import com.android.identity_credential.wallet.ui.ScreenWithAppBar
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONObject
import java.util.StringTokenizer
import kotlin.random.Random

private const val TAG = "ProvisionCredentialScreen"

@Composable
fun ProvisionDocumentScreen(
    application: WalletApplication,
    secureAreaRepository: SecureAreaRepository,
    provisioningViewModel: ProvisioningViewModel,
    onNavigate: (String) -> Unit,
    permissionTracker: PermissionTracker,
    walletServerProvider: WalletServerProvider,
    developerMode: Boolean = false
) {
    val context = application.applicationContext

    ScreenWithAppBar(title = stringResource(R.string.provisioning_title), navigationIcon = {
        if (provisioningViewModel.state.value != ProvisioningViewModel.State.PROOFING_COMPLETE) {
            IconButton(
                onClick = {
                    onNavigate(WalletDestination.PopBackStack.route)
                }
            ) {
                Icon(
                    imageVector = Icons.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.accessibility_go_back_icon)
                )
            }
        }
    }
    ) {
        when (provisioningViewModel.state.value) {
            ProvisioningViewModel.State.IDLE -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        modifier = Modifier.padding(8.dp),
                        text = stringResource(R.string.provisioning_idle)
                    )
                }
            }

            ProvisioningViewModel.State.CREDENTIAL_REGISTRATION -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        modifier = Modifier.padding(8.dp),
                        text = stringResource(R.string.provisioning_creating_key)
                    )
                }
            }

            ProvisioningViewModel.State.EVIDENCE_REQUESTS_READY -> {
                // TODO: for now we just consider the first evidence request
                val evidenceRequest = provisioningViewModel.nextEvidenceRequest.value!!
                println("evidence request: $evidenceRequest")
                when (evidenceRequest) {
                    is EvidenceRequestQuestionString -> {
                        EvidenceRequestQuestionStringView(
                            evidenceRequest,
                            onAccept = { inputString ->
                                provisioningViewModel.provideEvidence(
                                    evidence = EvidenceResponseQuestionString(inputString)
                                )
                            }
                        )
                    }

                    is EvidenceRequestCreatePassphrase -> {
                        EvidenceRequestCreatePassphraseView(
                            context = context,
                            evidenceRequest,
                            onAccept = { inputString ->
                                provisioningViewModel.provideEvidence(
                                    evidence = EvidenceResponseCreatePassphrase(inputString)
                                )
                            }
                        )
                    }

                    is EvidenceRequestSetupCloudSecureArea -> {
                        EvidenceRequestSetupCloudSecureAreaView(
                            context = context,
                            secureAreaRepository = secureAreaRepository,
                            evidenceRequest,
                            onAccept = {
                                provisioningViewModel.provideEvidence(
                                    evidence = EvidenceResponseSetupCloudSecureArea(
                                        evidenceRequest.cloudSecureAreaIdentifier)
                                )
                            },
                            onError = { error ->
                                provisioningViewModel.evidenceCollectionFailed(
                                    error = error
                                )
                            }
                        )
                    }

                    is EvidenceRequestMessage -> {
                        EvidenceRequestMessageView(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel
                        )
                    }

                    is EvidenceRequestCompletionMessage -> {
                        EvidenceRequestCompletedScreen(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel
                        )
                    }

                    is EvidenceRequestNotificationPermission -> {
                        EvidenceRequestNotificationPermissionView(
                            evidenceRequest,
                            provisioningViewModel = provisioningViewModel
                        )
                    }

                    is EvidenceRequestQuestionMultipleChoice -> {
                        EvidenceRequestQuestionMultipleChoiceView(
                            evidenceRequest,
                            onAccept = { selectedOption ->
                                provisioningViewModel.provideEvidence(
                                    evidence = EvidenceResponseQuestionMultipleChoice(selectedOption)
                                )
                            }
                        )
                    }

                    is EvidenceRequestIcaoPassiveAuthentication -> {
                        EvidenceRequestIcaoPassiveAuthenticationView(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel,
                            permissionTracker = permissionTracker
                        )
                    }

                    is EvidenceRequestIcaoNfcTunnel -> {
                        EvidenceRequestIcaoNfcTunnelView(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel,
                            permissionTracker = permissionTracker,
                            developerMode = developerMode

                        )
                    }

                    is EvidenceRequestSelfieVideo -> {
                        EvidenceRequestSelfieVideoView(
                            evidenceRequest,
                            provisioningViewModel = provisioningViewModel,
                            permissionTracker = permissionTracker
                        )
                    }

                    is EvidenceRequestGermanEid -> {
                        EvidenceRequestEIdView(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel
                        )
                    }

                    is EvidenceRequestWeb -> {
                        EvidenceRequestWebView(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel,
                            walletServerProvider = walletServerProvider
                        )
                    }

                    is EvidenceRequestOpenid4Vp -> {
                        EvidenceRequestOpenid4Vp(
                            evidenceRequest = evidenceRequest,
                            provisioningViewModel = provisioningViewModel,
                            application = application
                        )
                    }

                    is EvidenceRequestCredentialOffer -> {
                        // should have been processed by the model internally
                        Logger.e(TAG, "Unexpected evidence request type: EvidenceRequestPreauthorizedCode")
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Text(
                                modifier = Modifier.padding(8.dp),
                                style = MaterialTheme.typography.titleLarge,
                                textAlign = TextAlign.Center,
                                text = stringResource(R.string.provisioning_request_unexpected)
                            )
                        }
                    }
                }
            }

            ProvisioningViewModel.State.SUBMITTING_EVIDENCE -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge,
                        textAlign = TextAlign.Center,
                        text = stringResource(R.string.provisioning_submitting)
                    )
                }
            }

            ProvisioningViewModel.State.PROOFING_COMPLETE -> {
                onNavigate(
                    WalletDestination.PopBackStack
                        .getRouteWithArguments(
                            listOf(
                                Pair(
                                    WalletDestination.PopBackStack.Argument.ROUTE,
                                    WalletDestination.Main.route
                                ),
                                Pair(
                                    WalletDestination.PopBackStack.Argument.INCLUSIVE,
                                    false
                                )
                            )
                        )
                )
            }

            ProvisioningViewModel.State.FAILED -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    val error = provisioningViewModel.error
                    Text(
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge,
                        textAlign = TextAlign.Center,
                        text = if (error is IssuingAuthorityException) {
                            error.message!!  // Human-readable message from the server
                        } else {
                            stringResource(R.string.provisioning_error,
                                provisioningViewModel.error.toString())
                        }
                    )
                }
            }

            else -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        modifier = Modifier.padding(8.dp),
                        style = MaterialTheme.typography.titleLarge,
                        textAlign = TextAlign.Center,
                        text = stringResource(R.string.provisioning_unexpected,
                            provisioningViewModel.state.value)
                    )
                }
            }
        }
    }
}

fun getFragmentActivity(cx: Context): FragmentActivity {
    var context = cx
    while (context is ContextWrapper) {
        if (context is Activity) {
            if (context is FragmentActivity) {
                return context
            }
            break
        }
        context = context.baseContext
    }

    throw IllegalStateException("Not a FragmentActivity")
}

suspend fun openid4VpPresentation(
    credential: Credential,
    walletApp: WalletApplication,
    fragmentActivity: FragmentActivity,
    originUri: String,
    request: String
): String {
    val parts = request.split('.')
    val openid4vpRequest = JSONObject(String(parts[1].fromBase64Url()))
    val nonceBase64 = openid4vpRequest.getString("nonce")
    val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP or Base64.URL_SAFE)
    val clientID = openid4vpRequest.getString("client_id")

    val presentationDefinition = openid4vpRequest.getJSONObject("presentation_definition")
    val inputDescriptors = presentationDefinition.getJSONArray("input_descriptors")
    if (inputDescriptors.length() != 1) {
        throw IllegalArgumentException("Only support a single input input_descriptor")
    }
    val inputDescriptor = inputDescriptors.getJSONObject(0)!!
    val docType = inputDescriptor.getString("id")

    val constraints = inputDescriptor.getJSONObject("constraints")
    val fields = constraints.getJSONArray("fields")

    val requestedData = mutableMapOf<String, MutableList<Pair<String, Boolean>>>()

    for (n in 0 until fields.length()) {
        val field = fields.getJSONObject(n)
        // Only support a single path entry for now
        val path = field.getJSONArray("path").getString(0)!!
        // JSONPath is horrible, hacky way to parse it for demonstration purposes
        val st = StringTokenizer(path, "'", false).asSequence().toList()
        val namespace = st[1] as String
        val name = st[3] as String
        val intentToRetain = field.getBoolean("intent_to_retain")
        requestedData.getOrPut(namespace) { mutableListOf() }
            .add(Pair(name, intentToRetain))
    }

    val claims = MdocUtil.generateClaims(
        docType,
        requestedData,
        walletApp.documentTypeRepository,
        credential as MdocCredential
    )

    // Generate the Session Transcript
    val encodedSessionTranscript = CredmanUtil.generateBrowserSessionTranscript(
        nonce,
        originUri,
        Crypto.digest(Algorithm.SHA256, clientID.toByteArray())
    )
    val deviceResponse = showPresentmentFlowAndGetDeviceResponse(
        fragmentActivity,
        credential,
        claims,
        null,
        originUri,
        encodedSessionTranscript
    )

    val clientMetadata = openid4vpRequest.getJSONObject("client_metadata")
    val encryptionAlg = clientMetadata.getString("authorization_encrypted_response_alg")
    val encryptionEnc = clientMetadata.getString("authorization_encrypted_response_enc")

    // Create the openid4vp response
    val responseBody = buildJsonObject {
        if (openid4vpRequest.has("state")) {
            put("state", openid4vpRequest.getString("state"))
        }
        put("vp_token", deviceResponse.toBase64Url())

        // TODO: do we need this?
        //put("presentation_submission", Json.encodeToJsonElement(presentationSubmission))
    }.toString()

    val jwt = maybeEncryptJwtResponse(JWTClaimsSet.parse(responseBody),
        encryptionAlg, encryptionEnc, nonce, clientMetadata.getJSONObject("jwks").toString())

    return jwt.serialize()
}

private fun maybeEncryptJwtResponse(
    claimSet: JWTClaimsSet,
    encryptedResponseAlg: String?,
    encryptedResponseEnc: String?,
    requestNonce: ByteArray,
    jwks: String
): JWT {
    return if (encryptedResponseAlg == null || encryptedResponseEnc == null) {
        PlainJWT(claimSet)
    } else {
        val generatedNonce = Random.nextBytes(15)
        val apv = Base64URL.encode(requestNonce)
        val apu = Base64URL.encode(generatedNonce)
        val responseEncryptionAlg = JWEAlgorithm.parse(encryptedResponseAlg)
        val responseEncryptionMethod = EncryptionMethod.parse(encryptedResponseEnc)
        val jweHeader = JWEHeader.Builder(responseEncryptionAlg, responseEncryptionMethod)
            .apply {
                apv.let(::agreementPartyVInfo)
                apu.let(::agreementPartyUInfo)
            }
            .build()
        val keySet = JWKSet.parse(jwks)
        val jweEncrypter: ECDHEncrypter? = keySet.keys.mapNotNull { key ->
            runCatching { ECDHEncrypter(key as ECKey) }.getOrNull()
                ?.let { encrypter -> key to encrypter }
        }
            .toMap().firstNotNullOfOrNull { it.value }
        EncryptedJWT(jweHeader, claimSet).apply { encrypt(jweEncrypter) }
    }
}

private suspend fun showPresentmentFlowAndGetDeviceResponse(
    fragmentActivity: FragmentActivity,
    mdocCredential: MdocCredential,
    claims: List<Claim>,
    trustPoint: TrustPoint?,
    websiteOrigin: String?,
    encodedSessionTranscript: ByteArray,
): ByteArray {
    val request = MdocRequest(
        requester = Requester(websiteOrigin = websiteOrigin),
        claims = claims as List<MdocClaim>,
        docType = mdocCredential.docType
    )
    val documentCborBytes = showMdocPresentmentFlow(
        activity = fragmentActivity,
        request = request,
        trustPoint = trustPoint,
        document = ConsentDocument(
            name = mdocCredential.document.documentConfiguration.displayName,
            description = mdocCredential.document.documentConfiguration.typeDisplayName,
            cardArt = mdocCredential.document.documentConfiguration.cardArt,
        ),
        credential = mdocCredential,
        encodedSessionTranscript = encodedSessionTranscript,
    )
    // Create ISO DeviceResponse
    DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK).run {
        addDocument(documentCborBytes)
        return generate()
    }
}
