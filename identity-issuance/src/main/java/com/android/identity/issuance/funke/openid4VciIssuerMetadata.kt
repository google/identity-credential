package com.android.identity.issuance.funke

import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.cache
import com.android.identity.util.Logger
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.readBytes
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

// from .well-known/openid-credential-issuer
internal data class Openid4VciIssuerMetadata(
    val credentialIssuer: String,
    val credentialEndpoint: String,
    val display: List<Openid4VciIssuerDisplay>,
    val credentialConfigurations: Map<String, Openid4VciCredentialConfiguration>,
    val authorizationServerList: List<Openid4VciAuthorizationMetadata>
) {
    companion object {
        const val TAG = "Openid4VciIssuerMetadata"

        suspend fun get(env: FlowEnvironment, issuerUrl: String): Openid4VciIssuerMetadata {
            return env.cache(Openid4VciIssuerMetadata::class, issuerUrl) { _, _ ->
                val httpClient = env.getInterface(HttpClient::class)!!

                // Fetch issuer metadata
                val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
                val issuerMetadataRequest = httpClient.get(issuerMetadataUrl) {}
                if (issuerMetadataRequest.status != HttpStatusCode.OK) {
                    throw IllegalStateException("Invalid issuer, no $issuerMetadataUrl")
                }
                val credentialMetadataText = String(issuerMetadataRequest.readBytes())
                val credentialMetadata = Json.parseToJsonElement(credentialMetadataText).jsonObject

                // Fetch authorization metadata
                val authorizationServers = credentialMetadata["authorization_servers"]?.jsonArray
                val authorizationServerUrls =
                    authorizationServers?.map { it.jsonPrimitive.content } ?: listOf(issuerUrl)
                val authorizationMetadataList = mutableListOf<Openid4VciAuthorizationMetadata>()
                for (authorizationServerUrl in authorizationServerUrls) {
                    val authorizationMetadataUrl =
                        "$authorizationServerUrl/.well-known/oauth-authorization-server"
                    val authorizationMetadataRequest = httpClient.get(authorizationMetadataUrl) {}
                    if (authorizationMetadataRequest.status != HttpStatusCode.OK) {
                        if (authorizationServerUrl != issuerUrl) {
                            Logger.e(TAG, "Invalid authorization server '$authorizationServerUrl'")
                        }
                        continue
                    }
                    val authorizationMetadataText = String(authorizationMetadataRequest.readBytes())
                    val authorizationMetadata =
                        extractAuthorizationServerMetadata(
                            url = authorizationServerUrl,
                            jsonObject = Json.parseToJsonElement(authorizationMetadataText).jsonObject
                        )
                    if (authorizationMetadata != null) {
                        authorizationMetadataList.add(authorizationMetadata)
                    }
                }
                Openid4VciIssuerMetadata(
                    credentialIssuer = credentialMetadata["credential_issuer"]?.jsonPrimitive?.content ?: issuerUrl,
                    credentialEndpoint = credentialMetadata["credential_endpoint"]!!.jsonPrimitive.content,
                    display = extractDisplay(credentialMetadata["display"]),
                    authorizationServerList = authorizationMetadataList.toList(),
                    credentialConfigurations =
                        credentialMetadata["credential_configurations_supported"]!!.jsonObject.mapValues {
                            val obj = it.value.jsonObject
                            val credentialSigningAlgorithms =
                                obj["credential_signing_alg_values_supported"]
                                    ?: obj["cryptographic_suites_supported"]!!  // Deprecated name
                            Openid4VciCredentialConfiguration(
                                id = it.key,
                                scope = obj["scope"]?.jsonPrimitive?.content,
                                cryptographicBindingMethod = preferred(
                                    obj["cryptographic_binding_methods_supported"]?.jsonArray,
                                    SUPPORTED_BINDING_METHODS
                                ),
                                credentialSigningAlgorithm = preferred(
                                    credentialSigningAlgorithms.jsonArray,
                                    SUPPORTED_SIGNATURE_ALGORITHMS
                                ),
                                proofType = extractProofType(obj["proof_types_supported"]?.jsonObject),
                                format = extractFormat(obj),
                                display = extractDisplay(obj["display"])
                            )
                        }
                )
            }
        }

        private fun preferred(available: JsonArray?, supported: List<String>): String? {
            if (available == null) {
                return "none"
            }
            val availableSet = available?.map { it.jsonPrimitive.content }?.toSet() ?: return null
            return supported.firstOrNull { availableSet.contains(it) }
        }

        private fun extractDisplay(displayJson: JsonElement?): List<Openid4VciIssuerDisplay> {
            if (displayJson == null) {
                return listOf()
            }
            return displayJson.jsonArray.map {
                val displayObj = it.jsonObject
                Openid4VciIssuerDisplay(
                    text = displayObj["name"]!!.jsonPrimitive.content,
                    locale = displayObj["locale"]?.jsonPrimitive?.content ?: "en",
                    logoUrl = displayObj["logo"]?.jsonObject?.get("uri")?.jsonPrimitive?.content
                )
            }
        }

        // Returns null if no compatible configuration could be created
        private fun extractAuthorizationServerMetadata(
            url: String,
            jsonObject: JsonObject
        ): Openid4VciAuthorizationMetadata? {
            val responseType = preferred(
                jsonObject["response_types_supported"]?.jsonArray,
                SUPPORTED_RESPONSE_TYPES
            ) ?: return null
            val codeChallengeMethod = preferred(
                jsonObject["code_challenge_methods_supported"]?.jsonArray,
                SUPPORTED_CODE_CHALLENGE_METHODS
            ) ?: return null
            val dpopSigningAlgorithm = preferred(
                jsonObject["dpop_signing_alg_values_supported"]?.jsonArray,
                SUPPORTED_SIGNATURE_ALGORITHMS
            ) ?: return null
            val authorizationEndpoint = jsonObject["authorization_endpoint"]?.jsonPrimitive?.content
            val authorizationChallengeEndpoint =
                jsonObject["authorization_challenge_endpoint"]?.jsonPrimitive?.content
            val useGermanEId = authorizationEndpoint != null &&
                    authorizationEndpoint.startsWith("https://demo.pid-issuer.bundesdruckerei.de/")
            return Openid4VciAuthorizationMetadata(
                baseUrl = url,
                pushedAuthorizationRequestEndpoint = jsonObject["pushed_authorization_request_endpoint"]?.jsonPrimitive?.content,
                authorizationEndpoint = authorizationEndpoint,
                authorizationChallengeEndpoint = authorizationChallengeEndpoint,
                tokenEndpoint = jsonObject["token_endpoint"]!!.jsonPrimitive.content,
                responseType = responseType,
                codeChallengeMethod = codeChallengeMethod,
                dpopSigningAlgorithm = dpopSigningAlgorithm,
                useGermanEId = useGermanEId
            )
        }

        private fun extractProofType(jsonObject: JsonObject?): Openid4VciProofType? {
            if (jsonObject == null) {
                return Openid4VciNoProof
            }
            val attestation = jsonObject["attestation"]?.jsonObject
            if (attestation != null) {
                val alg = preferred(
                    attestation["proof_signing_alg_values_supported"]?.jsonArray,
                    SUPPORTED_SIGNATURE_ALGORITHMS
                )
                if (alg != null) {
                    return Openid4VciProofTypeKeyAttestation(alg)
                }
            }
            val jwt = jsonObject["jwt"]?.jsonObject
            if (jwt != null) {
                val alg = preferred(
                    jwt["proof_signing_alg_values_supported"]?.jsonArray,
                    SUPPORTED_SIGNATURE_ALGORITHMS
                )
                if (alg != null) {
                    return Openid4VciProofTypeJwt(alg)
                }
            }
            return null
        }

        private fun extractFormat(jsonObject: JsonObject): Openid4VciFormat? {
            return when (jsonObject["format"]?.jsonPrimitive?.content) {
                "vc+sd-jwt" -> Openid4VciFormatSdJwt(jsonObject["vct"]!!.jsonPrimitive.content)
                "mso_mdoc" -> Openid4VciFormatMdoc(jsonObject["doctype"]!!.jsonPrimitive.content)
                else -> null
            }
        }

        // Supported methods/algorithms in the order of preference
        private val SUPPORTED_BINDING_METHODS = listOf("cose_key", "jwk")
        private val SUPPORTED_SIGNATURE_ALGORITHMS = listOf("ES256")
        private val SUPPORTED_RESPONSE_TYPES = listOf("code")
        private val SUPPORTED_CODE_CHALLENGE_METHODS = listOf("S256")
    }
}

// from .well-known/oauth-authorization-server
internal data class Openid4VciAuthorizationMetadata(
    val baseUrl: String,
    val pushedAuthorizationRequestEndpoint: String?,
    val authorizationEndpoint: String?,
    val authorizationChallengeEndpoint: String?,
    val tokenEndpoint: String,
    val responseType: String,
    val codeChallengeMethod: String,
    val dpopSigningAlgorithm: String,

    // Heuristic, only needed to support the hackish way bundesdruckerei.de does authorization
    // using Ausweis App instead of the browser-based workflow. It would be better if it was
    // exposed in server metadata somehow.
    val useGermanEId: Boolean
)

internal data class Openid4VciIssuerDisplay(
    val text: String,
    val locale: String,
    val logoUrl: String?
)

// Create a configuration object even if it is not fully supported (unsupported fields will have
// null values), so that we can have clear error messages.
internal data class Openid4VciCredentialConfiguration(
    val id: String,
    val scope: String?,
    val cryptographicBindingMethod: String?,
    val credentialSigningAlgorithm: String?,
    val proofType: Openid4VciProofType?,
    val format: Openid4VciFormat?,
    val display: List<Openid4VciIssuerDisplay>
) {
    val isSupported: Boolean get() = cryptographicBindingMethod != null &&
            credentialSigningAlgorithm != null && proofType != null && format != null
}

internal sealed class Openid4VciFormat {
    abstract val id: String
}

internal data class Openid4VciFormatMdoc(val docType: String) : Openid4VciFormat() {
    override val id: String get() = "mso_mdoc"
}

internal data class Openid4VciFormatSdJwt(val vct: String) : Openid4VciFormat() {
    override val id: String get() = "vc+sd-jwt"
}

internal sealed class Openid4VciProofType {
    abstract val id: String
}

internal object Openid4VciNoProof : Openid4VciProofType() {
    override val id: String get() = "none"
}

internal data class Openid4VciProofTypeJwt(
    val signingAlgorithm: String
) : Openid4VciProofType() {
    override val id: String get() = "jwt"
}

internal data class Openid4VciProofTypeKeyAttestation(
    val signingAlgorithm: String
) : Openid4VciProofType() {
    override val id: String get() = "attestation"
}

internal fun JsonObjectBuilder.putFormat(format: Openid4VciFormat) {
    put("format", JsonPrimitive(format.id))
    when (format) {
        is Openid4VciFormatSdJwt -> {
            put("vct", JsonPrimitive(format.vct))
        }

        is Openid4VciFormatMdoc -> {
            put("doctype", JsonPrimitive(format.docType))
        }
    }
}
