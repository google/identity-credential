package com.android.identity.server.openid4vci

import com.android.identity.crypto.X509Cert
import com.android.identity.flow.handler.InvalidRequestException
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.cache
import com.android.identity.flow.server.getTable
import com.android.identity.sdjwt.util.JsonWebKey
import com.android.identity.util.fromBase64Url
import jakarta.servlet.http.HttpServletRequest
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

suspend fun createSession(environment: FlowEnvironment, req: HttpServletRequest): String {
    // Read all parameters
    if (req.getParameter("client_assertion_type") != ParServlet.ASSERTION_TYPE) {
        throw InvalidRequestException("invalid parameter 'client_assertion_type'")
    }
    val scope = req.getParameter("scope") ?: ""
    if (!CredentialFactory.supportedScopes.contains(scope)) {
        throw InvalidRequestException("invalid parameter 'scope'")
    }
    if (req.getParameter("response_type") != "code") {
        throw InvalidRequestException("invalid parameter 'response_type'")
    }
    if (req.getParameter("code_challenge_method") != "S256") {
        throw InvalidRequestException("invalid parameter 'code_challenge_method'")
    }
    val redirectUri = req.getParameter("redirect_uri")
        ?: throw InvalidRequestException("missing parameter 'redirect_uri'")
    val clientId = req.getParameter("client_id")
        ?: throw InvalidRequestException("missing parameter 'client_id'")
    val codeChallenge = try {
        ByteString(req.getParameter("code_challenge").fromBase64Url())
    } catch (err: Exception) {
        throw InvalidRequestException("invalid parameter 'code_challenge'")
    }
    val clientAssertion = req.getParameter("client_assertion")

    // Check that client assertion is signed by the trusted client.
    val sequence = clientAssertion.split("~")
    val clientCertificate =
        environment.cache(
            ClientCertificate::class,
            clientId
        ) { configuration, resources ->
            // So in real life this should be parameterized by clientId, as different clients will
            // have different public keys.
            val certificateName = configuration.getValue("attestation.certificate")
                ?: "attestation/certificate.pem"
            val certificate = X509Cert.fromPem(resources.getStringResource(certificateName)!!)
            ClientCertificate(certificate)
        }
    checkJwtSignature(clientCertificate.certificate.ecPublicKey, sequence[0])

    // Extract session key (used in DPoP authorization for subsequent requests).
    val parts = sequence[0].split(".")
    if (parts.size != 3) {
        throw InvalidRequestException("invalid JWT assertion")
    }
    val assertionBody = Json.parseToJsonElement(String(parts[1].fromBase64Url(), Charsets.UTF_8))
    val dpopKey = JsonWebKey((assertionBody as JsonObject)["cnf"] as JsonObject).asEcPublicKey

    // Create a session
    val storage = environment.getTable(IssuanceState.tableSpec)
    val state = IssuanceState(clientId, scope, dpopKey, redirectUri, codeChallenge)
    return storage.insert(key = null, data = ByteString(state.toCbor()))
}

private data class ClientCertificate(val certificate: X509Cert)
