package com.android.identity.server.openid4vci

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.Simple
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.javaPrivateKey
import com.android.identity.crypto.javaPublicKey
import com.android.identity.document.NameSpacedData
import com.android.identity.flow.server.getTable
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.util.fromBase64Url
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.EncryptedJWT
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.time.Duration.Companion.minutes

class Openid4VpResponseServlet: BaseServlet() {
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val stateCode = req.getParameter("state")!!
        val id = codeToId(OpaqueIdType.OPENID4VP_STATE, stateCode)
        val state = runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            IssuanceState.fromCbor(storage.get(id)!!.toByteArray())
        }

        val encryptedJWT = EncryptedJWT.parse(req.getParameter("response")!!)

        val encPub = state.pidReadingKey!!.publicKey.javaPublicKey as ECPublicKey
        val encPriv = state.pidReadingKey!!.javaPrivateKey as ECPrivateKey

        val encKey = ECKey(
            Curve.P_256,
            encPub,
            encPriv,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        )

        val decrypter = ECDHDecrypter(encKey)
        encryptedJWT.decrypt(decrypter)

        val vpToken = encryptedJWT.jwtClaimsSet.getClaim("vp_token") as String
        val deviceResponse = vpToken.fromBase64Url()
        val responseUri = "$baseUrl/openid4vp-response"

        val sessionTranscript = createSessionTranscriptOpenID4VP(
            clientId = state.clientId,
            responseUri = responseUri,
            authorizationRequestNonce = encryptedJWT.header.agreementPartyVInfo.toString(),
            mdocGeneratedNonce = encryptedJWT.header.agreementPartyUInfo.toString()
        )

        val parser = DeviceResponseParser(deviceResponse, sessionTranscript)
        val parsedResponse = parser.parse()

        val data = NameSpacedData.Builder()
        for (document in parsedResponse.documents) {
            for (namespaceName in document.issuerNamespaces) {
                for (dataElementName in document.getIssuerEntryNames(namespaceName)) {
                    val value = document.getIssuerEntryData(namespaceName, dataElementName)
                    data.putEntry(namespaceName, dataElementName, value)
                }
            }
        }

        state.credentialData = data.build()
        runBlocking {
            val storage = environment.getTable(IssuanceState.tableSpec)
            storage.update(id, ByteString(state.toCbor()))
        }

        val presentation = idToCode(OpaqueIdType.OPENID4VP_PRESENTATION, id, 5.minutes)
        resp.writer.write(buildJsonObject {
            put("presentation_during_issuance_session", presentation)
        }.toString())
    }
}

// defined in ISO 18013-7 Annex B
private fun createSessionTranscriptOpenID4VP(
    clientId: String,
    responseUri: String,
    authorizationRequestNonce: String,
    mdocGeneratedNonce: String
): ByteArray {
    val clientIdToHash = Cbor.encode(
        CborArray.builder()
        .add(clientId)
        .add(mdocGeneratedNonce)
        .end()
        .build())
    val clientIdHash = Crypto.digest(Algorithm.SHA256, clientIdToHash)

    val responseUriToHash = Cbor.encode(
        CborArray.builder()
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
