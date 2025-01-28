package com.android.identity.issuance.hardcoded

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.flow.annotation.FlowMethod
import com.android.identity.flow.annotation.FlowState
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.issuance.ProofingFlow
import com.android.identity.issuance.WalletApplicationCapabilities
import com.android.identity.issuance.WalletServerSettings
import com.android.identity.flow.cache
import com.android.identity.flow.server.getTable
import com.android.identity.issuance.evidence.EvidenceRequest
import com.android.identity.issuance.evidence.EvidenceResponse
import com.android.identity.issuance.evidence.EvidenceResponseGermanEid
import com.android.identity.issuance.evidence.EvidenceResponseGermanEidResolved
import com.android.identity.issuance.evidence.EvidenceResponseIcaoNfcTunnel
import com.android.identity.issuance.evidence.EvidenceResponseIcaoNfcTunnelResult
import com.android.identity.issuance.evidence.EvidenceResponseQuestionString
import com.android.identity.issuance.fromCbor
import com.android.identity.issuance.proofing.ProofingGraph
import com.android.identity.issuance.proofing.defaultGraph
import com.android.identity.issuance.tunnel.inProcessMrtdNfcTunnelFactory
import com.android.identity.issuance.wallet.AuthenticationState
import com.android.identity.mrtd.MrtdAccessDataCan
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.readBytes

/**
 * State of [ProofingFlow] RPC implementation.
 */
@FlowState(flowInterface = ProofingFlow::class)
@CborSerializable
class ProofingState(
    val clientId: String,
    val documentId: String = "",
    val issuingAuthorityId: String = "",
    val developerModeEnabled: Boolean = false,
    var state: String? = null,
    var done: Boolean = false,
    var nfcTunnelToken: String? = null,
    var pendingTunnelRequest: EvidenceRequest? = null,
    val evidence: MutableMap<String, EvidenceResponse> = mutableMapOf()
) {
    companion object {
        val tunnelProvider = inProcessMrtdNfcTunnelFactory
    }

    @FlowMethod
    suspend fun getEvidenceRequests(env: FlowEnvironment): List<EvidenceRequest> {
        if (done) {
            return listOf()
        }
        if (pendingTunnelRequest != null) {
            val request = pendingTunnelRequest!!
            pendingTunnelRequest = null
            return listOf(request)
        }
        val graph = getGraph(env)
        if (state == null) {
            state = graph.root.nodeId
        }
        return graph.map[state]!!.requests
    }

    @FlowMethod
    suspend fun sendEvidence(env: FlowEnvironment, evidenceResponse: EvidenceResponse) {
        val graph = getGraph(env)
        val node = graph.map[state]
        // Certain evidence types require special processing
        val newEvidence = when (evidenceResponse) {
            is EvidenceResponseIcaoNfcTunnel -> {
                // MRTD tunnel is a special case
                val tunnel = if (nfcTunnelToken == null) {
                    val dataGroups = (node as ProofingGraph.IcaoNfcTunnelNode).dataGroups
                    val mrtdAccessData = if (evidence.containsKey("mrtd_can")) {
                        MrtdAccessDataCan((evidence["mrtd_can"] as EvidenceResponseQuestionString).answer)
                    } else {
                        null
                    }
                    tunnelProvider.acquire(dataGroups, mrtdAccessData)
                } else {
                    tunnelProvider.getByToken(nfcTunnelToken!!)
                }
                val nextRequest = tunnel.handleNfcTunnelResponse(evidenceResponse)
                if (nextRequest == null) {
                    // end if tunnel workflow; do not send to the client, instead save collected
                    // evidence and move on to the next node in the evidence collection graph.
                    nfcTunnelToken = null
                    tunnel.complete()
                } else {
                    nfcTunnelToken = tunnel.token
                    pendingTunnelRequest = nextRequest
                    return
                }
            }
            is EvidenceResponseIcaoNfcTunnelResult -> {
                throw IllegalArgumentException("illegal evidence type")
            }
            is EvidenceResponseGermanEid -> {
                val data = if (evidenceResponse.url != null) {
                    val httpClient = env.getInterface(HttpClient::class)!!
                    val response = httpClient.get("${evidenceResponse.url}&mode=json") {}
                    String(response.readBytes())
                } else {
                    null
                }
                EvidenceResponseGermanEidResolved(
                    complete = evidenceResponse.complete,
                    status = evidenceResponse.status,
                    data = data
                )
            }
            is EvidenceResponseGermanEidResolved -> {
                throw IllegalArgumentException("illegal evidence type")
            }
            else -> evidenceResponse
        }

        evidence[state!!] = newEvidence
        val followUp = node!!.selectFollowUp(newEvidence)
        if (followUp != null) {
            state = followUp.nodeId
        } else {
            done = true
        }
    }

    private suspend fun getGraph(env: FlowEnvironment): ProofingGraph {
        val storage = env.getTable(AuthenticationState.walletAppCapabilitiesTableSpec)
        val walletApplicationCapabilities = storage.get(clientId)?.let {
            WalletApplicationCapabilities.fromCbor(it.toByteArray())
        } ?: throw IllegalStateException("WalletApplicationCapabilities not found")

        val key = GraphKey(issuingAuthorityId, documentId, developerModeEnabled)
        return env.cache(ProofingGraph::class, key) { configuration, resources ->
            val cloudSecureAreaUrl = WalletServerSettings(configuration).cloudSecureAreaUrl
            defaultGraph(
                documentId,
                resources,
                walletApplicationCapabilities,
                developerModeEnabled,
                cloudSecureAreaUrl,
                resources.getStringResource("$issuingAuthorityId/tos.html")!!,
                mapOf("logo.png" to resources.getRawResource("$issuingAuthorityId/logo.png")!!)
            )
        }
    }

    data class GraphKey(
        val issuingAuthorityId: String,
        val documentId: String,
        val developerModeEnabled: Boolean
    )
}