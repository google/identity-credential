package com.android.identity.issuance.wallet

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.device.AssertionNonce
import com.android.identity.device.DeviceAttestation
import com.android.identity.device.DeviceAttestationValidationData
import com.android.identity.flow.annotation.FlowMethod
import com.android.identity.flow.annotation.FlowState
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.Storage
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.issuance.AuthenticationFlow
import com.android.identity.issuance.ClientAuthentication
import com.android.identity.issuance.ClientChallenge
import com.android.identity.issuance.WalletServerCapabilities
import com.android.identity.issuance.WalletServerSettings
import com.android.identity.issuance.toCbor
import com.android.identity.util.toBase64Url
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlin.random.Random

@FlowState(flowInterface = AuthenticationFlow::class)
@CborSerializable
class AuthenticationState(
    var nonce: ByteString? = null,
    var clientId: String = "",
    var deviceAttestation: DeviceAttestation? = null,
    var authenticated: Boolean = false
) {
    companion object

    @FlowMethod
    suspend fun requestChallenge(env: FlowEnvironment, clientId: String): ClientChallenge {
        check(this.clientId.isEmpty())
        check(nonce != null)
        val storage = env.getInterface(Storage::class)!!
        val clientData = storage.get("Clients", "", clientId)
        if (clientData != null) {
            this.deviceAttestation =
                ClientRecord.fromCbor(clientData.toByteArray()).deviceAttestation
            this.clientId = clientId
            println("Existing client id: ${this.clientId}")
        }

        if (this.clientId.isEmpty()) {
            this.clientId = Random.Default.nextBytes(18).toBase64Url()
            println("New client id: ${this.clientId}")
        }

        return ClientChallenge(nonce!!, this.clientId)
    }

    @FlowMethod
    suspend fun authenticate(env: FlowEnvironment, auth: ClientAuthentication): WalletServerCapabilities {
        val settings = WalletServerSettings(env.getInterface(Configuration::class)!!)
        val storage = env.getInterface(Storage::class)!!

        val attestation = auth.attestation
        if (attestation != null) {
            if (this.deviceAttestation != null) {
                throw IllegalStateException("Client already registered")
            }
            attestation.validate(DeviceAttestationValidationData(
                clientId = clientId,
                iosReleaseBuild = settings.iosReleaseBuild,
                iosAppIdentifier = settings.iosAppIdentifier,
                androidGmsAttestation = settings.androidRequireGmsAttestation,
                androidVerifiedBootGreen = settings.androidRequireVerifiedBootGreen,
                androidAppSignatureCertificateDigests = listOf()
            ))
            val clientData = ByteString(ClientRecord(attestation).toCbor())
            this.deviceAttestation = attestation
            storage.insert("Clients", "", clientData, key = clientId)
        }

        this.deviceAttestation!!.validateAssertion(auth.assertion)

        if ((auth.assertion.assertion as AssertionNonce).nonce != this.nonce) {
            throw IllegalArgumentException("nonce mismatch")
        }
        authenticated = true
        if (storage.get(
            "WalletApplicationCapabilities",
            "",
            clientId,
        ) == null) {
            storage.insert(
                "WalletApplicationCapabilities",
                "",
                ByteString(auth.walletApplicationCapabilities.toCbor()),
                clientId
            )
        } else {
            storage.update(
                "WalletApplicationCapabilities",
                "",
                clientId,
                ByteString(auth.walletApplicationCapabilities.toCbor())
            )
        }
        return WalletServerCapabilities(
            Clock.System.now()
        )
    }
}