package com.android.identity.issuance

import com.android.identity.cbor.Cbor
import com.android.identity.crypto.X509Cert
import com.android.identity.device.AssertionBindingKeys
import com.android.identity.device.DeviceAssertion
import com.android.identity.device.DeviceAttestation
import com.android.identity.device.DeviceAttestationIos
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.cache
import com.android.identity.securearea.KeyAttestation
import com.android.identity.util.isCloudKeyAttestation
import com.android.identity.util.validateAndroidKeyAttestation
import com.android.identity.util.validateCloudKeyAttestation
import kotlinx.io.bytestring.ByteString

suspend fun validateDeviceAssertionBindingKeys(
    env: FlowEnvironment,
    deviceAttestation: DeviceAttestation,
    keyAttestations: List<KeyAttestation>,
    deviceAssertion: DeviceAssertion,
    nonce: ByteString?
): AssertionBindingKeys {
    val settings = WalletServerSettings(env.getInterface(Configuration::class)!!)
    if (env.getInterface(ApplicationSupport::class) == null) {
        // No ApplicationSupport is indication that we are running on the server, not
        // locally in app. Device assertion validation is only meaningful or possible
        // on the server.
        deviceAttestation.validateAssertion(deviceAssertion)
    }
    val assertion = deviceAssertion.assertion as AssertionBindingKeys
    check(nonce == null || nonce == assertion.nonce)

    val keyList = keyAttestations.map { attestation ->
        val certChain = attestation.certChain
        if (certChain == null) {
            if (deviceAttestation !is DeviceAttestationIos) {
                throw IllegalArgumentException("key attestations are only optional for iOS")
            }
        } else {
            // TODO: check that what is claimed in the assertion matches what we see in key
            // attestations
            check(attestation.publicKey == certChain.certificates.first().ecPublicKey)
            if (isCloudKeyAttestation(certChain)) {
                val trustedRootKeys = getCloudSecureAreaTrustedRootKeys(env)
                validateCloudKeyAttestation(
                    attestation.certChain!!,
                    assertion.nonce,
                    trustedRootKeys.trustedKeys
                )
            } else {
                validateAndroidKeyAttestation(
                    certChain,
                    assertion.nonce,
                    settings.androidRequireGmsAttestation,
                    settings.androidRequireVerifiedBootGreen,
                    settings.androidRequireAppSignatureCertificateDigests
                )
            }
        }
        attestation.publicKey
    }

    if (keyList != assertion.publicKeys) {
        throw IllegalArgumentException("key list mismatch")
    }

    return assertion
}

private suspend fun getCloudSecureAreaTrustedRootKeys(
    env: FlowEnvironment
): CloudSecureAreaTrustedRootKeys {
    return env.cache(CloudSecureAreaTrustedRootKeys::class) { configuration, resources ->
        val certificateName = configuration.getValue("csa.certificate")
            ?: "cloud_secure_area/certificate.pem"
        val certificate = X509Cert.fromPem(resources.getStringResource(certificateName)!!)
        CloudSecureAreaTrustedRootKeys(
            trustedKeys = setOf(ByteString(Cbor.encode(certificate.ecPublicKey.toDataItem())))
        )
    }
}

internal data class CloudSecureAreaTrustedRootKeys(
    val trustedKeys: Set<ByteString>
)
