package com.android.identity.device

import com.android.identity.android.securearea.AndroidKeystoreCreateKeySettings
import com.android.identity.crypto.Algorithm
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea
import com.android.identity.util.toBase64Url
import kotlinx.io.bytestring.ByteString
import kotlin.random.Random

/**
 * Generates statements validating device/app/OS integrity. Details of these
 * statements are inherently platform-specific.
 */
actual object DeviceCheck {
    actual suspend fun generateAttestation(
        secureArea: SecureArea,
        clientId: String
    ): DeviceAttestationResult {
        val keySettings = AndroidKeystoreCreateKeySettings.Builder(clientId.encodeToByteArray())
            .build()
        val alias = secureArea.createKey(null, keySettings)
        val keyInfo = secureArea.getKeyInfo(alias)
        return DeviceAttestationResult(
            deviceAttestationId = alias,
            deviceAttestation = DeviceAttestationAndroid(keyInfo.attestation.certChain!!)
        )
    }

    actual suspend fun generateAssertion(
        secureArea: SecureArea,
        deviceAttestationId: String,
        assertion: Assertion
    ): DeviceAssertion {
        val assertionData = assertion.toCbor()
        val signature = secureArea.sign(
            alias = deviceAttestationId,
            signatureAlgorithm = Algorithm.ES256,
            dataToSign = assertionData,
            keyUnlockData = null
        )
        return DeviceAssertion(
            assertionData = ByteString(assertionData),
            platformAssertion = ByteString(signature.toCoseEncoded())
        )
    }
}