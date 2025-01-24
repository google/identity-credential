package com.android.identity.issuance

import com.android.identity.cbor.annotation.CborSerializable
import kotlinx.datetime.Instant

/**
 * Information about the capabilities of the wallet application, for the wallet server.
 *
 * @property generatedAt The point in time this data was generated.
 * @property androidKeystoreAttestKeyAvailable Whether Android Keystore supports attest keys.
 * @property androidKeystoreStrongBoxAvailable Whether StrongBox is available on the device.
 * @property androidIsEmulator Whether the app is running on an emulator.
 */
@CborSerializable
data class WalletApplicationCapabilities(
    val generatedAt: Instant,
    val androidKeystoreAttestKeyAvailable: Boolean,
    val androidKeystoreStrongBoxAvailable: Boolean,
    val androidIsEmulator: Boolean,
    val directAccessSupported: Boolean,
) {
    companion object
}
