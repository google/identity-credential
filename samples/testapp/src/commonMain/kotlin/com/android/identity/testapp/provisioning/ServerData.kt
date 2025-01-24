package com.android.identity.testapp.provisioning

import com.android.identity.cbor.annotation.CborSerializable

@CborSerializable
data class ServerData(
    val clientId: String,
    val deviceAttestationId: String
) {
    companion object
}