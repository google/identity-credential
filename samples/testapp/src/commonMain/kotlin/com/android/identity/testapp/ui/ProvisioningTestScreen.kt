package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.android.identity.issuance.WalletApplicationCapabilities
import com.android.identity.testapp.platformIsEmulator
import com.android.identity.testapp.provisioning.WalletServerProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock

@Composable
fun ProvisioningTestScreen() {
    val serverAddress = remember { mutableStateOf("http://localhost:8080/server") }
    LazyColumn(
        modifier = Modifier.padding(8.dp)
    ) {
        item {
            TextField(serverAddress.value, { serverAddress.value = it }, label = {
                Text("Wallet Server address")
            })
        }
        item {
            TextButton(
                onClick = {
                    CoroutineScope(Dispatchers.Default).launch {
                        val provider = WalletServerProvider(serverAddress.value) {
                                WalletApplicationCapabilities(
                                    generatedAt = Clock.System.now(),
                                    androidKeystoreAttestKeyAvailable = true,
                                    androidKeystoreStrongBoxAvailable = true,
                                    androidIsEmulator = platformIsEmulator,
                                    directAccessSupported = false,
                                )
                            }

                        val server = provider.getWalletServer()
                        println("Server: $server")
                    }
                },
                content = { Text("Test provisioning") }
            )
        }
    }
}