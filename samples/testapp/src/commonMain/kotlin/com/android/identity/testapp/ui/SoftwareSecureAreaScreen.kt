package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.securearea.software.SoftwareCreateKeySettings
import com.android.identity.securearea.software.SoftwareKeyUnlockData
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.storage.ephemeral.EphemeralStorage
import com.android.identity.util.Logger
import com.android.identity.util.toHex
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import org.jetbrains.compose.ui.tooling.preview.Preview

private val TAG = "SoftwareSecureAreaScreen"

private val softwareSecureAreaProvider = SecureAreaProvider {
    SoftwareSecureArea.create(EphemeralStorage())
}

private data class swPassphraseTestConfiguration(
    val keyPurpose: KeyPurpose,
    val curve: EcCurve,
    val description: String
)

@Preview
@Composable
fun SoftwareSecureAreaScreen(
    showToast: (message: String) -> Unit
) {
    val coroutineScope = rememberCoroutineScope()

    val swShowPassphraseDialog = remember {
        mutableStateOf<swPassphraseTestConfiguration?>(null)
    }

    if (swShowPassphraseDialog.value != null) {
        ShowPassphraseDialog(
            onDismissRequest = {
                swShowPassphraseDialog.value = null;
            },
            onContinueButtonClicked = { passphraseEnteredByUser: String ->
                val configuration = swShowPassphraseDialog.value!!
                coroutineScope.launch {
                    swTest(
                        configuration.keyPurpose,
                        configuration.curve,
                        "1111",
                        passphraseEnteredByUser,
                        showToast
                    )
                    swShowPassphraseDialog.value = null
                }
            }
        )
    }

    LazyColumn(
        modifier = Modifier.padding(8.dp)
    ) {
        for ((keyPurpose, keyPurposeDesc) in arrayOf(
            Pair(KeyPurpose.SIGN, "Signature"),
            Pair(KeyPurpose.AGREE_KEY, "Key Agreement")
        )) {
            for ((curve, curveName, purposes) in arrayOf(
                Triple(EcCurve.P256, "P-256", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.P384, "P-384", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.P521, "P-521", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.BRAINPOOLP256R1, "Brainpool 256", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.BRAINPOOLP320R1, "Brainpool 320", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.BRAINPOOLP384R1, "Brainpool 384", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.BRAINPOOLP512R1, "Brainpool 512", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.ED25519, "Ed25519", setOf(KeyPurpose.SIGN)),
                Triple(EcCurve.X25519, "X25519", setOf(KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.ED448, "Ed448", setOf(KeyPurpose.SIGN)),
                Triple(EcCurve.X448, "X448", setOf(KeyPurpose.AGREE_KEY)),
            )) {
                if (!purposes.contains(keyPurpose)) {
                    // No common purpose
                    continue
                }
                for ((passphraseRequired, description) in arrayOf(
                    Pair(true, "- Passphrase"),
                    Pair(false, ""),
                )) {
                    // For brevity, only do passphrase for first item (P-256 Signature)
                    if (!(keyPurpose == KeyPurpose.SIGN && curve == EcCurve.P256)) {
                        if (passphraseRequired) {
                            continue;
                        }
                    }

                    item {
                        TextButton(onClick = {

                            if (passphraseRequired) {
                                swShowPassphraseDialog.value =
                                    swPassphraseTestConfiguration(keyPurpose, curve, description)
                            } else {
                                coroutineScope.launch {
                                    swTest(
                                        keyPurpose,
                                        curve,
                                        null,
                                        null,
                                        showToast
                                    )
                                }
                            }
                        })
                        {
                            Text(
                                text = "$curveName $keyPurposeDesc $description",
                                fontSize = 15.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ShowPassphraseDialog(
    onDismissRequest: () -> Unit,
    onContinueButtonClicked: (passphrase: String) -> Unit,
) {
    var passphraseTextField by rememberSaveable(stateSaver = TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(""))
    }
    var showPassphrase by remember { mutableStateOf(value = false) }
    Dialog(onDismissRequest = { onDismissRequest() }) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(275.dp)
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Enter passphrase to use key",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.bodyLarge
                )

                Text(
                    text = "The passphrase is '1111'.",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Start,
                    style = MaterialTheme.typography.bodyMedium
                )

                TextField(
                    value = passphraseTextField,
                    maxLines = 3,
                    onValueChange = { passphraseTextField = it },
                    textStyle = MaterialTheme.typography.bodyMedium,
                    visualTransformation = if (showPassphrase) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        if (showPassphrase) {
                            IconButton(onClick = { showPassphrase = false }) {
                                Icon(
                                    imageVector = Icons.Default.Visibility,
                                    contentDescription = "hide_password"
                                )
                            }
                        } else {
                            IconButton(
                                onClick = { showPassphrase = true }) {
                                Icon(
                                    imageVector = Icons.Default.VisibilityOff,
                                    contentDescription = "hide_password"
                                )
                            }
                        }
                    }
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(
                        onClick = { onDismissRequest() },
                    ) {
                        Text("Cancel")
                    }
                    TextButton(
                        onClick = { onContinueButtonClicked(passphraseTextField.text) },
                    ) {
                        Text("Continue")
                    }
                }

            }
        }
    }
}

private suspend fun swTest(
    keyPurpose: KeyPurpose,
    curve: EcCurve,
    passphrase: String?,
    passphraseEnteredByUser: String?,
    showToast: (message: String) -> Unit) {
    Logger.d(
        TAG,
        "swTest keyPurpose:$keyPurpose curve:$curve passphrase:$passphrase"
    )
    try {
        swTestUnguarded(keyPurpose, curve, passphrase, passphraseEnteredByUser, showToast)
    } catch (e: Throwable) {
        e.printStackTrace();
        showToast("${e.message}")
    }
}

private suspend fun swTestUnguarded(
    keyPurpose: KeyPurpose,
    curve: EcCurve,
    passphrase: String?,
    passphraseEnteredByUser: String?,
    showToast: (message: String) -> Unit) {

    val builder = SoftwareCreateKeySettings.Builder()
        .setEcCurve(curve)
        .setKeyPurposes(setOf(keyPurpose))
    if (passphrase != null) {
        builder.setPassphraseRequired(true, passphrase, null)
    }

    val softwareSecureArea = softwareSecureAreaProvider.get()

    softwareSecureArea.createKey("testKey", builder.build())

    var unlockData: KeyUnlockData? = null
    if (passphraseEnteredByUser != null) {
        unlockData = SoftwareKeyUnlockData(passphraseEnteredByUser)
    }

    if (keyPurpose == KeyPurpose.SIGN) {
        val signingAlgorithm = curve.defaultSigningAlgorithm
        try {
            val t0 = Clock.System.now()
            val signature = softwareSecureArea.sign(
                "testKey",
                signingAlgorithm,
                "data".encodeToByteArray(),
                unlockData)
            val t1 = Clock.System.now()
            Logger.d(
                TAG,
                "Made signature with key without authentication " +
                        "r=${signature.r.toHex()} s=${signature.s.toHex()}"
            )
            showToast("Signed w/o authn (${t1 - t0})")
        } catch (e: KeyLockedException) {
            e.printStackTrace();
            showToast("${e.message}")
        }
    } else {
        val otherKeyPairForEcdh = Crypto.createEcPrivateKey(curve)
        try {
            val t0 = Clock.System.now()
            val Zab = softwareSecureArea.keyAgreement(
                "testKey",
                otherKeyPairForEcdh.publicKey,
                unlockData)
            val t1 = Clock.System.now()
            Logger.dHex(
                TAG,
                "Calculated ECDH without authentication",
                Zab)
            showToast("ECDH w/o authn (${t1 - t0})")
        } catch (e: KeyLockedException) {
            e.printStackTrace();
            showToast("${e.message}")
        }
    }
}

