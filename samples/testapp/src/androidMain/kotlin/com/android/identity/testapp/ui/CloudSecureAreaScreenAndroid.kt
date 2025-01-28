package com.android.identity.secure_area_test_app.ui

import android.os.ConditionVariable
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.fragment.app.FragmentActivity.MODE_PRIVATE
import com.android.identity.android.securearea.UserAuthenticationType
import com.android.identity.android.securearea.cloud.CloudCreateKeySettings
import com.android.identity.android.securearea.cloud.CloudKeyLockedException
import com.android.identity.android.securearea.cloud.CloudKeyUnlockData
import com.android.identity.android.securearea.cloud.CloudSecureArea
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.util.AndroidContexts
import com.android.identity.storage.ephemeral.EphemeralStorage
import com.android.identity.util.Logger
import com.android.identity.util.toHex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.days

private val TAG = "CloudSecureAreaScreen"

// On the Android Emulator, 10.0.2.2 points to the host so this will work
// nicely if you are running the server on the same machine you are running
// Android Studio on.
//
private val CSA_URL_DEFAULT: String = "http://10.0.2.2:8080/server/csa"
private val CSA_WALLET_PIN_DEFAULT: String = "1111"

private var cloudSecureArea: CloudSecureArea? = null

private val sharedPreferences = AndroidContexts.applicationContext.getSharedPreferences("default", MODE_PRIVATE)

private data class CsaPassphraseTestConfiguration(
    val keyPurpose: KeyPurpose,
    val curve: EcCurve,
    val authRequired: Boolean,
    val authTimeoutMillis: Long,
    val userAuthType: Set<UserAuthenticationType>,
    val biometricConfirmationRequired: Boolean,
    val passphrase: String?
)

// This is Android-only for now.
@Composable
actual fun CloudSecureAreaScreen(showToast: (message: String) -> Unit) {
    val showCertificateDialog = remember { mutableStateOf<KeyAttestation?>(null) }
    var connectText by remember { mutableStateOf(
        if (cloudSecureArea == null) {
            "Click to connect to Cloud Secure Area"
        } else {
            "Connected to ${cloudSecureArea!!.serverUrl}"
        }
    ) }
    var connectColor by remember {
        if (cloudSecureArea == null) {
            mutableStateOf(Color.Red)
        } else {
            mutableStateOf(Color.Blue)
        }
    }
    val showConnectDialog = remember { mutableStateOf(false) }
    val showPassphraseDialog = remember { mutableStateOf<CsaPassphraseTestConfiguration?>(null) }

    val coroutineScope = rememberCoroutineScope()

    if (showCertificateDialog.value != null) {
        ShowCertificateDialog(showCertificateDialog.value!!.certChain!!,
            onDismissRequest = {
                showCertificateDialog.value = null
            })
    }

    if (showPassphraseDialog.value != null) {
        ShowPassphraseDialog(
            onDismissRequest = {
                showPassphraseDialog.value = null
            },
            onContinueButtonClicked = { passphraseEnteredByUser: String ->
                val configuration = showPassphraseDialog.value!!
                coroutineScope.launch {
                    csaTest(
                        configuration.keyPurpose,
                        configuration.curve,
                        configuration.authRequired,
                        configuration.authTimeoutMillis,
                        configuration.userAuthType,
                        configuration.biometricConfirmationRequired,
                        configuration.passphrase,
                        passphraseEnteredByUser,
                        showToast
                    )
                }
                showPassphraseDialog.value = null
            }
        )
    }


    if (showConnectDialog.value) {
        CsaConnectDialog(
            sharedPreferences.getString("csaUrl", CSA_URL_DEFAULT)!!,
            CSA_WALLET_PIN_DEFAULT,
            onDismissRequest = {
                showConnectDialog.value = false
            },
            onConnectButtonClicked = { url: String, walletPin: String ->
                sharedPreferences.edit().putString("csaUrl", url).apply()
                showConnectDialog.value = false
                coroutineScope.launch {
                    cloudSecureArea = CloudSecureArea.create(
                        EphemeralStorage(),
                        "CloudSecureArea",
                        url
                    )
                    try {
                        cloudSecureArea!!.register(
                            walletPin,
                            PassphraseConstraints.PIN_SIX_DIGITS
                        ) { true }
                        showToast("Registered with CSA")
                        connectText =
                            "Connected to ${cloudSecureArea!!.serverUrl}"
                        connectColor = Color.Blue
                    } catch (e: Throwable) {
                        e.printStackTrace()
                        cloudSecureArea = null
                        showToast("${e.message}")
                    }
                }
            }
        )
    }

    LazyColumn {

        item {
            TextButton(onClick = {
                coroutineScope.launch {
                    if (cloudSecureArea != null) {
                        cloudSecureArea!!.unregister()
                        cloudSecureArea = null
                        connectText = "Click to connect to Cloud Secure Area"
                        connectColor = Color.Red
                    } else {
                        showConnectDialog.value = true
                    }
                }
            })
            {
                Text(
                    text = connectText,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = connectColor
                )
            }
        }

        item {
            TextButton(onClick = {
                CoroutineScope(Dispatchers.IO).launch {
                    val attestation = csaAttestation(showToast)
                    if (attestation != null) {
                        Logger.d(TAG, "attestation: ${attestation.certChain}")
                        showCertificateDialog.value = attestation
                    }
                }
            })
            {
                Text(
                    text = "CSA Attestation",
                    fontSize = 15.sp
                )
            }
        }

        for ((keyPurpose, keyPurposeDesc) in arrayOf(
            Pair(KeyPurpose.SIGN, "Signature"),
            Pair(KeyPurpose.AGREE_KEY, "Key Agreement")
        )) {
            for ((curve, curveName, purposes) in arrayOf(
                Triple(EcCurve.P256, "P-256", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.P384, "P-384", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.P521, "P-521", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                Triple(
                    EcCurve.BRAINPOOLP256R1,
                    "Brainpool 256",
                    setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)
                ),
                Triple(
                    EcCurve.BRAINPOOLP320R1,
                    "Brainpool 320",
                    setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)
                ),
                Triple(
                    EcCurve.BRAINPOOLP384R1,
                    "Brainpool 384",
                    setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)
                ),
                Triple(
                    EcCurve.BRAINPOOLP512R1,
                    "Brainpool 512",
                    setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)
                ),
                Triple(EcCurve.ED25519, "Ed25519", setOf(KeyPurpose.SIGN)),
                Triple(EcCurve.X25519, "X25519", setOf(KeyPurpose.AGREE_KEY)),
                Triple(EcCurve.ED448, "Ed448", setOf(KeyPurpose.SIGN)),
                Triple(EcCurve.X448, "X448", setOf(KeyPurpose.AGREE_KEY)),
            )) {
                if (!purposes.contains(keyPurpose)) {
                    // No common purpose
                    continue
                }

                for ((passphraseRequired, passphraseDescription) in arrayOf(
                    Pair(false, ""),
                    Pair(true, "- Passphrase ")
                )) {
                    for ((userAuthType, authTimeout, authDesc) in arrayOf(
                        Triple(setOf<UserAuthenticationType>(), 0L, ""),
                        Triple(
                            setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC),
                            0L,
                            "- Auth"
                        ),
                        Triple(
                            setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC),
                            10 * 1000L,
                            "- Auth (10 sec)"
                        ),
                        Triple(setOf(UserAuthenticationType.LSKF), 0L, "- Auth (LSKF Only)"),
                        Triple(
                            setOf(UserAuthenticationType.BIOMETRIC),
                            0L,
                            "- Auth (Biometric Only)"
                        ),
                        Triple(
                            setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC),
                            -1L,
                            "- Auth (No Confirmation)"
                        ),
                    )) {
                        // For brevity, only do passphrase and auth for first item (P-256 Signature)
                        if (!(curve == EcCurve.P256 && keyPurpose == KeyPurpose.SIGN)) {
                            if (!userAuthType.isEmpty() || passphraseRequired) {
                                continue
                            }
                        }

                        item {
                            TextButton(onClick = {
                                if (passphraseRequired) {
                                    showPassphraseDialog.value =
                                        CsaPassphraseTestConfiguration(
                                            keyPurpose,
                                            curve,
                                            !userAuthType.isEmpty(),
                                            if (authTimeout < 0L) 0L else authTimeout,
                                            userAuthType,
                                            authTimeout >= 0L,
                                            if (passphraseRequired) "1111" else null
                                        )
                                } else {
                                    CoroutineScope(Dispatchers.IO).launch {
                                        csaTest(
                                            keyPurpose,
                                            curve,
                                            !userAuthType.isEmpty(),
                                            if (authTimeout < 0L) 0L else authTimeout,
                                            userAuthType,
                                            authTimeout >= 0L,
                                            null,
                                            null,
                                            showToast
                                        )
                                    }
                                }
                            })
                            {
                                Text(
                                    text = "$curveName $keyPurposeDesc $passphraseDescription$authDesc",
                                    fontSize = 15.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ShowCertificateDialog(attestation: X509CertChain,
                                  onDismissRequest: () -> Unit) {
    var certNumber by rememberSaveable() { mutableStateOf(0) }
    if (certNumber < 0 || certNumber >= attestation.certificates.size) {
        certNumber = 0
    }
    Dialog(onDismissRequest = { onDismissRequest() }) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(650.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = "Certificates",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.titleLarge
                )
                Row() {
                    Text(
                        text = "Certificate ${certNumber + 1} of ${attestation.certificates.size}",
                        modifier = Modifier.padding(8.dp),
                        textAlign = TextAlign.Start,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(
                        enabled = (certNumber > 0),
                        onClick = {
                            certNumber -= 1
                        }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                    IconButton(
                        enabled = (certNumber < attestation.certificates.size - 1),
                        onClick = {
                            certNumber += 1
                        }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowForward, "Forward")
                    }
                }
                Column(
                    modifier = Modifier
                        .size(470.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        text = styledX509CertificateText(
                            attestation.certificates[certNumber].javaX509Certificate.toString()
                        ),
                        //text = attestation[certNumber].toString(),
                        modifier = Modifier.padding(8.dp),
                        textAlign = TextAlign.Start,
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(
                        onClick = { onDismissRequest() },
                    ) {
                        Text("Close")
                    }
                }

            }
        }
    }
}

@Composable
private fun styledX509CertificateText(certificateText: String): AnnotatedString {
    val lines = certificateText.split("\n")
    return buildAnnotatedString {
        for (line in lines) {
            var colonPos = line.indexOf(':')
            if (colonPos > 0 && line.length > (colonPos + 1) && !line[colonPos + 1].isWhitespace()) {
                colonPos = -1
            }
            if (colonPos > 0) {
                withStyle(style = SpanStyle(fontWeight = FontWeight.Bold)) {
                    append(line.subSequence(0, colonPos))
                }
                append(line.subSequence(colonPos,line.length))
            } else {
                append(line)
            }
            append("\n")
        }
    }
}

@Composable
fun CsaConnectDialog(
    url: String,
    walletPin: String,
    onDismissRequest: () -> Unit,
    onConnectButtonClicked: (url: String, walletPin: String) -> Unit,
) {
    var urlTextField by rememberSaveable(stateSaver = TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(url))
    }
    var walletPinTextField by rememberSaveable(stateSaver = TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(walletPin))
    }
    Dialog(onDismissRequest = { onDismissRequest() }) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(400.dp)
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Cloud Secure Area",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.titleLarge
                )

                Text(
                    text = "URL for the Cloud Secure Area",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Start,
                    style = MaterialTheme.typography.bodyMedium
                )

                TextField(
                    value = urlTextField,
                    maxLines = 3,
                    onValueChange = { urlTextField = it },
                    textStyle = MaterialTheme.typography.bodySmall
                )

                Text(
                    text = "Wallet PIN",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Start,
                    style = MaterialTheme.typography.bodyMedium
                )

                TextField(
                    value = walletPinTextField,
                    maxLines = 3,
                    onValueChange = { walletPinTextField = it },
                    textStyle = MaterialTheme.typography.bodySmall
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
                        onClick = { onConnectButtonClicked(
                            urlTextField.text,
                            walletPinTextField.text
                        ) },
                    ) {
                        Text("Connect")
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
                .height(350.dp)
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Enter passphrase",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.bodyLarge
                )

                Text(
                    text = "Use passphrase chosen at CSA registration time " +
                            "(default is $CSA_WALLET_PIN_DEFAULT).",
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
                                    imageVector = Icons.Filled.Visibility,
                                    contentDescription = "hide_password"
                                )
                            }
                        } else {
                            IconButton(
                                onClick = { showPassphrase = true }) {
                                Icon(
                                    imageVector = Icons.Filled.VisibilityOff,
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

private suspend fun csaAttestation(
    showToast: (message: String) -> Unit
): KeyAttestation? {
    if (cloudSecureArea == null) {
        showToast("First connect to the CSA")
        return null
    }

    val now = Clock.System.now()
    val thirtyDaysFromNow = now + 30.days
    cloudSecureArea!!.createKey(
        "testKey",
        CloudCreateKeySettings.Builder("Challenge".toByteArray())
            .setUserAuthenticationRequired(
                true,
                10*1000,
                setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC)
            )
            .setValidityPeriod(now, thirtyDaysFromNow)
            .build()
    )
    return cloudSecureArea!!.getKeyInfo("testKey").attestation
}

private suspend fun csaTest(
    keyPurpose: KeyPurpose,
    curve: EcCurve,
    authRequired: Boolean,
    authTimeoutMillis: Long,
    userAuthType: Set<UserAuthenticationType>,
    biometricConfirmationRequired: Boolean,
    passphrase: String?,
    passphraseEnteredByUser: String?,
    showToast: (message: String) -> Unit
) {
    Logger.d(
        TAG,
        "cksTest keyPurpose:$keyPurpose curve:$curve authRequired:$authRequired authTimeout:$authTimeoutMillis"
    )
    try {
        csaTestUnguarded(
            keyPurpose, curve, authRequired, authTimeoutMillis, userAuthType,
            biometricConfirmationRequired, passphrase, passphraseEnteredByUser, showToast
        )
    } catch (e: Throwable) {
        showToast("${e.message}")
    }
}

private suspend fun csaTestUnguarded(
    keyPurpose: KeyPurpose,
    curve: EcCurve,
    authRequired: Boolean,
    authTimeoutMillis: Long,
    userAuthType: Set<UserAuthenticationType>,
    biometricConfirmationRequired: Boolean,
    passphrase: String?,
    passphraseEnteredByUser: String?,
    showToast: (message: String) -> Unit
) {

    if (cloudSecureArea == null) {
        showToast("First connect to the CSA")
        return
    }

    val builder = CloudCreateKeySettings.Builder("Challenge".toByteArray())
        .setEcCurve(curve)
        .setKeyPurposes(setOf(keyPurpose))
        .setUserAuthenticationRequired(authRequired, authTimeoutMillis, userAuthType)
    if (passphrase != null) {
        builder.setPassphraseRequired(true)
    }
    cloudSecureArea!!.createKey("testKey", builder.build())

    var unlockData = CloudKeyUnlockData(cloudSecureArea!!,"testKey")
    if (passphraseEnteredByUser != null) {
        unlockData.passphrase = passphraseEnteredByUser
    }

    if (keyPurpose == KeyPurpose.SIGN) {
        val signingAlgorithm = curve.defaultSigningAlgorithm
        try {
            val t0 = System.currentTimeMillis()
            val signature = cloudSecureArea!!.sign(
                "testKey",
                signingAlgorithm,
                "data".toByteArray(),
                unlockData)
            val t1 = System.currentTimeMillis()
            Logger.d(
                TAG,
                "Made signature with key without authentication" +
                        "r=${signature.r.toHex()} s=${signature.s.toHex()}",
            )
            showToast("Signed w/o authn (${t1 - t0} msec)")
        } catch (e: CloudKeyLockedException) {
            if (e.reason == CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED) {
                doUserAuth(
                    "Unlock to sign with key",
                    unlockData.cryptoObject,
                    false,
                    biometricConfirmationRequired,
                    onAuthSuccees = {
                        Logger.d(TAG, "onAuthSuccess")

                        val t0 = System.currentTimeMillis()
                        val signature = cloudSecureArea!!.sign(
                            "testKey",
                            signingAlgorithm,
                            "data".toByteArray(),
                            unlockData
                        )
                        val t1 = System.currentTimeMillis()
                        Logger.d(
                            TAG,
                            "Made signature with key after authentication" +
                                    "r=${signature.r.toHex()} s=${signature.s.toHex()}",
                        )
                        showToast("Signed after authn (${t1 - t0} msec)")
                    },
                    onAuthFailure = {
                        Logger.d(TAG, "onAuthFailure")
                    },
                    onDismissed = {
                        Logger.d(TAG, "onDismissed")
                    })
            } else {
                e.printStackTrace()
                showToast("${e.message}")
            }
        }
    } else {
        val otherKeyPairForEcdh = Crypto.createEcPrivateKey(curve)
        try {
            val t0 = System.currentTimeMillis()
            val Zab = cloudSecureArea!!.keyAgreement(
                "testKey",
                otherKeyPairForEcdh.publicKey,
                unlockData)
            val t1 = System.currentTimeMillis()
            Logger.dHex(
                TAG,
                "Calculated ECDH without authentication",
                Zab)
            showToast("ECDH w/o authn (${t1 - t0} msec)")
        } catch (e: CloudKeyLockedException) {
            if (e.reason == CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED) {
                doUserAuth(
                    "Unlock to ECDH with key",
                    unlockData.cryptoObject,
                    false,
                    biometricConfirmationRequired,
                    onAuthSuccees = {
                        Logger.d(TAG, "onAuthSuccess")

                        val t0 = System.currentTimeMillis()
                        val Zab = cloudSecureArea!!.keyAgreement(
                            "testKey",
                            otherKeyPairForEcdh.publicKey,
                            unlockData
                        )
                        val t1 = System.currentTimeMillis()
                        Logger.dHex(
                            TAG,
                            "Calculated ECDH after authentication",
                            Zab
                        )
                        showToast("ECDH after authn (${t1 - t0} msec)")
                    },
                    onAuthFailure = {
                        Logger.d(TAG, "onAuthFailure")
                    },
                    onDismissed = {
                        Logger.d(TAG, "onDismissed")
                    })
            } else {
                e.printStackTrace()
                showToast("${e.message}")
            }
        }

    }
}

private suspend fun doUserAuth(
    title: String,
    cryptoObject: BiometricPrompt.CryptoObject?,
    forceLskf: Boolean,
    biometricConfirmationRequired: Boolean,
    onAuthSuccees: suspend () -> Unit,
    onAuthFailure: suspend () -> Unit,
    onDismissed: suspend () -> Unit
) {
    val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Authentication required")
        .setConfirmationRequired(biometricConfirmationRequired)
        .setSubtitle(title)
    if (forceLskf) {
        // TODO: this works only on Android 11 or later but for now this is fine
        //   as this is just a reference/test app and this path is only hit if
        //   the user actually presses the "Use LSKF" button.  Longer term, we should
        //   fall back to using KeyGuard which will work on all Android versions.
        promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    } else {
        val canUseBiometricAuth = BiometricManager
            .from(AndroidContexts.applicationContext)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        if (canUseBiometricAuth) {
            promptInfoBuilder.setNegativeButtonText("Use LSKF")
        } else {
            promptInfoBuilder.setDeviceCredentialAllowed(true)
        }
    }

    var wasSuccess = false
    var wasFailure = false
    var wasDismissed = false
    val cv = ConditionVariable()

    // Run the prompt on the UI thread, we'll block below on `cv`...
    CoroutineScope(Dispatchers.Main).launch {
        val biometricPromptInfo = promptInfoBuilder.build()
        val biometricPrompt = BiometricPrompt(
            AndroidContexts.currentActivity!!,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Logger.d(TAG, "onAuthenticationError $errorCode $errString")
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
                        wasDismissed = true
                        cv.open()
                    } else if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        val promptInfoBuilderLskf = BiometricPrompt.PromptInfo.Builder()
                            .setTitle("Authentication required")
                            .setConfirmationRequired(biometricConfirmationRequired)
                            .setSubtitle(title)
                        promptInfoBuilderLskf.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                        val biometricPromptInfoLskf = promptInfoBuilderLskf.build()
                        val biometricPromptLskf = BiometricPrompt(
                            AndroidContexts.currentActivity!!,
                            object : BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationError(
                                    errorCode: Int,
                                    errString: CharSequence
                                ) {
                                    super.onAuthenticationError(errorCode, errString)
                                    Logger.d(
                                        TAG,
                                        "onAuthenticationError LSKF $errorCode $errString"
                                    )
                                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
                                        wasDismissed = true
                                        cv.open()
                                    } else {
                                        wasFailure = true
                                        cv.open()
                                    }
                                }

                                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                    super.onAuthenticationSucceeded(result)
                                    Logger.d(TAG, "onAuthenticationSucceeded LSKF $result")
                                    wasSuccess = true
                                    cv.open()
                                }

                                override fun onAuthenticationFailed() {
                                    super.onAuthenticationFailed()
                                    Logger.d(TAG, "onAuthenticationFailed LSKF")
                                }
                            }
                        )
                        Handler(Looper.getMainLooper()).postDelayed({
                            if (cryptoObject != null) {
                                biometricPromptLskf.authenticate(
                                    biometricPromptInfoLskf, cryptoObject
                                )
                            } else {
                                biometricPromptLskf.authenticate(biometricPromptInfoLskf)
                            }
                        }, 100)
                    } else {
                        wasFailure = true
                        cv.open()
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Logger.d(TAG, "onAuthenticationSucceeded $result")
                    wasSuccess = true
                    cv.open()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Logger.d(TAG, "onAuthenticationFailed")
                }
            })
        Logger.d(TAG, "cryptoObject: " + cryptoObject)
        if (cryptoObject != null) {
            biometricPrompt.authenticate(biometricPromptInfo, cryptoObject)
        } else {
            biometricPrompt.authenticate(biometricPromptInfo)
        }
    }
    cv.block()
    if (wasSuccess) {
        Logger.d(TAG, "Reporting success")
        onAuthSuccees()
    } else if (wasFailure) {
        Logger.d(TAG, "Reporting failure")
        onAuthFailure()
    } else if (wasDismissed) {
        Logger.d(TAG, "Reporting dismissed")
        onDismissed()
    }
}
