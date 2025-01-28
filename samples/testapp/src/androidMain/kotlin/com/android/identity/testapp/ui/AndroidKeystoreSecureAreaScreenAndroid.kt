package com.android.identity.testapp.ui

import android.content.Context
import android.content.pm.FeatureInfo
import android.content.pm.PackageManager
import android.os.Build
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.android.identity.android.securearea.AndroidKeystoreCreateKeySettings
import com.android.identity.android.securearea.AndroidKeystoreKeyUnlockData
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.securearea.UserAuthenticationType
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyPurpose
import com.android.identity.util.AndroidContexts
import com.android.identity.testapp.platformSecureAreaProvider
import com.android.identity.util.Logger
import com.android.identity.util.toHex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.io.files.Path
import kotlin.time.Duration.Companion.days

private val TAG = "AndroidKeystoreSecureAreaScreen"

private val androidKeystoreCapabilities: AndroidKeystoreSecureArea.Capabilities by lazy {
    AndroidKeystoreSecureArea.Capabilities(AndroidContexts.applicationContext)
}

private val keymintVersionTee: Int by lazy {
    getFeatureVersionKeystore(AndroidContexts.applicationContext, false)
}

private val keymintVersionStrongBox: Int by lazy {
    getFeatureVersionKeystore(AndroidContexts.applicationContext, true)
}

@Composable
actual fun AndroidKeystoreSecureAreaScreen(showToast: (message: String) -> Unit) {
    val showCapabilitiesDialog = remember {
        mutableStateOf<AndroidKeystoreSecureArea.Capabilities?>(null)
    }
    val showCertificateDialog = remember {
        mutableStateOf<X509CertChain?>(null)
    }

    if (showCapabilitiesDialog.value != null) {
        ShowCapabilitiesDialog(
            showCapabilitiesDialog.value!!,
            onDismissRequest = {
                showCapabilitiesDialog.value = null
            })
    }

    if (showCertificateDialog.value != null) {
        ShowCertificateDialog(showCertificateDialog.value!!,
            onDismissRequest = {
                showCertificateDialog.value = null
            })
    }

    val coroutineScope = rememberCoroutineScope()

    LazyColumn {

        item {
            TextButton(onClick = {
                // TODO: Does a lot of I/O, cannot run on UI thread                 
                showCapabilitiesDialog.value = androidKeystoreCapabilities
            })
            {
                Text(
                    text = "Versions and Capabilities",
                    fontSize = 15.sp
                )
            }
        }

        item {
            TextButton(onClick = {
                coroutineScope.launch {
                    val attestation = aksAttestation(false)
                    Logger.d(TAG, "attestation: " + attestation)
                    showCertificateDialog.value = attestation
                }
            })
            {
                Text(
                    text = "Attestation",
                    fontSize = 15.sp
                )
            }
        }

        item {
            TextButton(onClick = {
                coroutineScope.launch {
                    val attestation = aksAttestation(true)
                    Logger.d(TAG, "attestation: " + attestation)
                    showCertificateDialog.value = attestation
                }
            })
            {
                Text(
                    text = "StrongBox Attestation",
                    fontSize = 15.sp
                )
            }
        }

        for ((strongBox, strongBoxDesc) in arrayOf(
            Pair(false, ""), Pair(true, "StrongBox ")
        )) {
            for ((keyPurpose, keyPurposeDesc) in arrayOf(
                Pair(KeyPurpose.SIGN, "Signature"),
                Pair(KeyPurpose.AGREE_KEY, "Key Agreement")
            )) {
                for ((curve, curveName, purposes) in arrayOf(
                    Triple(EcCurve.P256, "P-256", setOf(KeyPurpose.SIGN, KeyPurpose.AGREE_KEY)),
                    Triple(EcCurve.ED25519, "Ed25519", setOf(KeyPurpose.SIGN)),
                    Triple(EcCurve.X25519, "X25519", setOf(KeyPurpose.AGREE_KEY)),
                )) {
                    if (!(purposes.contains(keyPurpose))) {
                        // No common purpose
                        continue
                    }

                    val AUTH_NONE = setOf<UserAuthenticationType>()
                    val AUTH_LSKF_OR_BIOMETRIC = setOf(
                        UserAuthenticationType.LSKF,
                        UserAuthenticationType.BIOMETRIC)
                    val AUTH_LSKF_ONLY = setOf(UserAuthenticationType.LSKF)
                    val AUTH_BIOMETRIC_ONLY = setOf(UserAuthenticationType.BIOMETRIC)
                    for ((userAuthType, authTimeout, authDesc) in arrayOf(
                        Triple(AUTH_NONE, 0L, ""),
                        Triple(AUTH_LSKF_OR_BIOMETRIC, 0L, "- Auth"),
                        Triple(AUTH_LSKF_OR_BIOMETRIC, 10 * 1000L, "- Auth (10 sec)"),
                        Triple(AUTH_LSKF_ONLY, 0L, "- Auth (LSKF Only)"),
                        Triple(AUTH_BIOMETRIC_ONLY, 0L, "- Auth (Biometric Only)"),
                        Triple(AUTH_LSKF_OR_BIOMETRIC, -1L, "- Auth (No Confirmation)"),
                    )) {
                        // For brevity, Only do auth for P-256 Sign and Mac
                        if (curve != EcCurve.P256 && userAuthType != AUTH_NONE) {
                            continue
                        }

                        val biometricConfirmationRequired = (authTimeout >= 0L)
                        item {
                            TextButton(onClick = {
                                coroutineScope.launch {
                                    aksTest(
                                        keyPurpose,
                                        curve,
                                        userAuthType != AUTH_NONE,
                                        if (authTimeout < 0L) 0L else authTimeout,
                                        userAuthType,
                                        biometricConfirmationRequired,
                                        strongBox,
                                        showToast
                                    )
                                }
                            })
                            {
                                Text(
                                    text = "$strongBoxDesc$curveName $keyPurposeDesc $authDesc",
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

// Unfortunately this is API is only available to system apps so we
// have to use reflection to use it.
private fun getFirstApiLevel(): Int =
    try {
        val c = Class.forName("android.os.SystemProperties")
        val get = c.getMethod("get", String::class.java)
        val firstApiLevelString = get.invoke(c, "ro.product.first_api_level") as String
        firstApiLevelString.toInt()
    } catch (e: java.lang.Exception) {
        Logger.w(TAG, "Error getting ro.product.first_api_level", e)
        0
    }

private fun getNameForApiLevel(apiLevel: Int): String {
    val fields = Build.VERSION_CODES::class.java.fields
    var codeName = "UNKNOWN"
    fields.filter { it.getInt(Build.VERSION_CODES::class) == apiLevel }
        .forEach { codeName = it.name }
    return codeName
}

@Composable
fun ShowCapabilitiesDialog(capabilities: AndroidKeystoreSecureArea.Capabilities,
                           onDismissRequest: () -> Unit) {
    Dialog(onDismissRequest = { onDismissRequest() }) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(520.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = "Versions and Capabilities",
                    modifier = Modifier.padding(16.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.titleLarge
                )
                Column(
                    modifier = Modifier
                        .size(400.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    val apiLevel = Build.VERSION.SDK_INT
                    val firstApiLevel = getFirstApiLevel()
                    // Would be nice to show first API level but that's only available to tests.
                    Text(
                        text = "API Level: ${apiLevel} (${getNameForApiLevel(apiLevel)})\n" +
                                "First API Level: ${firstApiLevel} (${getNameForApiLevel(firstApiLevel)})\n" +
                                "TEE KeyMint version: ${keymintVersionTee}\n" +
                                "StrongBox KeyMint version: ${keymintVersionStrongBox}",
                        modifier = Modifier.padding(8.dp),
                        textAlign = TextAlign.Start,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    val userAuthText =
                        if (capabilities.multipleAuthenticationTypesSupported)
                            "LSKF or Bio or LSKF+Bio"
                        else "Only LSKF+Bio"
                    val secureLockScreenText =
                        if (capabilities.secureLockScreenSetup)
                            "Enabled"
                        else
                            "Not Enabled"
                    Text(
                        text = "User Auth: $userAuthText\n" +
                                "Secure Lock Screen: $secureLockScreenText",
                        modifier = Modifier.padding(8.dp),
                        textAlign = TextAlign.Start,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "Attest Key support (TEE): ${capabilities.attestKeySupported}\n" +
                                "Key Agreement support (TEE): ${capabilities.keyAgreementSupported}\n" +
                                "Curve 25519 support (TEE): ${capabilities.curve25519Supported}",
                        modifier = Modifier.padding(8.dp),
                        textAlign = TextAlign.Start,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "StrongBox Available: ${capabilities.strongBoxSupported}\n" +
                                "Attest Key support (StrongBox): ${capabilities.strongBoxAttestKeySupported}\n" +
                                "Key Agreement support (StrongBox): ${capabilities.strongBoxKeyAgreementSupported}\n" +
                                "Curve 25519 support (StrongBox): ${capabilities.strongBoxCurve25519Supported}",
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
                            attestation.certificates[certNumber].javaX509Certificate.toString()),
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

private fun getFeatureVersionKeystore(appContext: Context, useStrongbox: Boolean): Int {
    var feature = PackageManager.FEATURE_HARDWARE_KEYSTORE
    if (useStrongbox) {
        feature = PackageManager.FEATURE_STRONGBOX_KEYSTORE
    }
    val pm = appContext.packageManager
    if (pm.hasSystemFeature(feature)) {
        var info: FeatureInfo? = null
        val infos = pm.systemAvailableFeatures
        for (n in infos.indices) {
            val i = infos[n]
            if (i.name == feature) {
                info = i
                break
            }
        }
        var version = 0
        if (info != null) {
            version = info.version
        }
        // It's entirely possible that the feature exists but the version number hasn't
        // been set. In that case, assume it's at least KeyMaster 4.1.
        if (version < 41) {
            version = 41
        }
        return version
    }
    // It's only a requirement to set PackageManager.FEATURE_HARDWARE_KEYSTORE since
    // Android 12 so for old devices this isn't set. However all devices since Android
    // 8.1 has had HW-backed keystore so in this case we can report KeyMaster 4.1
    if (!useStrongbox) {
        return 41
    }
    return 0
}

private suspend fun aksAttestation(strongBox: Boolean): X509CertChain {
    val now = Clock.System.now()
    val thirtyDaysFromNow = now + 30.days
    val androidKeystoreSecureArea = platformSecureAreaProvider().get() as AndroidKeystoreSecureArea
    androidKeystoreSecureArea.createKey(
        "testKey",
        AndroidKeystoreCreateKeySettings.Builder("Challenge".toByteArray())
            .setUserAuthenticationRequired(
                true, 10*1000,
                setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC)
            )
            .setValidityPeriod(now, thirtyDaysFromNow)
            .setUseStrongBox(strongBox)
            .build()
    )
    return androidKeystoreSecureArea.getKeyInfo("testKey").attestation.certChain!!
}

private suspend fun aksTest(
    keyPurpose: KeyPurpose,
    curve: EcCurve,
    authRequired: Boolean,
    authTimeoutMillis: Long,
    userAuthType: Set<UserAuthenticationType>,
    biometricConfirmationRequired: Boolean,
    strongBox: Boolean,
    showToast: (message: String) -> Unit) {
    Logger.d(
        TAG,
        "aksTest keyPurpose:$keyPurpose curve:$curve authRequired:$authRequired authTimeout:$authTimeoutMillis strongBox:$strongBox"
    )
    try {
        aksTestUnguarded(keyPurpose, curve, authRequired, authTimeoutMillis, userAuthType,
            biometricConfirmationRequired, strongBox, showToast)
    } catch (e: Throwable) {
        e.printStackTrace();
        showToast("${e.message}")
    }
}

private suspend fun aksTestUnguarded(
    keyPurpose: KeyPurpose,
    curve: EcCurve,
    authRequired: Boolean,
    authTimeoutMillis: Long,
    userAuthType: Set<UserAuthenticationType>,
    biometricConfirmationRequired: Boolean,
    strongBox: Boolean,
    showToast: (message: String) -> Unit) {

    val androidKeystoreSecureArea = platformSecureAreaProvider().get() as AndroidKeystoreSecureArea
    androidKeystoreSecureArea.createKey(
        "testKey",
        AndroidKeystoreCreateKeySettings.Builder("Challenge".toByteArray())
            .setKeyPurposes(setOf(keyPurpose))
            .setUserAuthenticationRequired(
                authRequired, authTimeoutMillis, userAuthType)
            .setUseStrongBox(strongBox)
            .build()
    )

    if (keyPurpose == KeyPurpose.SIGN) {
        val signingAlgorithm = curve.defaultSigningAlgorithm
        val dataToSign = "data".toByteArray()
        try {
            val t0 = System.currentTimeMillis()
            val signature = androidKeystoreSecureArea.sign(
                "testKey",
                signingAlgorithm,
                dataToSign,
                null)
            val t1 = System.currentTimeMillis()
            Logger.d(
                TAG,
                "Made signature with key without authentication" +
                        "r=${signature.r.toHex()} s=${signature.s.toHex()}",
            )
            showToast("Signed w/o authn (${t1 - t0} msec)")
        } catch (e: KeyLockedException) {
            val unlockData = AndroidKeystoreKeyUnlockData("testKey")
            doUserAuth(
                "Unlock to sign with key",
                unlockData.getCryptoObjectForSigning(Algorithm.ES256),
                false,
                biometricConfirmationRequired,
                onAuthSuccees = {
                    Logger.d(TAG, "onAuthSuccess")

                    val t0 = System.currentTimeMillis()
                    val signature = androidKeystoreSecureArea.sign(
                        "testKey",
                        signingAlgorithm,
                        dataToSign,
                        unlockData)
                    val t1 = System.currentTimeMillis()
                    Logger.d(
                        TAG,
                        "Made signature with key after authentication: " +
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
        }
    } else {
        val otherKeyPairForEcdh = Crypto.createEcPrivateKey(curve)
        try {
            val t0 = System.currentTimeMillis()
            val Zab = androidKeystoreSecureArea.keyAgreement(
                "testKey",
                otherKeyPairForEcdh.publicKey,
                null)
            val t1 = System.currentTimeMillis()
            Logger.dHex(
                TAG,
                "Calculated ECDH",
                Zab)
            showToast("ECDH w/o authn (${t1 - t0} msec)")
        } catch (e: KeyLockedException) {
            val unlockData = AndroidKeystoreKeyUnlockData("testKey")
            doUserAuth(
                "Unlock to ECDH with key",
                unlockData.cryptoObjectForKeyAgreement,
                false,
                biometricConfirmationRequired,
                onAuthSuccees = {
                    Logger.d(TAG, "onAuthSuccess")
                    val t0 = System.currentTimeMillis()
                    val Zab = androidKeystoreSecureArea.keyAgreement(
                        "testKey",
                        otherKeyPairForEcdh.publicKey,
                        unlockData)
                    val t1 = System.currentTimeMillis()
                    Logger.dHex(
                        TAG,
                        "Calculated ECDH",
                        Zab)
                    showToast("ECDH after authn (${t1 - t0} msec)")
                },
                onAuthFailure = {
                    Logger.d(TAG, "onAuthFailure")
                },
                onDismissed = {
                    Logger.d(TAG, "onDismissed")
                })
        }

    }
}


private fun doUserAuth(
    title: String,
    cryptoObject: BiometricPrompt.CryptoObject?,
    forceLskf: Boolean,
    biometricConfirmationRequired: Boolean,
    onAuthSuccees: suspend () -> Unit,
    onAuthFailure: suspend () -> Unit,
    onDismissed: suspend () -> Unit
) {
    // Run this in a worker thread...
    CoroutineScope(Dispatchers.IO).launch {
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
}



