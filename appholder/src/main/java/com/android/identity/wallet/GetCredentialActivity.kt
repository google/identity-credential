package com.android.identity.wallet

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.android.identity.android.mdoc.util.CredmanUtil
import com.android.identity.android.securearea.AndroidKeystoreKeyUnlockData
import com.android.identity.document.Credential
import com.android.identity.document.DocumentRequest
import com.android.identity.document.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.util.Timestamp
import com.android.identity.wallet.util.ProvisioningUtil
import com.android.identity.wallet.util.log
import com.google.android.gms.identitycredentials.GetCredentialResponse
import com.google.android.gms.identitycredentials.IntentHelper.EXTRA_CREDENTIAL_ID
import com.google.android.gms.identitycredentials.IntentHelper.extractCallingAppInfo
import com.google.android.gms.identitycredentials.IntentHelper.extractGetCredentialRequest
import com.google.android.gms.identitycredentials.IntentHelper.setGetCredentialResponse
import org.json.JSONObject
import java.security.PublicKey

class GetCredentialActivity : FragmentActivity() {

    fun addDeviceNamespaces(documentGenerator : DocumentGenerator,
                            authKey : Credential,
                            unlockData: KeyUnlockData?) {
        documentGenerator.setDeviceNamespacesSignature(
            NameSpacedData.Builder().build(),
            authKey.secureArea,
            authKey.alias,
            unlockData,
            Algorithm.ES256)
    }

    fun doBiometricAuth(authKey : Credential,
                        forceLskf : Boolean,
                        onBiometricAuthCompleted: (unlockData: KeyUnlockData?) -> Unit) {
        var title = "To share your credential we need to check that it's you."
        var unlockData = AndroidKeystoreKeyUnlockData(authKey.alias)
        var cryptoObject = unlockData.getCryptoObjectForSigning(Algorithm.ES256)

        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentication required")
            .setSubtitle(title)
            .setConfirmationRequired(false)
        if (forceLskf) {
            // TODO: this works only on Android 11 or later but for now this is fine
            //   as this is just a reference/test app and this path is only hit if
            //   the user actually presses the "Use LSKF" button.  Longer term, we should
            //   fall back to using KeyGuard which will work on all Android versions.
            promptInfoBuilder.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            val canUseBiometricAuth = BiometricManager
                .from(applicationContext)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            if (canUseBiometricAuth) {
                promptInfoBuilder.setNegativeButtonText("Use PIN")
            } else {
                promptInfoBuilder.setDeviceCredentialAllowed(true)
            }
        }

        val biometricPromptInfo = promptInfoBuilder.build()
        val biometricPrompt = BiometricPrompt(this,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        Logger.d("TAG", "onAuthenticationError $errorCode $errString")
                        // TODO: "Use LSKF"...  without this delay, the prompt won't work correctly
                        Handler(Looper.getMainLooper()).postDelayed({
                            doBiometricAuth(authKey, true, onBiometricAuthCompleted)
                        }, 100)
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Logger.d("TAG", "onAuthenticationSucceeded $result")

                    onBiometricAuthCompleted(unlockData)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Logger.d("TAG", "onAuthenticationFailed")
                    onBiometricAuthCompleted(null)
                }
            })

        if (cryptoObject != null) {
            biometricPrompt.authenticate(biometricPromptInfo, cryptoObject)
        } else {
            biometricPrompt.authenticate(biometricPromptInfo)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val request = extractGetCredentialRequest(intent)
        val credentialId = intent.getLongExtra(EXTRA_CREDENTIAL_ID, -1)
        val callingAppInfo = extractCallingAppInfo(intent)
        //log("CredId: $credentialId ${request!!.credentialOptions.get(0).requestMatcher}")

        val dataElements = mutableListOf<DocumentRequest.DataElement>()

        val json = JSONObject(request!!.credentialOptions.get(0).requestMatcher)
        val provider = json.getJSONArray("providers").getJSONObject(0)
        val responseFormat = provider.get("responseFormat")
        val params = provider.getJSONObject("params")
        val nonceBase64 = params.getString("nonce")
        val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP or Base64.URL_SAFE)
        val requesterIdentityBase64 = params.getString("requesterIdentity")
        val requesterIdentity = CredmanUtil.publicKeyFromUncompressed(
            Base64.decode(requesterIdentityBase64, Base64.NO_WRAP or Base64.URL_SAFE))
        log("responseFormat: $responseFormat nonce: $nonce requester: $requesterIdentity")
        val fields = provider.getJSONObject("selector").getJSONArray("fields")
        for (n in 0 until fields.length()) {
            // TODO: request format needs revision, this won't work if data elements have dots in them.
            val field = fields.getJSONObject(n)
            val name = field.getString("name")
            var finalDot = name.lastIndexOf('.')
            if (finalDot > 0) {
                val nameSpaceName = name.substring(0, finalDot)
                val dataElementName = name.substring(finalDot + 1)
                dataElements.add(
                    DocumentRequest.DataElement(
                        nameSpaceName,
                        dataElementName,
                        false
                    )
                )
            }
        }

        val documentRequest = DocumentRequest(dataElements)

        val documentStore = ProvisioningUtil.getInstance(applicationContext).documentStore
        val documentName = documentStore.listDocuments().get(credentialId.toInt())
        val document = documentStore.lookupDocument(documentName)
        val nameSpacedData = document!!.applicationData.getNameSpacedData("documentData")

        val encodedSessionTranscript = CredmanUtil.generateAndroidSessionTranscript(
            nonce,
            requesterIdentity,
            "com.android.mdl.appreader"
        ) // TODO: get from |request|

        val credential = document.findCredential(
            ProvisioningUtil.CREDENTIAL_DOMAIN,
            Timestamp.now()
        )
        if (credential == null) {
            throw IllegalStateException("No credential")
        }
        val staticAuthData = StaticAuthDataParser(credential.issuerProvidedData).parse()
        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            documentRequest, nameSpacedData, staticAuthData
        )
        val deviceResponseGenerator = DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
        var documentGenerator = DocumentGenerator(
            document.applicationData.getString(ProvisioningUtil.DOCUMENT_TYPE),
            staticAuthData.issuerAuth,
            encodedSessionTranscript
        )
        documentGenerator.setIssuerNamespaces(mergedIssuerNamespaces)
        try {
            addDeviceNamespaces(documentGenerator, credential, null)
            completeResponse(credential, deviceResponseGenerator, documentGenerator,
                requesterIdentity, encodedSessionTranscript)
        } catch (e: KeyLockedException) {
            doBiometricAuth(credential, false) { keyUnlockData ->
                if (keyUnlockData != null) {
                    addDeviceNamespaces(documentGenerator, credential, keyUnlockData)
                    completeResponse(credential, deviceResponseGenerator, documentGenerator,
                        requesterIdentity, encodedSessionTranscript)
                } else {
                    log("Need to convey error")
                }
            }
        }
    }

    fun completeResponse(authKey: Credential,
                         deviceResponseGenerator: DeviceResponseGenerator,
                         documentGenerator: DocumentGenerator,
                         requesterIdentity: PublicKey,
                         encodedSessionTranscript: ByteArray) {

        deviceResponseGenerator.addDocument(documentGenerator.generate())
        val encodedDeviceResponse = deviceResponseGenerator.generate()
        //log("Response: " + CborUtil.toDiagnostics(encodedDeviceResponse,
        //    CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT + CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR))

        val credmanUtil = CredmanUtil(requesterIdentity, null)
        val (cipherText, encapsulatedPublicKey) = credmanUtil.encrypt(encodedDeviceResponse, encodedSessionTranscript)
        val encodedCredentialDocument = CredmanUtil.generateCredentialDocument(cipherText, encapsulatedPublicKey)
        authKey.increaseUsageCount()

        val bundle = Bundle()
        bundle.putByteArray("identityToken", Base64.encodeToString(encodedCredentialDocument, Base64.NO_WRAP or Base64.URL_SAFE).toByteArray())
        val credentialResponse = com.google.android.gms.identitycredentials.Credential("type", bundle)
        val response = GetCredentialResponse(credentialResponse)
        val resultData = Intent()
        setGetCredentialResponse(resultData, response)
        setResult(RESULT_OK, resultData)
        finish()

    }
}