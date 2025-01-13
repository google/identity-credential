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
import com.android.identity.document.DocumentRequest
import com.android.identity.document.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.wallet.util.ProvisioningUtil
import com.android.identity.wallet.util.log
import com.google.android.gms.identitycredentials.GetCredentialResponse
import com.google.android.gms.identitycredentials.IntentHelper
import com.google.android.gms.identitycredentials.IntentHelper.EXTRA_CREDENTIAL_ID
import com.google.android.gms.identitycredentials.IntentHelper.extractGetCredentialRequest
import com.google.android.gms.identitycredentials.IntentHelper.setGetCredentialException
import com.google.android.gms.identitycredentials.IntentHelper.setGetCredentialResponse
import org.json.JSONObject
import java.util.StringTokenizer
import kotlinx.datetime.Clock

class GetCredentialActivity : FragmentActivity() {

    fun addDeviceNamespaces(documentGenerator : DocumentGenerator,
                            credential : MdocCredential,
                            unlockData: KeyUnlockData?) {
        documentGenerator.setDeviceNamespacesSignature(
            NameSpacedData.Builder().build(),
            credential.secureArea,
            credential.alias,
            unlockData,
            Algorithm.ES256)
    }

    fun doBiometricAuth(credential : MdocCredential,
                        forceLskf : Boolean,
                        onBiometricAuthCompleted: (unlockData: KeyUnlockData?) -> Unit) {
        var title = "To share your credential we need to check that it's you."
        var unlockData = AndroidKeystoreKeyUnlockData(credential.alias)
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
                            doBiometricAuth(credential, true, onBiometricAuthCompleted)
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
                }
            })

        if (cryptoObject != null) {
            biometricPrompt.authenticate(biometricPromptInfo, cryptoObject)
        } else {
            biometricPrompt.authenticate(biometricPromptInfo)
        }
    }

    private fun createMDocDeviceResponse(
        credentialId: Int,
        dataElements: List<DocumentRequest.DataElement>,
        encodedSessionTranscript: ByteArray,
        onComplete: (ByteArray) -> Unit
    ) {
        val documentRequest = DocumentRequest(dataElements)
        val documentStore = ProvisioningUtil.getInstance(applicationContext).documentStore
        val documentName = documentStore.listDocuments()[credentialId]
        val document = documentStore.lookupDocument(documentName)
        val nameSpacedData = document!!.applicationData.getNameSpacedData("documentData")

        val credential = document.findCredential(
            ProvisioningUtil.CREDENTIAL_DOMAIN,
            Clock.System.now()
        ) as MdocCredential? ?: throw IllegalStateException("No credential")
        val staticAuthData = StaticAuthDataParser(credential.issuerProvidedData).parse()
        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            documentRequest, nameSpacedData, staticAuthData
        )

        val deviceResponseGenerator = DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
        val documentGenerator = DocumentGenerator(
            document.applicationData.getString(ProvisioningUtil.DOCUMENT_TYPE),
            staticAuthData.issuerAuth,
            encodedSessionTranscript
        )
        documentGenerator.setIssuerNamespaces(mergedIssuerNamespaces)
        try {
            addDeviceNamespaces(documentGenerator, credential, null)
            deviceResponseGenerator.addDocument(documentGenerator.generate())
            credential.increaseUsageCount()
            onComplete(deviceResponseGenerator.generate())
        } catch (e: KeyLockedException) {
            doBiometricAuth(credential, false) { keyUnlockData ->
                if (keyUnlockData != null) {
                    addDeviceNamespaces(documentGenerator, credential, keyUnlockData)
                    deviceResponseGenerator.addDocument(documentGenerator.generate())
                    credential.increaseUsageCount()
                    onComplete(deviceResponseGenerator.generate())
                } else {
                    throw RuntimeException("Biometric Auth Failed")
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {


            val cmrequest = extractGetCredentialRequest(intent)
            val credentialId = intent.getLongExtra(EXTRA_CREDENTIAL_ID, -1).toInt()

            val callingAppInfo = IntentHelper.extractCallingAppInfo(intent)!!
            val callingPackageName = callingAppInfo.packageName
            val callingOrigin = callingAppInfo.origin

            log("CredId: $credentialId ${cmrequest!!.credentialOptions.get(0).requestMatcher}")
            log("Calling app $callingPackageName $callingOrigin")

            val dataElements = mutableListOf<DocumentRequest.DataElement>()

            val json = JSONObject(cmrequest!!.credentialOptions.get(0).requestMatcher)
            val provider = json.getJSONArray("providers").getJSONObject(0)

            val protocol = provider.getString("protocol")
            log("Request protocol: $protocol")
            val request = provider.getString("request")
            log("Request: $request")
            if (protocol == "preview") {
                // Extract params from the preview protocol request
                val previewRequest = JSONObject(request)
                val selector = previewRequest.getJSONObject("selector")
                val nonceBase64 = previewRequest.getString("nonce")
                val readerPublicKeyBase64 = previewRequest.getString("readerPublicKey")
                val docType = selector.getString("doctype")
                log("DocType: $docType")
                log("nonce: $nonceBase64")
                log("readerPublicKey: $readerPublicKeyBase64")

                // Covert nonce and publicKey
                val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP or Base64.URL_SAFE)
                val readerPublicKey = EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(
                    EcCurve.P256,
                    Base64.decode(readerPublicKeyBase64, Base64.NO_WRAP or Base64.URL_SAFE)
                )

                // Match all the requested fields
                val fields = selector.getJSONArray("fields")
                for (n in 0 until fields.length()) {
                    val field = fields.getJSONObject(n)
                    val name = field.getString("name")
                    val namespace = field.getString("namespace")
                    val intentToRetain = field.getBoolean("intentToRetain")
                    log("Field $namespace $name $intentToRetain")
                    dataElements.add(
                        DocumentRequest.DataElement(
                            namespace,
                            name,
                            intentToRetain
                        )
                    )
                }

                // Generate the Session Transcript
                val encodedSessionTranscript = if (callingOrigin == null) {
                    CredmanUtil.generateAndroidSessionTranscript(
                        nonce,
                        callingPackageName,
                        Crypto.digest(Algorithm.SHA256, readerPublicKey.asUncompressedPointEncoding)
                    )
                } else {
                    CredmanUtil.generateBrowserSessionTranscript(
                        nonce,
                        callingOrigin,
                        Crypto.digest(Algorithm.SHA256, readerPublicKey.asUncompressedPointEncoding)
                    )
                }
                // Create ISO DeviceResponse
                createMDocDeviceResponse(credentialId, dataElements, encodedSessionTranscript) { deviceResponse ->
                    // The Preview protocol HPKE encrypts the response.
                    val (cipherText, encapsulatedPublicKey) = Crypto.hpkeEncrypt(
                        Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
                        readerPublicKey,
                        deviceResponse,
                        encodedSessionTranscript
                    )
                    val encodedCredentialDocument =
                        CredmanUtil.generateCredentialDocument(cipherText, encapsulatedPublicKey)

                    // Create the preview response
                    val responseJson = JSONObject()
                    responseJson.put(
                        "token",
                        Base64.encodeToString(
                            encodedCredentialDocument,
                            Base64.NO_WRAP or Base64.URL_SAFE
                        )
                    )
                    val response = responseJson.toString(2)

                    // Send result back to credman
                    val resultData = Intent()
                    setGetCredentialResponse(resultData, createGetCredentialResponse(response))
                    setResult(RESULT_OK, resultData)
                    finish()
                }
            } else if (protocol == "openid4vp") {
                val openid4vpRequest = JSONObject(request)
                val clientID = openid4vpRequest.getString("client_id")
                log("client_id $clientID")
                val nonceBase64 = openid4vpRequest.getString("nonce")
                log("nonce: $nonceBase64")
                val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP or Base64.URL_SAFE)

                val presentationDefinition = openid4vpRequest.getJSONObject("presentation_definition")
                val inputDescriptors = presentationDefinition.getJSONArray("input_descriptors")
                if (inputDescriptors.length() != 1) {
                    throw IllegalArgumentException("Only support a single input input_descriptor")
                }
                val inputDescriptor = inputDescriptors.getJSONObject(0)!!
                val docType = inputDescriptor.getString("id")
                log("DocType: $docType")

                val constraints = inputDescriptor.getJSONObject("constraints")
                val fields = constraints.getJSONArray("fields")

                for (n in 0 until fields.length()) {
                    val field = fields.getJSONObject(n)
                    // Only support a single path entry for now
                    val path = field.getJSONArray("path").getString(0)!!
                    // JSONPath is horrible, hacky way to parse it for demonstration purposes
                    val st = StringTokenizer(path, "'", false).asSequence().toList()
                    val namespace = st[1] as String
                    val name = st[3] as String
                    log("namespace $namespace name $name")
                    val intentToRetain = field.getBoolean("intent_to_retain")
                    dataElements.add(
                        DocumentRequest.DataElement(
                            namespace,
                            name,
                            intentToRetain
                        )
                    )
                }
                // Generate the Session Transcript
                val encodedSessionTranscript = if (callingOrigin == null) {
                    CredmanUtil.generateAndroidSessionTranscript(
                        nonce,
                        callingPackageName,
                        Crypto.digest(Algorithm.SHA256, clientID.toByteArray())
                    )
                } else {
                    CredmanUtil.generateBrowserSessionTranscript(
                        nonce,
                        callingOrigin,
                        Crypto.digest(Algorithm.SHA256, clientID.toByteArray())
                    )
                }
                // Create ISO DeviceResponse
                createMDocDeviceResponse(credentialId, dataElements, encodedSessionTranscript) { deviceResponse ->
                    // Create the openid4vp respoinse
                    val responseJson = JSONObject()
                    responseJson.put(
                        "vp_token",
                        Base64.encodeToString(
                            deviceResponse,
                            Base64.NO_WRAP or Base64.URL_SAFE
                        )
                    )
                    val response = responseJson.toString(2)

                    // Send result back to credman
                    val resultData = Intent()
                    setGetCredentialResponse(resultData, createGetCredentialResponse(response))
                    setResult(RESULT_OK, resultData)
                    finish()
                }
            } else {
                // Unknown protocol
                throw IllegalArgumentException("Unknown protocol")
            }

        } catch (e: Exception) {
            log("Exception $e")
            val resultData = Intent()
            setGetCredentialException(resultData, e.toString(), e.message)
            setResult(RESULT_OK, resultData)
            finish()
        }
    }

    private fun createGetCredentialResponse(response: String): GetCredentialResponse {
        val bundle = Bundle()
        bundle.putByteArray("identityToken", response.toByteArray())
        val credentialResponse = com.google.android.gms.identitycredentials.Credential("type", bundle)
        return GetCredentialResponse(credentialResponse)
    }

}