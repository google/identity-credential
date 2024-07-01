/*
 * Copyright (C) 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity_credential.wallet.credman

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.android.identity.android.mdoc.util.CredmanUtil
import com.android.identity.android.securearea.AndroidKeystoreKeyUnlockData
import com.android.identity.android.securearea.UserAuthenticationType
import com.android.identity.cbor.Cbor
import com.android.identity.credential.Credential
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.document.DocumentRequest
import com.android.identity.document.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.WalletApplication
import com.android.identity_credential.wallet.presentation.showPresentmentFlow
import com.android.identity_credential.wallet.ui.prompt.biometric.showBiometricPrompt
import org.json.JSONObject

import com.google.android.gms.identitycredentials.GetCredentialResponse
import com.google.android.gms.identitycredentials.IntentHelper
import kotlinx.coroutines.launch
import java.util.StringTokenizer
import kotlinx.datetime.Clock


/**
 * Activity that is called from Credential Manager to authenticate the user.
 * Depending on the protocol that is specified on this Activity's Intent,
 * a Presentment Flow is initiated and a response JSON is called back as the payload on the Intent.
 *
 * Using FragmentActivity in order to support androidx.biometric.BiometricPrompt.
 */
class CredmanPresentationActivity : FragmentActivity() {
    companion object {
        private const val TAG = "CredmanPresentationActivity"
    }

    // reference WalletApplication for obtaining dependencies
    private val walletApp: WalletApplication by lazy {
        application as WalletApplication
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {

            val cmrequest = IntentHelper.extractGetCredentialRequest(intent)
            val credentialId = intent.getLongExtra(IntentHelper.EXTRA_CREDENTIAL_ID, -1).toInt()

            // This call is currently broken, have to extract this info manually for now
            //val callingAppInfo = extractCallingAppInfo(intent)
            val callingPackageName =
                intent.getStringExtra(IntentHelper.EXTRA_CALLING_PACKAGE_NAME)!!
            val callingOrigin = intent.getStringExtra(IntentHelper.EXTRA_ORIGIN)

            Logger.i(TAG, "CredId: $credentialId ${cmrequest!!.credentialOptions.get(0).requestMatcher}")
            Logger.i(TAG, "Calling app $callingPackageName $callingOrigin")

            val dataElements = mutableListOf<DocumentRequest.DataElement>()

            val json = JSONObject(cmrequest!!.credentialOptions.get(0).requestMatcher)
            val provider = json.getJSONArray("providers").getJSONObject(0)

            val protocol = provider.getString("protocol")
            Logger.i(TAG, "Request protocol: $protocol")
            val request = provider.getString("request")
            Logger.i(TAG, "Request: $request")
            if (protocol == "preview") {
                // Extract params from the preview protocol request
                val previewRequest = JSONObject(request)
                val selector = previewRequest.getJSONObject("selector")
                val nonceBase64 = previewRequest.getString("nonce")
                val readerPublicKeyBase64 = previewRequest.getString("readerPublicKey")
                val docType = selector.getString("doctype")
                Logger.i(TAG, "DocType: $docType")
                Logger.i(TAG, "nonce: $nonceBase64")
                Logger.i(TAG, "readerPublicKey: $readerPublicKeyBase64")

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
                    Logger.i(TAG, "Field $namespace $name $intentToRetain")
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
                lifecycleScope.launch {
                    val deviceResponse = showPresentmentFlowAndGetDeviceResponse(
                        credentialId,
                        dataElements,
                        encodedSessionTranscript
                    )

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
                    IntentHelper.setGetCredentialResponse(
                        resultData,
                        createGetCredentialResponse(response)
                    )
                    setResult(RESULT_OK, resultData)
                    finish()
                }

            } else if (protocol == "openid4vp") {
                val openid4vpRequest = JSONObject(request)
                val clientID = openid4vpRequest.getString("client_id")
                Logger.i(TAG, "client_id $clientID")
                val nonceBase64 = openid4vpRequest.getString("nonce")
                Logger.i(TAG, "nonce: $nonceBase64")
                val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP or Base64.URL_SAFE)

                val presentationDefinition = openid4vpRequest.getJSONObject("presentation_definition")
                val inputDescriptors = presentationDefinition.getJSONArray("input_descriptors")
                if (inputDescriptors.length() != 1) {
                    throw IllegalArgumentException("Only support a single input input_descriptor")
                }
                val inputDescriptor = inputDescriptors.getJSONObject(0)!!
                val docType = inputDescriptor.getString("id")
                Logger.i(TAG, "DocType: $docType")

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
                    Logger.i(TAG, "namespace $namespace name $name")
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
                lifecycleScope.launch {
                    val deviceResponse = showPresentmentFlowAndGetDeviceResponse(
                        credentialId,
                        dataElements,
                        encodedSessionTranscript
                    )
                    // Create the openid4vp response
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
                    IntentHelper.setGetCredentialResponse(
                        resultData,
                        createGetCredentialResponse(response)
                    )
                    setResult(RESULT_OK, resultData)
                    finish()

                }
            } else {
                // Unknown protocol
                throw IllegalArgumentException("Unknown protocol")
            }

        } catch (e: Exception) {
            Logger.i(TAG, "Exception $e")
            val resultData = Intent()
            IntentHelper.setGetCredentialException(resultData, e.toString(), e.message)
            setResult(RESULT_OK, resultData)
            finish()
        }
    }

    /**
     * Show the Presentment Flow and handle producing the DeviceResponse CBOR bytes.
     *
     * @param credentialId the int index of [Document] in [DocumentStore]
     * @param dataElements the list of requested data points of a credential
     * @param encodedSessionTranscript CBOR bytes
     * @return the DeviceResponse CBOR bytes containing the [Document] for the given [credentialId]
     */
    private suspend fun showPresentmentFlowAndGetDeviceResponse(
        credentialId: Int,
        dataElements: List<DocumentRequest.DataElement>,
        encodedSessionTranscript: ByteArray,
    ): ByteArray {
        val mdocCredential = getMdocCredentialForCredentialId(credentialId)
        val documentCborBytes = showPresentmentFlow(
            activity = this@CredmanPresentationActivity,
            walletApp = walletApp,
            documentRequest = DocumentRequest(dataElements),
            mdocCredential = mdocCredential,
            // TODO: Need to extend TrustManager with a verify() variants which takes a domain or appId
            trustPoint = null,
            encodedSessionTranscript = encodedSessionTranscript,
        )
        // Create ISO DeviceResponse
        DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK).run {
            addDocument(documentCborBytes)
            return generate()
        }
    }

    /**
     * Return the MdocCredential that has the given Int credentialId.
     *
     * @param credentialId the index of the credential in the document store.
     * @return the [MdocCredential] object.
     */
    private fun getMdocCredentialForCredentialId(credentialId: Int): MdocCredential {
        val documentName = walletApp.documentStore.listDocuments().get(credentialId)
        val document = walletApp.documentStore.lookupDocument(documentName)

        return document!!.findCredential(
            WalletApplication.CREDENTIAL_DOMAIN_MDOC,
            Clock.System.now()
        ) as MdocCredential
    }

    private fun createGetCredentialResponse(response: String): GetCredentialResponse {
        val bundle = Bundle()
        bundle.putByteArray("identityToken", response.toByteArray())
        val credentialResponse = com.google.android.gms.identitycredentials.Credential("type", bundle)
        return GetCredentialResponse(credentialResponse)
    }
}
