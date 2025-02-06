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
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.Simple
import com.android.identity.cbor.Tstr
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.issuance.WalletDocumentMetadata
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.mdoc.util.toMdocRequest
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.util.fromBase64Url
import com.android.identity_credential.wallet.WalletApplication
import com.android.identity_credential.wallet.presentation.showMdocPresentmentFlow
import com.android.identity.request.Requester
import com.android.identity.request.MdocClaim
import com.android.identity.request.MdocRequest
import com.google.android.gms.identitycredentials.Credential
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

            val callingAppInfo = IntentHelper.extractCallingAppInfo(intent)!!
            val callingPackageName = callingAppInfo.packageName
            val callingOrigin = callingAppInfo.origin

            Logger.i(TAG, "CredId: $credentialId ${cmrequest!!.credentialOptions.get(0).requestMatcher}")
            Logger.i(TAG, "Calling app $callingPackageName $callingOrigin")

            val requestedData = mutableMapOf<String, MutableList<Pair<String, Boolean>>>()

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
                    requestedData.getOrPut(namespace) { mutableListOf() }
                        .add(Pair(name, intentToRetain))
                }

                lifecycleScope.launch {
                    val mdocCredential = getMdocCredentialForCredentialId(credentialId)
                    val claims = MdocUtil.generateClaims(
                        docType,
                        requestedData,
                        walletApp.documentTypeRepository,
                        mdocCredential
                    )

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
                    val deviceResponse = showPresentmentFlowAndGetDeviceResponse(
                        mdocCredential,
                        claims,
                        null,
                        callingOrigin,
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

            } else if (protocol == "austroads-request-forwarding-v2") {
                val arfRequest = JSONObject(request)
                val deviceRequestBase64 = arfRequest.getString("deviceRequest")
                val encryptionInfoBase64 = arfRequest.getString("encryptionInfo")
                Logger.i(TAG, "origin: ${callingOrigin!!}")
                Logger.iCbor(TAG, "deviceRequest", deviceRequestBase64.fromBase64Url())
                Logger.iCbor(TAG, "encryptionInfo", encryptionInfoBase64.fromBase64Url())

                val encodedSessionTranscript =
                    Cbor.encode(
                        CborArray.builder()
                            .add(Simple.NULL) // DeviceEngagementBytes
                            .add(Simple.NULL) // EReaderKeyBytes
                            .addArray() // BrowserHandover
                            .add("ARFHandoverv2")
                            .add(encryptionInfoBase64)
                            .add(callingOrigin!!)
                            .end()
                            .end()
                            .build()
                    )

                // For now we only consider the first document request
                val docRequest = DeviceRequestParser(
                    deviceRequestBase64.fromBase64Url(),
                    encodedSessionTranscript
                ).parse().docRequests[0]

                lifecycleScope.launch {
                    val mdocCredential = getMdocCredentialForCredentialId(credentialId)
                    val claims = docRequest.toMdocRequest(
                        documentTypeRepository = walletApp.documentTypeRepository,
                        mdocCredential = mdocCredential
                    ).claims

                    val encryptionInfo = Cbor.decode(encryptionInfoBase64.fromBase64Url())
                    if (encryptionInfo.asArray.get(0).asTstr != "ARFEncryptionv2") {
                        throw IllegalArgumentException("Malformed EncryptionInfo")
                    }
                    val nonce = encryptionInfo.asArray.get(1).asMap.get(Tstr("nonce"))!!.asBstr
                    val readerPublicKey = encryptionInfo.asArray.get(1).asMap.get(Tstr
                        ("readerPublicKey"))!!.asCoseKey.ecPublicKey

                    // See if we recognize the reader/verifier
                    var trustPoint: TrustPoint? = null
                    if (docRequest.readerAuthenticated) {
                        val result = walletApp.readerTrustManager.verify(
                            docRequest.readerCertificateChain!!.certificates,
                        )
                        if (result.isTrusted && result.trustPoints.isNotEmpty()) {
                            trustPoint = result.trustPoints.first()
                        } else if (result.error != null) {
                            Logger.w(
                                TAG,
                                "Error finding TrustPoint for reader auth",
                                result.error!!
                            )
                        }
                    }
                    Logger.i(TAG, "TrustPoint: $trustPoint")

                    val deviceResponse = showPresentmentFlowAndGetDeviceResponse(
                        mdocCredential,
                        claims,
                        trustPoint,
                        callingOrigin,
                        encodedSessionTranscript,
                    )

                    val (cipherText, encapsulatedPublicKey) = Crypto.hpkeEncrypt(
                        Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
                        readerPublicKey,
                        deviceResponse,
                        encodedSessionTranscript
                    )
                    val encryptedResponse =
                        Cbor.encode(
                            CborArray.builder()
                                .add("ARFencryptionv2")
                                .addMap()
                                .put("pkEM", encapsulatedPublicKey.toCoseKey().toDataItem())
                                .put("cipherText", cipherText)
                                .end()
                                .end()
                                .build()
                        )

                    // Create the preview response
                    val responseJson = JSONObject()
                    responseJson.put(
                        "encryptedResponse",
                        Base64.encodeToString(
                            encryptedResponse,
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
                    requestedData.getOrPut(namespace) { mutableListOf() }
                        .add(Pair(name, intentToRetain))
                }
                lifecycleScope.launch {
                    val mdocCredential = getMdocCredentialForCredentialId(credentialId)
                    val claims = MdocUtil.generateClaims(
                        docType,
                        requestedData,
                        walletApp.documentTypeRepository,
                        mdocCredential
                    )

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

                    val deviceResponse = showPresentmentFlowAndGetDeviceResponse(
                        mdocCredential,
                        claims,
                        null,
                        callingOrigin,
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
            Logger.i(TAG, "Exception caught while generating response", e)
            val resultData = Intent()
            IntentHelper.setGetCredentialException(resultData, e.toString(), e.message)
            setResult(RESULT_OK, resultData)
            finish()
        }
    }

    /**
     * Show the Presentment Flow and handle producing the DeviceResponse CBOR bytes.
     *
     * @param mdocCredential the credential.
     * @param claims the list of fields to request.
     * @param trustPoint The trust point, if known.
     * @param websiteOrigin the Website Origin, if known.
     * @param encodedSessionTranscript CBOR bytes.
     * @return the DeviceResponse CBOR bytes containing the [Document] for the given credential.
     */
    private suspend fun showPresentmentFlowAndGetDeviceResponse(
        mdocCredential: MdocCredential,
        claims: List<MdocClaim>,
        trustPoint: TrustPoint?,
        websiteOrigin: String?,
        encodedSessionTranscript: ByteArray,
    ): ByteArray {
        val documentConfiguration = (mdocCredential.document.metadata as WalletDocumentMetadata).documentConfiguration
        val documentCborBytes = showMdocPresentmentFlow(
            activity = this@CredmanPresentationActivity,
            request = MdocRequest(
                requester = Requester(websiteOrigin = websiteOrigin),
                claims = claims,
                docType = mdocCredential.docType
            ),
            document = ConsentDocument(
                name = documentConfiguration.displayName,
                description = documentConfiguration.typeDisplayName,
                cardArt = documentConfiguration.cardArt,
            ),
            trustPoint = trustPoint,
            credential = mdocCredential,
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
    private suspend fun getMdocCredentialForCredentialId(credentialId: Int): MdocCredential {
        val documentName = walletApp.documentStore.listDocuments()[credentialId]
        val document = walletApp.documentStore.lookupDocument(documentName)

        return document!!.findCredential(
            WalletApplication.CREDENTIAL_DOMAIN_MDOC,
            Clock.System.now()
        ) as MdocCredential
    }

    private fun createGetCredentialResponse(response: String): GetCredentialResponse {
        val bundle = Bundle()
        bundle.putByteArray("identityToken", response.toByteArray())
        val credentialResponse = Credential("type", bundle)
        return GetCredentialResponse(credentialResponse)
    }
}
