package com.android.identity_credential.wallet.presentation

import androidx.fragment.app.FragmentActivity
import com.android.identity.android.securearea.AndroidKeystoreKeyUnlockData
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.securearea.UserAuthenticationType
import com.android.identity.android.securearea.cloud.CloudKeyLockedException
import com.android.identity.android.securearea.cloud.CloudKeyUnlockData
import com.android.identity.android.securearea.cloud.CloudSecureArea
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.cbor.Cbor
import com.android.identity.credential.Credential
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.crypto.Algorithm
import com.android.identity.document.Document
import com.android.identity.document.NameSpacedData
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.sdjwt.SdJwtVerifiableCredential
import com.android.identity.securearea.KeyLockedException
import com.android.identity.securearea.KeyUnlockData
import com.android.identity.securearea.software.SoftwareKeyInfo
import com.android.identity.securearea.software.SoftwareKeyUnlockData
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.ui.prompt.biometric.showBiometricPrompt
import com.android.identity.request.Claim
import com.android.identity.request.Requester
import com.android.identity.request.MdocClaim
import com.android.identity.request.MdocRequest
import com.android.identity.request.Request
import com.android.identity.request.VcClaim
import com.android.identity.request.VcRequest
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity_credential.wallet.ui.prompt.consent.showConsentPrompt
import com.android.identity_credential.wallet.ui.prompt.passphrase.showPassphrasePrompt

const val TAG = "PresentmentFlow"
const val MAX_PASSPHRASE_ATTEMPTS = 3

private suspend fun showPresentmentFlowImpl(
    activity: FragmentActivity,
    request: Request,
    trustPoint: TrustPoint?,
    document: ConsentDocument,
    credential: Credential,
    signAndGenerate: (KeyUnlockData?) -> ByteArray
): ByteArray {
    // always show the Consent Prompt first
    showConsentPrompt(
        activity = activity,
        document = document,
        request = request,
        trustPoint = trustPoint
    ).let { resultSuccess ->
        // throw exception if user canceled the Prompt
        if (!resultSuccess){
            throw UserCanceledPromptException()
        }
    }

    // initially null and updated when catching a KeyLockedException in the while-loop below
    var keyUnlockData: KeyUnlockData? = null
    var remainingPassphraseAttempts = MAX_PASSPHRASE_ATTEMPTS

    while (true) {
        try {
            return signAndGenerate(keyUnlockData)
        }
        // if KeyLockedException is raised show the corresponding Prompt to unlock
        // the auth key for a Credential's Secure Area
        catch (e: KeyLockedException) {
            // The only way we should get a KeyLockedException is if this is a secure area bound
            // credential.
            val secureAreaBoundCredential = credential as SecureAreaBoundCredential
            when (secureAreaBoundCredential.secureArea) {
                // show Biometric prompt
                is AndroidKeystoreSecureArea -> {
                    val unlockData =
                        AndroidKeystoreKeyUnlockData(secureAreaBoundCredential.alias)
                    val cryptoObject =
                        unlockData.getCryptoObjectForSigning(Algorithm.ES256)

                    // update KeyUnlockData to be used on the next loop iteration
                    keyUnlockData = unlockData

                    val successfulBiometricResult = showBiometricPrompt(
                        activity = activity,
                        title = activity.resources.getString(R.string.presentation_biometric_prompt_title),
                        subtitle = activity.resources.getString(R.string.presentation_biometric_prompt_subtitle),
                        cryptoObject = cryptoObject,
                        userAuthenticationTypes = setOf(
                            UserAuthenticationType.BIOMETRIC,
                            UserAuthenticationType.LSKF
                        ),
                        requireConfirmation = false
                    )
                    // if user cancelled or was unable to authenticate, throw IllegalStateException
                    check(successfulBiometricResult) { "Biometric Unsuccessful" }
                }

                // show Passphrase prompt
                is SoftwareSecureArea -> {
                    // enforce a maximum number of attempts
                    if (remainingPassphraseAttempts == 0) {
                        throw IllegalStateException("Error! Reached maximum number of Passphrase attempts.")
                    }
                    remainingPassphraseAttempts--

                    val softwareKeyInfo =
                        secureAreaBoundCredential.secureArea.getKeyInfo(secureAreaBoundCredential.alias) as SoftwareKeyInfo
                    val constraints = softwareKeyInfo.passphraseConstraints!!
                    val title =
                        if (constraints.requireNumerical)
                            activity.resources.getString(R.string.passphrase_prompt_pin_title)
                        else
                            activity.resources.getString(R.string.passphrase_prompt_passphrase_title)
                    val content =
                        if (constraints.requireNumerical) {
                            activity.resources.getString(R.string.passphrase_prompt_pin_content)
                        } else {
                            activity.resources.getString(
                                R.string.passphrase_prompt_passphrase_content
                            )
                        }
                    val passphrase = showPassphrasePrompt(
                        activity = activity,
                        constraints = constraints,
                        title = title,
                        content = content,
                    )

                    // if passphrase is null then user canceled the prompt
                    if (passphrase == null) {
                        throw UserCanceledPromptException()
                    }

                    keyUnlockData = SoftwareKeyUnlockData(passphrase)
                }

                // Shows Wallet PIN/Passphrase prompt or Biometrics/LSKF, depending
                is CloudSecureArea -> {
                    if (keyUnlockData == null) {
                        keyUnlockData = CloudKeyUnlockData(
                            secureAreaBoundCredential.secureArea as CloudSecureArea,
                            secureAreaBoundCredential.alias,
                        )
                    }

                    when ((e as CloudKeyLockedException).reason) {
                        CloudKeyLockedException.Reason.WRONG_PASSPHRASE -> {
                            // enforce a maximum number of attempts
                            if (remainingPassphraseAttempts == 0) {
                                throw IllegalStateException("Error! Reached maximum number of Passphrase attempts.")
                            }
                            remainingPassphraseAttempts--

                            val constraints = (secureAreaBoundCredential.secureArea as CloudSecureArea).passphraseConstraints
                            val title =
                                if (constraints.requireNumerical)
                                    activity.resources.getString(R.string.passphrase_prompt_csa_pin_title)
                                else
                                    activity.resources.getString(R.string.passphrase_prompt_csa_passphrase_title)
                            val content =
                                if (constraints.requireNumerical) {
                                    activity.resources.getString(R.string.passphrase_prompt_csa_pin_content)
                                } else {
                                    activity.resources.getString(
                                        R.string.passphrase_prompt_csa_passphrase_content
                                    )
                                }
                            val passphrase = showPassphrasePrompt(
                                activity = activity,
                                constraints = constraints,
                                title = title,
                                content = content,
                            )

                            // if passphrase is null then user canceled the prompt
                            if (passphrase == null) {
                                throw UserCanceledPromptException()
                            }
                            (keyUnlockData as CloudKeyUnlockData).passphrase = passphrase
                        }

                        CloudKeyLockedException.Reason.USER_NOT_AUTHENTICATED -> {
                            val successfulBiometricResult = showBiometricPrompt(
                                activity = activity,
                                title = activity.resources.getString(R.string.presentation_biometric_prompt_title),
                                subtitle = activity.resources.getString(R.string.presentation_biometric_prompt_subtitle),
                                cryptoObject = (keyUnlockData as CloudKeyUnlockData).cryptoObject,
                                userAuthenticationTypes = setOf(
                                    UserAuthenticationType.BIOMETRIC,
                                    UserAuthenticationType.LSKF
                                ),
                                requireConfirmation = false
                            )
                            // if user cancelled or was unable to authenticate, throw IllegalStateException
                            check(successfulBiometricResult) { "Biometric Unsuccessful" }
                        }
                    }
                }

                // for secure areas not yet implemented
                else -> {
                    throw IllegalStateException("No prompts implemented for Secure Area ${secureAreaBoundCredential.secureArea.displayName}")
                }
            }
        }
    }
}

suspend fun showMdocPresentmentFlow(
    activity: FragmentActivity,
    request: MdocRequest,
    trustPoint: TrustPoint?,
    document: ConsentDocument,
    credential: MdocCredential,
    encodedSessionTranscript: ByteArray,
): ByteArray {
    return showPresentmentFlowImpl(
        activity,
        request,
        trustPoint,
        document,
        credential
    ) { keyUnlockData: KeyUnlockData? ->
        mdocSignAndGenerate(request.claims, credential, encodedSessionTranscript, keyUnlockData)
    }
}

suspend fun showSdJwtPresentmentFlow(
    activity: FragmentActivity,
    request: VcRequest,
    trustPoint: TrustPoint?,
    document: ConsentDocument,
    credential: Credential,
    nonce: String,
    clientId: String,
): ByteArray {
    return showPresentmentFlowImpl(
        activity,
        request,
        trustPoint,
        document,
        credential
    ) { keyUnlockData: KeyUnlockData? ->
        val sdJwt = SdJwtVerifiableCredential.fromString(
            String(credential.issuerProvidedData, Charsets.US_ASCII))

        val requestedAttributes = request.claims.map { it.claimName }.toSet()
        Logger.i(
            TAG, "Filtering requested attributes (${requestedAttributes.joinToString()}) " +
                    "from disclosed attributes (${sdJwt.disclosures.joinToString { it.key }})")
        val filteredSdJwt = sdJwt.discloseOnly(requestedAttributes)
        Logger.i(TAG, "Remaining disclosures: ${filteredSdJwt.disclosures.joinToString { it.key }}")
        if (filteredSdJwt.disclosures.isEmpty()) {
            // This is going to cause problems with the encoding and decoding. We should
            // cancel the submission, since we can't fulfill any of the requested
            // information.
            // TODO: Handle this cancellation better.
            Logger.e(TAG, "No disclosures remaining.")
        }

        val secureAreaBoundCredential = credential as? SecureAreaBoundCredential
        filteredSdJwt.createPresentation(
            secureAreaBoundCredential?.secureArea,
            secureAreaBoundCredential?.alias,
            keyUnlockData,
            Algorithm.ES256,
            nonce!!,
            clientId!!
        ).toString().toByteArray(Charsets.US_ASCII)
    }
}

private fun mdocSignAndGenerate(
    claims: List<Claim>,
    credential: SecureAreaBoundCredential,
    encodedSessionTranscript: ByteArray,
    keyUnlockData: KeyUnlockData?
): ByteArray {
    // create the document generator for the suitable Document (of DocumentRequest)
    val documentGenerator =
        createDocumentGenerator(
            claims = claims,
            document = credential.document,
            credential = credential,
            sessionTranscript = encodedSessionTranscript
        )
    // try signing the data of the document (or KeyLockedException is thrown)
    documentGenerator.setDeviceNamespacesSignature(
        NameSpacedData.Builder().build(),
        credential.secureArea,
        credential.alias,
        keyUnlockData,
        Algorithm.ES256
    )
    // increment the credential's usage count since it just finished signing the data successfully
    credential.increaseUsageCount()
    // finally add the document to the response generator and generate the bytes
    return documentGenerator.generate()
}

private fun createDocumentGenerator(
    claims: List<Claim>,
    document: Document,
    credential: Credential,
    sessionTranscript: ByteArray,
): DocumentGenerator {
    val staticAuthData = StaticAuthDataParser(credential.issuerProvidedData).parse()
    val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
        getNamespacesAndDataElements(claims),
        document.documentConfiguration.mdocConfiguration!!.staticData,
        staticAuthData
    )

    val issuerAuthCoseSign1 = Cbor.decode(staticAuthData.issuerAuth).asCoseSign1
    val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
    val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)
    val mso = MobileSecurityObjectParser(encodedMso).parse()

    val documentGenerator = DocumentGenerator(
        mso.docType,
        staticAuthData.issuerAuth,
        sessionTranscript
    )
    documentGenerator.setIssuerNamespaces(mergedIssuerNamespaces)
    return documentGenerator
}

private fun getNamespacesAndDataElements(
    claims: List<Claim>
): Map<String, List<String>> {
    val ret = mutableMapOf<String, MutableList<String>>()
    for (field in claims) {
        field as MdocClaim
        val listOfDataElements = ret.getOrPut(field.namespaceName) { mutableListOf() }
        listOfDataElements.add(field.dataElementName)
    }
    return ret
}

class UserCanceledPromptException : Exception()