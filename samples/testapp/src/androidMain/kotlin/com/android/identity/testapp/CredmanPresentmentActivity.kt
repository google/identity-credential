package com.android.identity.testapp

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import com.android.identity.appsupport.ui.AppTheme
import com.android.identity.appsupport.ui.digitalcredentials.DigitalCredentials
import com.android.identity.appsupport.ui.digitalcredentials.getCredentialForId
import com.android.identity.appsupport.ui.presentment.DigitalCredentialsPresentmentMechanism
import com.android.identity.appsupport.ui.presentment.Presentment
import com.android.identity.appsupport.ui.presentment.PresentmentModel
import com.android.identity.util.AndroidContexts
import com.android.identity.util.Logger
import com.google.android.gms.identitycredentials.Credential
import com.google.android.gms.identitycredentials.GetCredentialResponse
import com.google.android.gms.identitycredentials.IntentHelper
import identitycredential.samples.testapp.generated.resources.Res
import identitycredential.samples.testapp.generated.resources.app_icon
import identitycredential.samples.testapp.generated.resources.app_name
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.resources.stringResource
import org.json.JSONObject

class CredmanPresentmentActivity: FragmentActivity() {
    companion object {
        private const val TAG = "CredmanPresentmentActivity"
    }

    private val presentmentModel = PresentmentModel()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AndroidContexts.setCurrentActivity(this)

        try {
            val request = IntentHelper.extractGetCredentialRequest(intent)
                ?: throw IllegalStateException("Error extracting GetCredentialRequest")
            val credentialId = intent.getLongExtra(IntentHelper.EXTRA_CREDENTIAL_ID, -1).toInt()

            val callingAppInfo = IntentHelper.extractCallingAppInfo(intent)!!
            val callingPackageName = callingAppInfo.packageName
            val callingOrigin = callingAppInfo.origin

            val json = JSONObject(request.credentialOptions.get(0).requestMatcher)
            val provider = json.getJSONArray("providers").getJSONObject(0)

            val credential = DigitalCredentials.Default.getCredentialForId(credentialId)
                ?: throw Error("No registered credential for ID $credentialId")

            val mechanism = object : DigitalCredentialsPresentmentMechanism(
                appId = callingPackageName,
                webOrigin = callingOrigin,
                protocol = provider.getString("protocol"),
                request = provider.getString("request"),
                document = credential.document
            ) {
                override fun sendResponse(response: String) {
                    val bundle = Bundle()
                    bundle.putByteArray("identityToken", response.toByteArray())
                    val credentialResponse = Credential("type", bundle)

                    val resultData = Intent()
                    IntentHelper.setGetCredentialResponse(
                        resultData,
                        GetCredentialResponse(credentialResponse)
                    )
                    setResult(RESULT_OK, resultData)
                }

                override fun close() {
                    Logger.i(TAG, "close")
                }
            }

            presentmentModel.reset()
            presentmentModel.setConnecting()
            presentmentModel.setMechanism(mechanism)

        } catch (e: Throwable) {
            Logger.i(TAG, "Error processing request", e)
            e.printStackTrace()
            finish()
            return
        }

        setContent {
            AppTheme {
                Presentment(
                    presentmentModel = presentmentModel,
                    documentTypeRepository = TestAppUtils.documentTypeRepository,
                    source = TestAppPresentmentSource(App.settingsModel),
                    onPresentmentComplete = { finish() },
                    appName = stringResource(Res.string.app_name),
                    appIconPainter = painterResource(Res.drawable.app_icon),
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        AndroidContexts.setCurrentActivity(this)
    }

    override fun onPause() {
        super.onPause()
        AndroidContexts.setCurrentActivity(null)
    }

    override fun onDestroy() {
        super.onDestroy()
    }
}
