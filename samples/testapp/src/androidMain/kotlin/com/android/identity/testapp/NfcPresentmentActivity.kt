package com.android.identity.testapp

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import com.android.identity.appsupport.ui.AppTheme
import com.android.identity.appsupport.ui.presentment.Presentment
import com.android.identity.util.AndroidContexts
import identitycredential.samples.testapp.generated.resources.Res
import identitycredential.samples.testapp.generated.resources.app_icon
import identitycredential.samples.testapp.generated.resources.app_name
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.resources.stringResource

class NfcPresentmentActivity : FragmentActivity() {
    companion object {
        private const val TAG = "NfcPresentmentActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AndroidContexts.setCurrentActivity(this)
        setContent {
            AppTheme {
                Presentment(
                    presentmentModel = NdefService.presentmentModel,
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