package com.android.identity.testapp.ui

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import com.android.identity.appsupport.ui.presentment.Presentment
import com.android.identity.appsupport.ui.presentment.PresentmentModel
import com.android.identity.testapp.TestAppSettingsModel
import com.android.identity.testapp.TestAppPresentmentSource
import com.android.identity.testapp.TestAppUtils
import identitycredential.samples.testapp.generated.resources.Res
import identitycredential.samples.testapp.generated.resources.app_icon
import identitycredential.samples.testapp.generated.resources.app_name
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.resources.stringResource

private const val TAG = "PresentmentScreen"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PresentmentScreen(
    presentmentModel: PresentmentModel,
    settingsModel: TestAppSettingsModel,
    onPresentationComplete: () -> Unit,
) {
    Presentment(
        presentmentModel = presentmentModel,
        documentTypeRepository = TestAppUtils.documentTypeRepository,
        source = TestAppPresentmentSource(settingsModel),
        onPresentmentComplete = onPresentationComplete,
        appName = stringResource(Res.string.app_name),
        appIconPainter = painterResource(Res.drawable.app_icon),
    )
}