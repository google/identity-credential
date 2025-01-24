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

package com.android.identity_credential.wallet

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.MutableLiveData
import androidx.navigation.compose.rememberNavController
import com.android.identity_credential.wallet.credentialoffer.extractCredentialIssuerData
import com.android.identity_credential.wallet.dynamicregistration.AidRegistrationUtil
import com.android.identity_credential.wallet.navigation.WalletDestination
import com.android.identity_credential.wallet.navigation.WalletNavigation
import com.android.identity_credential.wallet.navigation.navigateTo
import com.android.identity_credential.wallet.ui.theme.IdentityCredentialTheme
import com.android.identity_credential.wallet.util.getUrlQueryFromCustomSchemeUrl
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {
    companion object {
        private const val TAG = "MainActivity"
    }

    private lateinit var application: WalletApplication
    private val qrEngagementViewModel: QrEngagementViewModel by viewModels()
    private val provisioningViewModel: ProvisioningViewModel by viewModels()
    private val routeRequest = MutableLiveData<String?>(null)

    private val permissionTracker: PermissionTracker = if (Build.VERSION.SDK_INT >= 31) {
        PermissionTracker(this, mapOf(
            Manifest.permission.CAMERA to R.string.permission_camera,
            Manifest.permission.NFC to R.string.permission_nfc,
            Manifest.permission.BLUETOOTH_ADVERTISE to R.string.permission_bluetooth_advertise,
            Manifest.permission.BLUETOOTH_SCAN to R.string.permission_bluetooth_scan,
            Manifest.permission.BLUETOOTH_CONNECT to R.string.permission_bluetooth_connect
        ))
    } else {
        PermissionTracker(this, mapOf(
            Manifest.permission.CAMERA to R.string.permission_camera,
            Manifest.permission.NFC to R.string.permission_nfc,
            Manifest.permission.ACCESS_FINE_LOCATION to R.string.permission_bluetooth_connect
        ))
    }

    override fun onStart() {
        super.onStart()
        application.settingsModel.updateScreenLockIsSetup()
        application.documentModel.attachToActivity(this)
    }

    override fun onStop() {
        super.onStop()
        application.documentModel.detachFromActivity(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        application = getApplication() as WalletApplication
        provisioningViewModel.init(
            walletServerProvider = application.walletServerProvider,
            documentStore = application.documentStore,
            settingsModel = application.settingsModel
        )
        permissionTracker.updatePermissions()
        // handle intents with schema openid-credential-offer://
        handleOid4vciCredentialOfferIntent(intent)
        // route aids to host by default
        AidRegistrationUtil.routeAidsToHost(this)

        setContent {
            IdentityCredentialTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()

                    val route = routeRequest.observeAsState()
                    LaunchedEffect(route.value) {
                        if (route.value != null) {
                            navigateTo(navController, routeRequest.value!!)
                            routeRequest.value = null
                        }
                    }
                    WalletNavigation(
                        navController,
                        application = application,
                        provisioningViewModel = provisioningViewModel,
                        permissionTracker = permissionTracker,
                        qrEngagementViewModel = qrEngagementViewModel,
                        documentModel = application.documentModel,
                        readerModel = application.readerModel,
                    )
                }
            }
        }
    }

    /**
     * Intercept deep links when the Activity is backgrounded (has previously run).
     *
     * Handle OID4VCI openid-credential-offer deep links.
     */
    override fun onNewIntent(intent: Intent) {
        // super class handles intent internally
        super.onNewIntent(intent)
        // calls to getIntent() return the new intent
        setIntent(intent)
        // handle OID4VCI deep links starting with scheme "openid-credential-offer://"
        handleOid4vciCredentialOfferIntent(intent)
    }

    /**
     * Handle incoming Intents from deep links emanating from onCreate() or onNewIntent() and
     * notifies Compose to initiate the provisioning flow (via [ProvisioningViewModel]) for
     * obtaining an Issuing Authority from a Uri (that is found in the deep link's payload).
     */
    private fun handleOid4vciCredentialOfferIntent(intent: Intent) {
        if (intent.action == Intent.ACTION_VIEW) {
            // perform recomposition only if deep link url starts with oid4vci credential offer scheme
            if (intent.dataString?.startsWith(WalletApplication.OID4VCI_CREDENTIAL_OFFER_URL_SCHEME) == true) {
                CoroutineScope(Dispatchers.Main).launch {
                    val query = getUrlQueryFromCustomSchemeUrl(intent.dataString!!)
                    val offer = extractCredentialIssuerData(query)
                    if (offer != null) {
                        routeRequest.value = WalletDestination.ProvisionDocument.route
                        provisioningViewModel.start(
                            issuerIdentifier = null,
                            openid4VciCredentialOffer = offer
                        )
                    }
                }
            }
        }
    }
}
