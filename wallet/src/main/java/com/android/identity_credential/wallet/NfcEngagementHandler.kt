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

import android.content.Context
import android.content.pm.PackageManager
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Vibrator
import androidx.core.content.ContextCompat
import com.android.identity.android.mdoc.engagement.NfcEngagementHelper
import com.android.identity.android.mdoc.transport.DataTransport
import com.android.identity.android.util.NfcUtil
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.util.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class NfcEngagementHandler : HostApduService() {
    companion object {
        private val TAG = "NfcEngagementHandler"
    }

    private var engagementHelper: NfcEngagementHelper? = null

    private val eDeviceKeyCurve = EcCurve.P256
    private val eDeviceKey by lazy {
        Crypto.createEcPrivateKey(eDeviceKeyCurve)
    }
    private val nfcEngagementListener = object : NfcEngagementHelper.Listener {

        override fun onTwoWayEngagementDetected() {
            Logger.i(TAG, "onTwoWayEngagementDetected")
        }

        override fun onHandoverSelectMessageSent() {
            Logger.i(TAG, "onHandoverSelectMessageSent")
            // This is invoked _just_ before the NFC tag reader will do a READ_BINARY
            // for the Handover Select message. Vibrate the device to indicate to the
            // user they can start removing the device from the reader.
            val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            val vibrationPattern = longArrayOf(0, 500, 50, 300)
            val indexInPatternToRepeat = -1
            vibrator.vibrate(vibrationPattern, indexInPatternToRepeat)
        }

        override fun onDeviceConnecting() {
            Logger.i(TAG, "onDeviceConnecting")
        }

        override fun onDeviceConnected(transport: DataTransport) {
            Logger.i(TAG, "onDeviceConnected")

            PresentationActivity.startPresentation(applicationContext, transport,
                engagementHelper!!.handover, eDeviceKey,
                engagementHelper!!.deviceEngagement)

            engagementHelper?.close()
            engagementHelper = null
        }

        override fun onError(error: Throwable) {
            Logger.i(TAG, "Engagement Listener: onError -> ${error.message}")
            engagementHelper?.close()
            engagementHelper = null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Logger.i(TAG, "onDestroy, this=$this")
        if (PresentationActivity.isPresentationActive()) {
            PresentationActivity.stopPresentation(applicationContext)
        }
    }

    override fun onCreate() {
        super.onCreate()
        Logger.i(TAG, "onCreate, this=$this")
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        Logger.dHex(TAG, "processCommandApdu", commandApdu)

        // If we don't have the required BLE permissions, tell the reader "No thanks!"
        // and notify the user that they need to grant permissions
        for (permission in WalletApplication.MDOC_PROXIMITY_PERMISSIONS) {
            if (applicationContext.checkSelfPermission(permission) == PackageManager.PERMISSION_DENIED) {
                Logger.e(TAG, "Don't have permission $permission - sending FILE_NOT_FOUND APDU")

                val walletApplication = application as WalletApplication

                // Make sure the user sees the permissions SnackBar next time they go to the app...
                walletApplication.settingsModel.hideMissingProximityPermissionsWarning.value = false

                // This is best effort, user may not have grant POST_NOTIFICATIONS permission..
                // but if they do, they'll see this notification and tapping on it will bring
                // them to MainScreen of the wallet app where we show a SnackBar with a button
                // to help remedy the problem.
                walletApplication.postNotificationForMissingMdocProximityPermissions()

                // Inform the reader that we can't continue.
                return NfcUtil.STATUS_WORD_FILE_NOT_FOUND
            }
        }

        if (engagementHelper == null) {
            val application: WalletApplication = application as WalletApplication
            // TODO: how to avoid this? Need to create non-blocking way to determine if there
            // are any documents in the documentStore
            val hasDocuments = runBlocking {
                application.documentStore.withLock {
                    application.documentStore.listDocuments().isNotEmpty()
                }
            }
            if (hasDocuments && !PresentationActivity.isPresentationActive()) {
                PresentationActivity.engagementDetected(application.applicationContext)

                val walletApplication = application as WalletApplication
                val (connectionMethods, options) = walletApplication.settingsModel
                    .createConnectionMethodsAndOptions()
                val builder = NfcEngagementHelper.Builder(
                    applicationContext,
                    eDeviceKey.publicKey,
                    options,
                    nfcEngagementListener,
                    ContextCompat.getMainExecutor(applicationContext)
                )

                if (walletApplication.settingsModel.nfcStaticHandoverEnabled.value == true) {
                    builder.useStaticHandover(connectionMethods)
                } else {
                    builder.useNegotiatedHandover()
                }
                engagementHelper = builder.build()
            }
        }

        return engagementHelper?.nfcProcessCommandApdu(commandApdu)
    }

    override fun onDeactivated(reason: Int) {
        Logger.i(TAG, "onDeactivated: reason-> $reason")
        engagementHelper?.nfcOnDeactivated(reason)

        // We need to close the NfcEngagementHelper but if we're doing it as the reader moves
        // out of the field, it's too soon as it may take a couple of seconds to establish
        // the connection, triggering onDeviceConnected() callback above.
        //
        // In fact, the reader _could_ actually take a while to establish the connection...
        // for example the UI in the mdoc doc reader might have the operator pick the
        // transport if more than one is offered. In fact this is exactly what we do in
        // our mdoc reader.
        //
        // So we give the reader 15 seconds to do this...
        //
        val timeoutSeconds = 15
        Handler(Looper.getMainLooper()).postDelayed({
            if (engagementHelper != null) {
                Logger.w(TAG, "Reader didn't connect inside $timeoutSeconds seconds, closing")
                engagementHelper!!.close()

                if (PresentationActivity.isPresentationActive()) {
                    PresentationActivity.stopPresentationReaderTimeout(applicationContext)
                }
            }
        }, timeoutSeconds * 1000L)
    }
}