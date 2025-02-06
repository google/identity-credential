/*
 * Copyright (C) 2023 Google LLC
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

package com.android.identity.preconsent_mdl

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RawRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.android.identity.android.securearea.AndroidKeystoreCreateKeySettings
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.toDataItem
import com.android.identity.cbor.toDataItemDateTimeString
import com.android.identity.cose.Cose
import com.android.identity.cose.CoseLabel
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.document.NameSpacedData
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.preconsent_mdl.ui.theme.IdentityCredentialTheme
import com.android.identity.util.Logger
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import kotlin.random.Random

class MainActivity : ComponentActivity() {

    companion object {
        private val TAG = "MainActivity"

        const val AUTH_KEY_DOMAIN = "mdoc"

        const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
        const val MDL_NAMESPACE = "org.iso.18013.5.1"
        const val AAMVA_NAMESPACE = "org.iso.18013.5.1.aamva"
    }

    private lateinit var transferHelper: TransferHelper

    private var documentId: String? = null

    private suspend fun provisionDocuments() {
        val list = transferHelper.documentStore.listDocuments()
        if (list.isEmpty()) {
            provisionDocument()
        } else {
            documentId = list[0]
            Logger.d(TAG, "Already have document $documentId")
        }
    }

    private suspend fun provisionDocument() {
        val baos = ByteArrayOutputStream()
        BitmapFactory.decodeResource(applicationContext.resources, R.drawable.img_erika_portrait)
            .compress(Bitmap.CompressFormat.JPEG, 50, baos)
        val portrait: ByteArray = baos.toByteArray()

        val now = Clock.System.now()
        val expiryDate = Instant.fromEpochMilliseconds(
            now.toEpochMilliseconds() + 5 * 365 * 24 * 3600 * 1000L)

        val nameSpacedData = NameSpacedData.Builder()
            .putEntryString(MDL_NAMESPACE, "given_name", "Erika")
            .putEntryString(MDL_NAMESPACE, "family_name", "Mustermann")
            .putEntryByteString(MDL_NAMESPACE, "portrait", portrait)
            .putEntryNumber(MDL_NAMESPACE, "sex", 2)
            .putEntry(MDL_NAMESPACE, "issue_date", Cbor.encode(now.toDataItemDateTimeString()))
            .putEntry(MDL_NAMESPACE, "expiry_date", Cbor.encode(expiryDate.toDataItemDateTimeString()))
            .putEntryString(MDL_NAMESPACE, "document_number", "1234567890")
            .putEntryString(MDL_NAMESPACE, "issuing_authority", "State of Utopia")
            .putEntryString(AAMVA_NAMESPACE, "DHS_compliance", "F")
            .putEntryNumber(AAMVA_NAMESPACE, "EDL_credential", 1)
            .putEntryBoolean(MDL_NAMESPACE, "age_over_18", true)
            .putEntryBoolean(MDL_NAMESPACE, "age_over_21", true)
            .build()

        val documentData = PreconsentDocumentMetadata.Data(
            displayName = "Erika's Driver License",
            typeDisplayName = "Preconcent Document",
            cardArt = null,
            issuerLogo = null,
            namespacedData = nameSpacedData
        )

        val document = transferHelper.documentStore.createDocument { metadata ->
            (metadata as PreconsentDocumentMetadata).init(documentData)
        }
        documentId = document.identifier

        // Create Credentials and MSOs, make sure they're valid for a long time
        val timeSigned = now
        val validFrom = now
        val validUntil = Instant.fromEpochMilliseconds(
            validFrom.toEpochMilliseconds() + 365 * 24 * 3600 * 1000L)

        // Create three credentials and certify them
        for (n in 0..2) {
            val pendingCredential = MdocCredential.create(
                document,
                null,
                AUTH_KEY_DOMAIN,
                transferHelper.secureAreaRepository.getImplementation(AndroidKeystoreSecureArea.IDENTIFIER)!!,
                MDL_DOCTYPE,
                AndroidKeystoreCreateKeySettings.Builder("".toByteArray()).build()
            )

            // Generate an MSO and issuer-signed data for this credentials.
            val msoGenerator = MobileSecurityObjectGenerator(
                "SHA-256",
                MDL_DOCTYPE,
                pendingCredential.getAttestation().publicKey
            )
            msoGenerator.setValidityInfo(
                timeSigned,
                validFrom,
                validUntil,
                null)
            val issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
                nameSpacedData,
                Random.Default,
                16,
                null
            )
            for (nameSpaceName in issuerNameSpaces.keys) {
                val digests = MdocUtil.calculateDigestsForNameSpace(
                    nameSpaceName,
                    issuerNameSpaces,
                    Algorithm.SHA256
                )
                msoGenerator.addDigestIdsForNamespace(nameSpaceName, digests)
            }

            ensureDocumentSigningKey()
            val mso = msoGenerator.generate()
            val taggedEncodedMso = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(mso)))
            val protectedHeaders = mapOf<CoseLabel, DataItem>(Pair(
                CoseNumberLabel(Cose.COSE_LABEL_ALG),
                Algorithm.ES256.coseAlgorithmIdentifier.toDataItem()
            ))
            val unprotectedHeaders = mapOf<CoseLabel, DataItem>(Pair(
                CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                X509CertChain(
                    listOf(X509Cert(documentSigningKeyCert.encodedCertificate))
                ).toDataItem()
            ))
            val encodedIssuerAuth = Cbor.encode(
                Cose.coseSign1Sign(
                    documentSigningKey,
                    taggedEncodedMso,
                    true,
                    Algorithm.ES256,
                    protectedHeaders,
                    unprotectedHeaders
                ).toDataItem()
            )

            val issuerProvidedAuthenticationData = StaticAuthDataGenerator(
                issuerNameSpaces,
                encodedIssuerAuth
            ).generate()

            pendingCredential.certify(
                issuerProvidedAuthenticationData,
                validFrom,
                validUntil)
        }
        Logger.d(TAG, "Created document with name ${document.identifier}")
    }

    private lateinit var documentSigningKey: EcPrivateKey
    private lateinit var documentSigningKeyCert: X509Cert

    private fun getRawResourceAsString(@RawRes resourceId: Int): String {
        val inputStream = application.applicationContext.resources.openRawResource(resourceId)
        val bytes = inputStream.readBytes()
        return String(bytes, StandardCharsets.UTF_8)
    }

    private fun ensureDocumentSigningKey() {
        if (this::documentSigningKey.isInitialized) {
            return
        }

        documentSigningKeyCert = X509Cert.fromPem(getRawResourceAsString(R.raw.ds_certificate))
        documentSigningKey = EcPrivateKey.fromPem(
            getRawResourceAsString(R.raw.ds_private_key),
            documentSigningKeyCert.ecPublicKey
        )

    }

    private val permissionsLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
            permissions.entries.forEach {
                Logger.d(TAG, "permissionsLauncher ${it.key} = ${it.value}")
                if (!it.value) {
                    Toast.makeText(
                        this,
                        "The ${it.key} permission is required for BLE",
                        Toast.LENGTH_LONG
                    ).show()
                    return@registerForActivityResult
                }
            }
        }

    private val appPermissions: Array<String> =
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            arrayOf(
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.NEARBY_WIFI_DEVICES
            )
        } else {
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
            )
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        transferHelper = TransferHelper.getInstance(applicationContext)

        lifecycleScope.launch {
            provisionDocuments()
        }

        val permissionsNeeded = appPermissions.filter { permission ->
            ContextCompat.checkSelfPermission(
                applicationContext,
                permission
            ) != PackageManager.PERMISSION_GRANTED
        }

        if (permissionsNeeded.isNotEmpty()) {
            permissionsLauncher.launch(
                permissionsNeeded.toTypedArray()
            )
        }

        setContent {
            IdentityCredentialTheme {
                MainScreen(applicationContext)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(context: Context) {
    val transferHelper = remember { TransferHelper.getInstance(context) }
    val nfcStaticHandoverEnabled =
        remember { mutableStateOf(transferHelper.getNfcStaticHandoverEnabled()) }
    val nfcNegotiatedHandoverEnabled =
        remember { mutableStateOf(transferHelper.getNfcNegotiatedHandoverEnabled()) }
    val bleCentralClientDataTransferEnabled =
        remember { mutableStateOf(transferHelper.getBleCentralClientDataTransferEnabled()) }
    val blePeripheralServerDataTransferEnabled =
        remember { mutableStateOf(transferHelper.getBlePeripheralServerDataTransferEnabled()) }
    val wifiAwareDataTransferEnabled =
        remember { mutableStateOf(transferHelper.getWifiAwareDataTransferEnabled()) }
    val nfcDataTransferEnabled =
        remember { mutableStateOf(transferHelper.getNfcDataTransferEnabled()) }
    val tcpDataTransferEnabled =
        remember { mutableStateOf(transferHelper.getTcpDataTransferEnabled()) }
    val udpDataTransferEnabled =
        remember { mutableStateOf(transferHelper.getUdpDataTransferEnabled()) }
    val l2capEnabled = remember { mutableStateOf(transferHelper.getL2CapEnabled()) }
    val experimentalPsmEnabled =
        remember { mutableStateOf(transferHelper.getExperimentalPsmEnabled()) }
    val debugEnabled = remember { mutableStateOf(transferHelper.getDebugEnabled()) }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),

        topBar = {
            CenterAlignedTopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                title = {
                    Text(
                        "mDL Preconsent Sample",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                scrollBehavior = scrollBehavior,
            )
        },
    ) { innerPadding ->
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            color = MaterialTheme.colorScheme.background
        ) {
            Column {
                val scrollState = rememberScrollState()
                Column(
                    modifier = Modifier
                        .padding(16.dp)
                        .verticalScroll(scrollState),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Column {
                        Text(
                            modifier = Modifier.fillMaxWidth(),
                            text = "This app contains an mDL with Preconsent which " +
                                    "will be presented to any mdoc reader, without authentication " +
                                    "or consent. The main purpose of this application is " +
                                    "to evaluate performance.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }

                    SettingSectionTitle(title = "Engagement Settings")
                    SettingToggle(
                        title = "NFC Static Handover",
                        subtitleOn = "NFC Static Handover enabled",
                        subtitleOff = "NFC Static Handover disabled",
                        isChecked = nfcStaticHandoverEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setNfcStaticHandoverEnabled(checked)
                            nfcStaticHandoverEnabled.value = checked
                            transferHelper.setNfcNegotiatedHandoverEnabled(!checked)
                            nfcNegotiatedHandoverEnabled.value = !checked
                        }
                    )
                    SettingToggle(
                        title = "NFC Negotiated Handover",
                        subtitleOn = "NFC Negotiated Handover enabled",
                        subtitleOff = "NFC Negotiated Handover disabled",
                        isChecked = nfcNegotiatedHandoverEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setNfcNegotiatedHandoverEnabled(checked)
                            nfcNegotiatedHandoverEnabled.value = checked
                            transferHelper.setNfcStaticHandoverEnabled(!checked)
                            nfcStaticHandoverEnabled.value = !checked
                        }
                    )
                    SettingSectionTitle(title = "Data Transfer Settings")
                    SettingToggle(
                        title = "BLE mdoc central client data retrieval",
                        subtitleOn = "BLE mdoc central client data retrieval enabled",
                        subtitleOff = "BLE mdoc central client data retrieval disabled",
                        isChecked = bleCentralClientDataTransferEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setBleCentralClientDataTransferEnabled(checked)
                            bleCentralClientDataTransferEnabled.value = checked
                        }
                    )
                    SettingToggle(
                        title = "BLE mdoc peripheral server data retrieval",
                        subtitleOn = "BLE mdoc peripheral server data retrieval enabled",
                        subtitleOff = "BLE mdoc peripheral server data retrieval disabled",
                        isChecked = blePeripheralServerDataTransferEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setBlePeripheralServerDataTransferEnabled(checked)
                            blePeripheralServerDataTransferEnabled.value = checked
                        }
                    )
                    SettingToggle(
                        title = "Wifi Aware data transfer",
                        subtitleOn = "Wifi Aware data transfer enabled",
                        subtitleOff = "Wifi Aware data transfer disabled",
                        isChecked = wifiAwareDataTransferEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setWifiAwareDataTransferEnabled(checked)
                            wifiAwareDataTransferEnabled.value = checked
                        }
                    )
                    SettingToggle(
                        title = "NFC data transfer",
                        subtitleOn = "NFC data transfer enabled",
                        subtitleOff = "NFC data transfer disabled",
                        isChecked = nfcDataTransferEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setNfcDataTransferEnabled(checked)
                            nfcDataTransferEnabled.value = checked
                        }
                    )
                    SettingToggle(
                        title = "TCP data transfer (proprietary)",
                        subtitleOn = "TCP data transfer enabled",
                        subtitleOff = "TCP data transfer disabled",
                        isChecked = tcpDataTransferEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setTcpDataTransferEnabled(checked)
                            tcpDataTransferEnabled.value = checked
                        }
                    )
                    SettingToggle(
                        title = "UDP data transfer (proprietary)",
                        subtitleOn = "UDP data transfer enabled",
                        subtitleOff = "UDP data transfer disabled",
                        isChecked = udpDataTransferEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setUdpDataTransferEnabled(checked)
                            udpDataTransferEnabled.value = checked
                        }
                    )
                    SettingSectionTitle(title = "Options")
                    SettingToggle(
                        title = "Use BLE L2CAP if available",
                        subtitleOn = "BLE L2CAP enabled",
                        subtitleOff = "BLE L2CAP disabled",
                        isChecked = l2capEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setL2CapEnabled(checked)
                            l2capEnabled.value = checked
                        }
                    )
                    SettingToggle(
                        title = "Experimental conveyance of L2CAP PSM",
                        subtitleOn = "Experimental PSM Conveyance enabled",
                        subtitleOff = "Experimental PSM Conveyance disabled",
                        isChecked = experimentalPsmEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setExperimentalPsmEnabled(checked)
                            experimentalPsmEnabled.value = checked
                        }
                    )
                    SettingSectionTitle(title = "Logging")
                    SettingToggle(
                        title = "Show Debug Messages",
                        subtitleOn = "Debug messages enabled",
                        subtitleOff = "Debug messages disabled",
                        isChecked = debugEnabled.value,
                        onCheckedChange = { checked ->
                            transferHelper.setDebugEnabled(checked)
                            debugEnabled.value = checked
                            Logger.isDebugEnabled = checked
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun SettingSectionTitle(
    modifier: Modifier = Modifier,
    title: String
) {
    Column(modifier = modifier) {
        Text(
            modifier = Modifier.fillMaxWidth(),
            text = title,
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
private fun SettingToggle(
    modifier: Modifier = Modifier,
    title: String,
    subtitleOn: String,
    subtitleOff: String,
    isChecked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true
) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            val subtitle = if (isChecked) subtitleOn else subtitleOff
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
        Switch(
            checked = isChecked,
            enabled = enabled,
            onCheckedChange = onCheckedChange
        )
    }
}
