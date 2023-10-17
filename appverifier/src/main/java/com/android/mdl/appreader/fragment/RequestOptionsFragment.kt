package com.android.mdl.appreader.fragment

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.nfc.NfcAdapter
import android.os.Bundle
import android.os.ResultReceiver
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.core.content.ContextCompat.checkSelfPermission
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.navigation.NavDirections
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.android.mdl.appreader.document.RequestDocument
import com.android.mdl.appreader.document.RequestDocumentList
import com.android.mdl.appreader.home.HomeScreen
import com.android.mdl.appreader.home.CreateRequestViewModel
import com.android.mdl.appreader.home.RequestingDocumentState
import com.android.mdl.appreader.theme.ReaderAppTheme
import com.android.mdl.appreader.transfer.TransferManager
import com.android.mdl.appreader.util.TransferStatus
import com.android.mdl.appreader.util.logDebug
import com.google.android.gms.identitycredentials.CredentialOption
import com.google.android.gms.identitycredentials.GetCredentialRequest
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import com.google.android.gms.identitycredentials.IntentHelper
import java.security.SecureRandom

class RequestOptionsFragment() : Fragment() {

    private val createRequestViewModel: CreateRequestViewModel by activityViewModels()
    private val args: RequestOptionsFragmentArgs by navArgs()
    private val appPermissions: List<String> get() {
        val permissions = mutableListOf<String>()
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            permissions.add(Manifest.permission.BLUETOOTH_ADVERTISE)
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
        }
        return permissions
    }

    private val permissionsLauncher = registerForActivityResult(RequestMultiplePermissions()) { permissions ->
        permissions.entries.forEach { permission ->
            logDebug("permissionsLauncher ${permission.key} = ${permission.value}")
            if (!permission.value && !shouldShowRequestPermissionRationale(permission.key)) {
                openSettings()
                return@registerForActivityResult
            }
        }
    }

    private lateinit var transferManager: TransferManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return ComposeView(requireContext()).apply {
            setContent {
                ReaderAppTheme {
                    val state by createRequestViewModel.state.collectAsState()
                    HomeScreen(
                        modifier = Modifier.fillMaxSize(),
                        state = state,
                        onSelectionUpdated = createRequestViewModel::onRequestUpdate,
                        onRequestConfirm = { onRequestConfirmed(it.isCustomMdlRequest) },
                        onRequestQRCodePreview = { navigateToQRCodeScan(it.isCustomMdlRequest) },
                        onRequestViaCredman = {onRequestViaCredman(it)}
                    )
                }
            }
        }
    }


    private fun onRequestViaCredman(state: RequestingDocumentState) {
        val client = IdentityCredentialManager.Companion.getClient(this.requireContext())
        val nonce = ByteArray(16)
        SecureRandom().nextBytes(nonce)
        val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP or Base64.URL_SAFE)
        val requestIdentityKeyPair = Util.createEphemeralKeyPair(SecureArea.EC_CURVE_P256)
        val requesterIdentityBase64 = Base64.encodeToString(Util.publicKeyToUncompressed(requestIdentityKeyPair.public), Base64.NO_WRAP or Base64.URL_SAFE)
        val requestJson = (
                "{\n" +
                "  \"providers\": [\n" +
                "    {\n" +
                "      \"responseFormat\": \"mdoc\",\n" +
                "      \"selector\": {\n" +
                "        \"fields\": [\n" +
                "          {\n" +
                "            \"name\": \"doctype\",\n" +
                "            \"equal\": \"org.iso.18013.5.1.mDL\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.portrait\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.family_name\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.given_name\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.document_number\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.expiry_date\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.issue_date\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.age_over_18\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.aamva.DHS_compliance\"\n" +
                "          },\n" +
                "          {\n" +
                "            \"name\": \"org.iso.18013.5.1.aamva.EDL_credential\"\n" +
                "          }\n" +
                "        ]\n" +
                "      },\n" +
                "      \"params\": {\n" +
                "        \"nonce\": \"$nonceBase64\",\n" +
                "        \"requesterIdentity\": \"$requesterIdentityBase64\"\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}")
        val option = CredentialOption(
            type = "com.credman.IdentityCredential",
            credentialRetrievalData = Bundle(),
            candidateQueryData = Bundle(),
            requestMatcher = requestJson,
        )
        client.getCredential(GetCredentialRequest(
            credentialOptions = listOf(option),
            data = Bundle(),
            origin = null,
            resultReceiver = object: ResultReceiver(null) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    super.onReceiveResult(resultCode, resultData)
                    Log.i("TAG", "Got a result $resultCode $resultData")

                    val response = IntentHelper.extractGetCredentialResponse(resultCode, resultData!!)
                    val identityToken = Base64.decode(
                        String(response.credential.data.getByteArray("identityToken")!!),
                        Base64.NO_WRAP or Base64.URL_SAFE)
                    //Logger.dCbor("TAG", "identityToken", identityToken!!)

                    val bundle = Bundle()
                    bundle.putByteArray("identityToken", identityToken)
                    bundle.putByteArray("nonce", nonce)
                    findNavController().navigate(RequestOptionsFragmentDirections.toShowDeviceResponse(
                        bundle, requestIdentityKeyPair))
                }
            }
        )).addOnSuccessListener {result ->
            startIntentSenderForResult(result.pendingIntent.intentSender, 777, null, 0, 0, 0, null)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        transferManager = TransferManager.getInstance(requireContext())
        if (!args.keepConnection) {
            // Always call to cancel any connection that could be on progress
            transferManager.disconnect()
        }
        transferManager.initVerificationHelper()
        observeTransferManager()
    }

    private fun observeTransferManager() {
        transferManager.getTransferStatus().observe(viewLifecycleOwner) {
            when (it) {
                TransferStatus.ENGAGED -> {
                    logDebug("Device engagement received")
                    onDeviceEngagementReceived()
                }

                TransferStatus.CONNECTED -> {
                    logDebug("Device connected")
                    Toast.makeText(
                        requireContext(), "Error invalid callback connected",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                TransferStatus.RESPONSE -> {
                    logDebug("Device response received")
                    Toast.makeText(
                        requireContext(), "Error invalid callback response",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                TransferStatus.DISCONNECTED -> {
                    logDebug("Device disconnected")
                    Toast.makeText(
                        requireContext(), "Device disconnected",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                TransferStatus.ERROR -> {
                    logDebug("Error received")
                    Toast.makeText(
                        requireContext(), "Error connecting to holder",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                else -> {}
            }
        }
    }

    private fun onDeviceEngagementReceived() {
        val requestedDocuments = calcRequestDocumentList()
        val destination = if (transferManager.availableMdocConnectionMethods?.size == 1) {
            RequestOptionsFragmentDirections.toTransfer(requestedDocuments)
        } else {
            RequestOptionsFragmentDirections.toSelectTransport(requestedDocuments)
        }
        findNavController().navigate(destination)
    }

    override fun onResume() {
        super.onResume()
        checkRequiredPermissions()
        transferManager.setNdefDeviceEngagement(
            NfcAdapter.getDefaultAdapter(requireContext()),
            requireActivity()
        )
    }

    private fun checkRequiredPermissions() {
        val permissionsNeeded = appPermissions.filter { permission ->
            checkSelfPermission(requireContext(), permission) != PackageManager.PERMISSION_GRANTED
        }
        if (permissionsNeeded.isNotEmpty()) {
            permissionsLauncher.launch(permissionsNeeded.toTypedArray())
        }
    }

    private fun openSettings() {
        val intent = Intent()
        intent.action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS
        intent.data = Uri.fromParts("package", requireContext().packageName, null)
        startActivity(intent)
    }

    private fun onRequestConfirmed(isCustomMdlRequest: Boolean) {
        if (isCustomMdlRequest) {
            val destination = getCustomMdlDestination()
            findNavController().navigate(destination)
        }
    }

    private fun navigateToQRCodeScan(isCustomMdlRequest: Boolean) {
        val documentList = calcRequestDocumentList()
        val destination = if (isCustomMdlRequest) {
            getCustomMdlDestination()
        } else {
            if (args.keepConnection) {
                RequestOptionsFragmentDirections.toTransfer(documentList, true)
            } else {
                RequestOptionsFragmentDirections.toScanDeviceEngagement(documentList)
            }
        }
        findNavController().navigate(destination)
    }

    private fun getCustomMdlDestination():NavDirections {
        val requestDocumentList = calcRequestDocumentList()
        val mdl = requestDocumentList.getAll().first { it.docType == RequestDocument.MDL_DOCTYPE }
        return RequestOptionsFragmentDirections.toRequestCustom(
            mdl,
            requestDocumentList,
            args.keepConnection
        )
    }

    private fun calcRequestDocumentList(): RequestDocumentList {
        // TODO: get intent to retain from user
        val intentToRetain = false
        return createRequestViewModel.calculateRequestDocumentList(intentToRetain)
    }
}