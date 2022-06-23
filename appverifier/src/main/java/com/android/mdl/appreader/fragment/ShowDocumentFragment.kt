package com.android.mdl.appreader.fragment

import android.graphics.BitmapFactory
import android.icu.text.SimpleDateFormat
import android.icu.util.GregorianCalendar
import android.icu.util.TimeZone
import android.os.Bundle
import android.text.Html
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.android.identity.DeviceResponseParser
import com.android.mdl.appreader.R
import com.android.mdl.appreader.databinding.FragmentShowDocumentBinding
import com.android.mdl.appreader.issuerauth.SimpleIssuerTrustStore
import com.android.mdl.appreader.transfer.TransferManager
import com.android.mdl.appreader.util.FormatUtil
import com.android.mdl.appreader.util.KeysAndCertificates
import com.android.mdl.appreader.util.TransferStatus
import org.jetbrains.anko.attr
import java.security.MessageDigest


/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class ShowDocumentFragment : Fragment() {

    companion object {
        private const val LOG_TAG = "ShowDocumentFragment"
        private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
        private const val MICOV_DOCTYPE = "org.micov.1"
        private const val MDL_NAMESPACE = "org.iso.18013.5.1"
        private const val MICOV_ATT_NAMESPACE = "org.micov.attestation.1"
    }

    private var _binding: FragmentShowDocumentBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!
    private var portraitBytes: ByteArray? = null
    private lateinit var transferManager: TransferManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentShowDocumentBinding.inflate(inflater, container, false)
        transferManager = TransferManager.getInstance(requireContext())
        requireActivity().onBackPressedDispatcher.addCallback(viewLifecycleOwner, callback)

        return binding.root

    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val documents = transferManager.getDeviceResponse().documents
        binding.tvResults.text =
            Html.fromHtml(formatTextResult(documents), Html.FROM_HTML_MODE_COMPACT)

        portraitBytes?.let { pb ->
            Log.d(LOG_TAG, "Showing portrait " + pb.size + " bytes")
            binding.ivPortrait.setImageBitmap(
                BitmapFactory.decodeByteArray(portraitBytes, 0, pb.size)
            )
            binding.ivPortrait.visibility = View.VISIBLE
        }


        binding.btOk.setOnClickListener {
            findNavController().navigate(R.id.action_ShowDocument_to_RequestOptions)
        }
        binding.btCloseConnection.setOnClickListener {
            transferManager.stopVerification(
                sendSessionTerminationMessage = false,
                useTransportSpecificSessionTermination = false
            )
            hideButtons()
        }
        binding.btCloseTransportSpecific.setOnClickListener {
            transferManager.stopVerification(
                sendSessionTerminationMessage = true,
                useTransportSpecificSessionTermination = true
            )
            hideButtons()
        }
        binding.btCloseTerminationMessage.setOnClickListener {
            transferManager.stopVerification(
                sendSessionTerminationMessage = true,
                useTransportSpecificSessionTermination = false
            )
            hideButtons()
        }
        binding.btNewRequest.setOnClickListener {
            findNavController().navigate(
                ShowDocumentFragmentDirections.actionShowDocumentToRequestOptions(true)
            )
        }
        transferManager.getTransferStatus().observe(viewLifecycleOwner, {
            when (it) {
                TransferStatus.ENGAGED -> {
                    Log.d(LOG_TAG, "Device engagement received.")
                }
                TransferStatus.CONNECTED -> {
                    Log.d(LOG_TAG, "Device connected received.")
                }
                TransferStatus.RESPONSE -> {
                    Log.d(LOG_TAG, "Device response received.")
                }
                TransferStatus.DISCONNECTED -> {
                    Log.d(LOG_TAG, "Device disconnected received.")
                    transferManager.stopVerification(
                        sendSessionTerminationMessage = false,
                        useTransportSpecificSessionTermination = false
                    )
                    hideButtons()
                }
                TransferStatus.ERROR -> {
                    Toast.makeText(
                        requireContext(), "Error with the connection.",
                        Toast.LENGTH_SHORT
                    ).show()
                    transferManager.stopVerification(
                        sendSessionTerminationMessage = false,
                        useTransportSpecificSessionTermination = false
                    )
                    hideButtons()
                }
            }
        })
    }

    private fun hideButtons() {
        binding.btOk.visibility = View.VISIBLE
        binding.btCloseConnection.visibility = View.GONE
        binding.btCloseTransportSpecific.visibility = View.GONE
        binding.btCloseTerminationMessage.visibility = View.GONE
        binding.btNewRequest.visibility = View.GONE
    }

    private fun formatTextResult(documents: Collection<DeviceResponseParser.Document>): String {
        // Create the trustManager to validate the DS Certificate against the list of known
        // certificates in the app
        val simpleIssuerTrustStore =
            SimpleIssuerTrustStore(KeysAndCertificates.getTrustedIssuerCertificates(requireContext()))

        val sb = StringBuffer()
        sb.append("Number of documents returned: <b>${documents.size}</b><br>")
        sb.append("Address: <b>" + transferManager.mdocAddress + "</b><br>")
        sb.append("<br>")
        for (doc in documents) {
            // Get primary color from theme to use in the HTML formatted document.
            val color = String.format(
                "#%06X",
                0xFFFFFF and requireContext().theme.attr(R.attr.colorPrimary).data
            )
            sb.append("<h3>Doctype: <font color=\"$color\">${doc.docType}</font></h3>")
            val certPath =
                simpleIssuerTrustStore.createCertificationTrustPath(doc.issuerCertificateChain.toList())
            val isDSTrusted = simpleIssuerTrustStore.validateCertificationTrustPath(certPath)
            var commonName = ""
            // Use the issuer certificate chain if we could not build the certificate trust path
            val certChain = if (certPath?.isNotEmpty() == true) {
                certPath
            } else {
                doc.issuerCertificateChain.toList()
            }

            certChain.last().issuerX500Principal.name.split(",").forEach { line ->
                val (key, value) = line.split("=", limit = 2)
                if (key == "CN") {
                    commonName = "($value)"
                }
            }
            sb.append("${getFormattedCheck(isDSTrusted)}Issuer’s DS Key Recognized: $commonName<br>")
            sb.append("${getFormattedCheck(doc.issuerSignedAuthenticated)}Issuer Signed Authenticated<br>")
            var macOrSignatureString = "MAC"
            if (doc.deviceSignedAuthenticatedViaSignature)
                macOrSignatureString = "ECDSA"
            sb.append("${getFormattedCheck(doc.deviceSignedAuthenticated)}Device Signed Authenticated (${macOrSignatureString})<br>")

            sb.append("<h6>MSO</h6>")

            val df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX")
            val calSigned = GregorianCalendar(TimeZone.getTimeZone("UTC"))
            val calValidFrom = GregorianCalendar(TimeZone.getTimeZone("UTC"))
            val calValidUntil = GregorianCalendar(TimeZone.getTimeZone("UTC"))
            calSigned.timeInMillis = doc.validityInfoSigned.toEpochMilli()
            calValidFrom.timeInMillis = doc.validityInfoValidFrom.toEpochMilli()
            calValidUntil.timeInMillis = doc.validityInfoValidUntil.toEpochMilli()
            sb.append("${getFormattedCheck(true)}Signed: ${df.format(calSigned)}<br>")
            sb.append("${getFormattedCheck(true)}Valid From: ${df.format(calValidFrom)}<br>")
            sb.append("${getFormattedCheck(true)}Valid Until: ${df.format(calValidUntil)}<br>")
            if (doc.validityInfoExpectedUpdate != null) {
                val calExpectedUpdate = GregorianCalendar(TimeZone.getTimeZone("UTC"))
                calExpectedUpdate.timeInMillis = doc.validityInfoExpectedUpdate!!.toEpochMilli()
                sb.append("${getFormattedCheck(true)}Expected Update: ${df.format(calExpectedUpdate)}<br>")
            }
            // TODO: show warning if MSO is valid for more than 30 days

            // Just show the SHA-1 of DeviceKey since all we're interested in here is whether
            // we saw the same key earlier.
            sb.append("<h6>DeviceKey</h6>")
            val deviceKeySha1 = FormatUtil.encodeToString(
                MessageDigest.getInstance("SHA-1").digest(doc.deviceKey.encoded))
            sb.append("${getFormattedCheck(true)}SHA-1: ${deviceKeySha1}<br>")
            // TODO: log DeviceKey's that we've seen and show warning if a DeviceKey is seen
            //  a second time. Also would want button in Settings page to clear the log.

            for (ns in doc.issuerNamespaces) {
                sb.append("<br>")
                sb.append("<h5>Namespace: $ns</h5>")
                sb.append("<p>")
                for (elem in doc.getIssuerEntryNames(ns)) {
                    val value: ByteArray = doc.getIssuerEntryData(ns, elem)
                    var valueStr: String
                    if (doc.docType == MDL_DOCTYPE && ns == MDL_NAMESPACE && elem == "portrait") {
                        valueStr = String.format("(%d bytes, shown above)", value.size)
                        portraitBytes = doc.getIssuerEntryByteString(ns, elem)
                    } else if (doc.docType == MICOV_DOCTYPE && ns == MICOV_ATT_NAMESPACE && elem == "fac") {
                        valueStr = String.format("(%d bytes, shown above)", value.size)
                        portraitBytes = doc.getIssuerEntryByteString(ns, elem)
                    } else if (doc.docType == MDL_DOCTYPE
                        && ns == MDL_NAMESPACE && elem == "extra"
                    ) {
                        valueStr = String.format("%d bytes extra data", value.size)
                    } else {
                        valueStr = FormatUtil.cborPrettyPrint(value)
                    }
                    sb.append(
                        "${
                            getFormattedCheck(doc.getIssuerEntryDigestMatch(ns, elem))
                        }<b>$elem</b> -> $valueStr<br>"
                    )
                }
                sb.append("</p><br>")
            }
        }
        return sb.toString()
    }

    private fun getFormattedCheck(authenticated: Boolean) = if (authenticated) {
        "<font color=green>&#x2714;</font> "
    } else {
        "<font color=red>&#x274C;</font> "
    }

    private var callback = object : OnBackPressedCallback(true /* enabled by default */) {
        override fun handleOnBackPressed() {
            TransferManager.getInstance(requireContext()).stopVerification(
                sendSessionTerminationMessage = true,
                useTransportSpecificSessionTermination = true
            )
            findNavController().navigate(R.id.action_ShowDocument_to_RequestOptions)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}