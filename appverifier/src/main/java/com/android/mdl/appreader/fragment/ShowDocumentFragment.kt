package com.android.mdl.appreader.fragment

import android.content.res.Resources
import android.graphics.BitmapFactory
import android.icu.text.SimpleDateFormat
import android.icu.util.GregorianCalendar
import android.icu.util.TimeZone
import android.os.Bundle
import android.text.Html
import android.util.TypedValue
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.annotation.AttrRes
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.android.identity.android.mdoc.document.DataElement
import com.android.identity.android.mdoc.document.Document
import com.android.identity.android.mdoc.document.Namespace
import com.android.identity.android.mdoc.document.DocumentType
import com.android.identity.internal.Util
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.securearea.SecureArea
import com.android.mdl.appreader.R
import com.android.mdl.appreader.databinding.FragmentShowDocumentBinding
import com.android.mdl.appreader.issuerauth.SimpleIssuerTrustStore
import com.android.mdl.appreader.transfer.TransferManager
import com.android.mdl.appreader.util.FormatUtil
import com.android.mdl.appreader.util.KeysAndCertificates
import com.android.mdl.appreader.util.TransferStatus
import com.android.mdl.appreader.util.logDebug
import java.security.MessageDigest

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class ShowDocumentFragment : Fragment() {

    private var _binding: FragmentShowDocumentBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!
    private var portraitBytes: ByteArray? = null
    private var signatureBytes: ByteArray? = null
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
            logDebug("Showing portrait " + pb.size + " bytes")
            binding.ivPortrait.setImageBitmap(
                BitmapFactory.decodeByteArray(portraitBytes, 0, pb.size)
            )
            binding.ivPortrait.visibility = View.VISIBLE
        }

        signatureBytes?.let { signature ->
            logDebug("Showing signature " + signature.size + " bytes")
            binding.ivSignature.setImageBitmap(
                BitmapFactory.decodeByteArray(signatureBytes, 0, signature.size)
            )
            binding.ivSignature.visibility = View.VISIBLE
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
        transferManager.getTransferStatus().observe(viewLifecycleOwner) {
            when (it) {
                TransferStatus.ENGAGED -> {
                    logDebug("Device engagement received.")
                }

                TransferStatus.CONNECTED -> {
                    logDebug("Device connected received.")
                }

                TransferStatus.RESPONSE -> {
                    logDebug("Device response received.")
                }

                TransferStatus.DISCONNECTED -> {
                    logDebug("Device disconnected received.")
                    hideButtons()
                }

                TransferStatus.ERROR -> {
                    Toast.makeText(
                        requireContext(), "Error with the connection.",
                        Toast.LENGTH_SHORT
                    ).show()
                    transferManager.disconnect()
                    hideButtons()
                }
                else -> {}
            }
        }
    }

    private fun hideButtons() {
        binding.btOk.visibility = View.VISIBLE
        binding.btCloseConnection.visibility = View.GONE
        binding.btCloseTransportSpecific.visibility = View.GONE
        binding.btCloseTerminationMessage.visibility = View.GONE
        binding.btNewRequest.visibility = View.GONE
    }

    private fun curveNameFor(ecCurve: Int): String {
        return when (ecCurve) {
            SecureArea.EC_CURVE_P256 -> "P-256"
            SecureArea.EC_CURVE_P384 -> "P-384"
            SecureArea.EC_CURVE_P521 -> "P-521"
            SecureArea.EC_CURVE_BRAINPOOLP256R1 -> "BrainpoolP256R1"
            SecureArea.EC_CURVE_BRAINPOOLP320R1 -> "BrainpoolP320R1"
            SecureArea.EC_CURVE_BRAINPOOLP384R1 -> "BrainpoolP384R1"
            SecureArea.EC_CURVE_BRAINPOOLP512R1 -> "BrainpoolP512R1"
            SecureArea.EC_CURVE_ED25519 -> "Ed25519"
            SecureArea.EC_CURVE_X25519 -> "X25519"
            SecureArea.EC_CURVE_ED448 -> "Ed448"
            SecureArea.EC_CURVE_X448 -> "X448"
            else -> throw IllegalArgumentException("Unknown curve $ecCurve")
        }
    }

    private fun formatTextResult(documents: Collection<DeviceResponseParser.Document>): String {
        // Create the trustManager to validate the DS Certificate against the list of known
        // certificates in the app
        val simpleIssuerTrustStore =
            SimpleIssuerTrustStore(KeysAndCertificates.getTrustedIssuerCertificates(requireContext()))

        val sb = StringBuffer()

        for (doc in documents) {
            if (!checkPortraitPresenceIfRequired(doc)) {
                // Warn if portrait isn't included in the response.
                sb.append("<h3>WARNING: <font color=\"red\">No portrait image provided "
                        + "for ${doc.docType}.</font></h3><br>")
                sb.append("<i>This means it's not possible to verify the presenter is the authorized "
                        + "holder. Be careful doing any business transactions or inquiries until "
                        + "proper identification is confirmed.</i><br>")
                sb.append("<br>")
            }
        }

        sb.append("Number of documents returned: <b>${documents.size}</b><br>")
        sb.append("Address: <b>" + transferManager.mdocConnectionMethod + "</b><br>")
        sb.append("Session encryption curve: <b>" + curveNameFor(transferManager.getMdocSessionEncryptionCurve()) + "</b><br>")
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
            // Use the issuer certificate chain if we could not build the certificate trust path
            val certChain = if (certPath?.isNotEmpty() == true) {
                certPath
            } else {
                doc.issuerCertificateChain.toList()
            }

            val issuerItems = certChain.last().issuerX500Principal.name.split(",")
            var cnFound = false
            val commonName = StringBuffer()
            for (issuerItem in issuerItems) {
                when {
                    issuerItem.contains("CN=") -> {
                        val (key, value) = issuerItem.split("=", limit = 2)
                        commonName.append(value)
                        cnFound = true
                    }
                    // Common Name value with ',' symbols would be treated as set of items
                    // Append all parts of CN field if any before next issuer item
                    cnFound && !issuerItem.contains("=") -> commonName.append(", $issuerItem")
                    // Ignore any next issuer items only after we've collected required
                    cnFound -> break
                }
            }

            sb.append("${getFormattedCheck(isDSTrusted)}Issuer’s DS Key Recognized: ($commonName)<br>")
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
            sb.append("${getFormattedCheck(true)}Curve: <b>${curveNameFor(Util.getCurve(doc.deviceKey))}</b><br>")
            val deviceKeySha1 = FormatUtil.encodeToString(
                MessageDigest.getInstance("SHA-1").digest(doc.deviceKey.encoded)
            )
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
                    if (isPortraitElement(ns, elem)) {
                        valueStr = String.format("(%d bytes, shown above)", value.size)
                        portraitBytes = doc.getIssuerEntryByteString(ns, elem)
                    } else if (isElement(ns, elem, Document.Micov.Element.FACIAL_IMAGE)) {
                        valueStr = String.format("(%d bytes, shown above)", value.size)
                        portraitBytes = doc.getIssuerEntryByteString(ns, elem)
                    } else if (doc.docType == DocumentType.MDL.value && ns == Namespace.MDL.value && elem == "extra") {
                        valueStr = String.format("%d bytes extra data", value.size)
                    } else if (isElement(ns, elem, Document.Mdl.Element.SIGNATURE_USUAL_MARK)) {
                        valueStr = String.format("(%d bytes, shown below)", value.size)
                        signatureBytes = doc.getIssuerEntryByteString(ns, elem)
                    } else if (isElement(ns, elem, Document.EuPid.Element.BIOMETRIC_TEMPLATE_FINGER)) {
                        valueStr = String.format("%d bytes", value.size)
                    } else {
                        valueStr = FormatUtil.cborPrettyPrint(value)
                    }
                    sb.append("${getFormattedCheck(doc.getIssuerEntryDigestMatch(ns, elem))}<b>$elem</b> -> $valueStr<br>")
                }
                sb.append("</p><br>")
            }
        }
        return sb.toString()
    }


    private fun isElement(namespace: String?,
                          entryName: String?,
                          candidate: DataElement
    ): Boolean{
        return candidate.nameSpace.value == namespace && candidate.elementName == entryName
    }

    private fun isPortraitElement(
        namespace: String?,
        entryName: String?
    ): Boolean {
        return isElement(namespace, entryName, Document.Mdl.Element.PORTRAIT) ||
                isElement(namespace, entryName, Document.EuPid.Element.PORTRAIT)
    }

    // ISO/IEC 18013-5 requires the portrait image to be shared if the portrait was requested and if any other data element is released
    private fun checkPortraitPresenceIfRequired(document: DeviceResponseParser.Document): Boolean {
        document.issuerNamespaces.forEach { ns ->
            val portraitApplicable = listOf(Namespace.MDL.value, Namespace.EUPID.value).contains(ns)
            if (portraitApplicable) {
                val entries = document.getIssuerEntryNames(ns)
                val isPortraitMandatory = entries.isNotEmpty()
                val isPortraitMissing = !entries.contains("portrait")
                // check if other data elements are released but portrait is not present
                if (isPortraitMandatory && isPortraitMissing) {
                    return false
                }
            }
        }
        return true
    }

    private fun Resources.Theme.attr(@AttrRes attribute: Int): TypedValue {
        val typedValue = TypedValue()
        if (!resolveAttribute(attribute, typedValue, true)) {
            throw IllegalArgumentException("Failed to resolve attribute: $attribute")
        }
        return typedValue
    }

    private fun getFormattedCheck(authenticated: Boolean) = if (authenticated) {
        "<font color=green>&#x2714;</font> "
    } else {
        "<font color=red>&#x274C;</font> "
    }

    private var callback = object : OnBackPressedCallback(true /* enabled by default */) {
        override fun handleOnBackPressed() {
            TransferManager.getInstance(requireContext()).disconnect()
            findNavController().navigate(R.id.action_ShowDocument_to_RequestOptions)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}