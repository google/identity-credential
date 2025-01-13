package com.android.identity.testapp.ui

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import com.android.identity.appsupport.ui.consent.ConsentModalBottomSheet
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.request.Requester
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborMap
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509Cert
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.mdoc.request.DeviceRequestGenerator
import com.android.identity.mdoc.request.DeviceRequestParser
import com.android.identity.mdoc.util.toMdocRequest
import com.android.identity.trustmanagement.TrustPoint
import identitycredential.samples.testapp.generated.resources.Res
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.ExperimentalResourceApi

private const val IACA_CERT_PEM =
    """
-----BEGIN CERTIFICATE-----
MIICujCCAj+gAwIBAgIQWlUtc8+HqDS3PvCqXIlyYDAKBggqhkjOPQQDAzA5MSowKAYDVQQDDCFP
V0YgSWRlbnRpdHkgQ3JlZGVudGlhbCBURVNUIElBQ0ExCzAJBgNVBAYTAlpaMB4XDTI0MDkxNzE2
NTEzN1oXDTI5MDkxNzE2NTEzN1owOTEqMCgGA1UEAwwhT1dGIElkZW50aXR5IENyZWRlbnRpYWwg
VEVTVCBJQUNBMQswCQYDVQQGEwJaWjB2MBAGByqGSM49AgEGBSuBBAAiA2IABJUHWyr1+ZlNvYEv
sR/1y2uYUkUczBqXTeTwiyRyiEGFFnZ0UR+gNKC4grdCP4F/dA+TWTduy2NlRmog5IByPSdwlvfW
B2f+Tf+MdbgZM+1+ukeaCgDhT/ZwgCoTNgvjyKOCAQowggEGMB0GA1UdDgQWBBQzCQV8RylodOk8
Yq6AwLDQhC7fUDAfBgNVHSMEGDAWgBQzCQV8RylodOk8Yq6AwLDQhC7fUDAOBgNVHQ8BAf8EBAMC
AQYwTAYDVR0SBEUwQ4ZBaHR0cHM6Ly9naXRodWIuY29tL29wZW53YWxsZXQtZm91bmRhdGlvbi1s
YWJzL2lkZW50aXR5LWNyZWRlbnRpYWwwEgYDVR0TAQH/BAgwBgEB/wIBADBSBgNVHR8ESzBJMEeg
RaBDhkFodHRwczovL2dpdGh1Yi5jb20vb3BlbndhbGxldC1mb3VuZGF0aW9uLWxhYnMvaWRlbnRp
dHktY3JlZGVudGlhbDAKBggqhkjOPQQDAwNpADBmAjEAil9jZ+deFSg1/ESWDEuA3gSU43XCO2t4
MirhUlQqSRYlOVBlD0sel7tyuiSPxEldAjEA1eTa/5yCZ67jjg6f2gbbJ8ZzMbff+DlHy77+wXIS
b35NiZ8FdVHgC2ut4fDQTRN4
-----END CERTIFICATE-----        
    """

@OptIn(ExperimentalMaterial3Api::class, ExperimentalResourceApi::class)
@Composable
fun ConsentModalBottomSheetScreen(
    mdlSampleRequest: String,
    verifierType: VerifierType,
    showToast: (message: String) -> Unit,
    onSheetConfirmed: () -> Unit,
    onSheetDismissed: () -> Unit,
) {
    val scope = rememberCoroutineScope()

    // TODO: use sheetGesturesEnabled=false when available - see
    //  https://issuetracker.google.com/issues/288211587 for details
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true
    )

    val request = remember {
        val request = DrivingLicense.getDocumentType().cannedRequests.find { it.id == mdlSampleRequest }!!
        val namespacesToRequest = mutableMapOf<String, Map<String, Boolean>>()
        for (ns in request.mdocRequest!!.namespacesToRequest) {
            val dataElementsToRequest = mutableMapOf<String, Boolean>()
            for ((de, intentToRetain) in ns.dataElementsToRequest) {
                dataElementsToRequest[de.attribute.identifier] = intentToRetain
            }
            namespacesToRequest[ns.namespace] = dataElementsToRequest
        }
        val encodedSessionTranscript = Cbor.encode(CborMap.builder().put("doesn't", "matter").end().build())
        val encodedDeviceRequest = DeviceRequestGenerator(encodedSessionTranscript)
            .addDocumentRequest(
                request.mdocRequest!!.docType,
                namespacesToRequest,
                null,
                null,
                Algorithm.UNSET,
                null
            ).generate()
        val deviceRequest = DeviceRequestParser(encodedDeviceRequest, encodedSessionTranscript)
            .parse()

        val docTypeRepo = DocumentTypeRepository()
        docTypeRepo.addDocumentType(DrivingLicense.getDocumentType())
        deviceRequest.docRequests[0].toMdocRequest(
            documentTypeRepository = docTypeRepo,
            mdocCredential = null
        )
    }

    var cardArt by remember {
        mutableStateOf(ByteArray(0))
    }
    var relyingPartyDisplayIcon by remember {
        mutableStateOf(ByteArray(0))
    }
    LaunchedEffect(Unit) {
        cardArt = Res.readBytes("files/utopia_driving_license_card_art.png")
        relyingPartyDisplayIcon = Res.readBytes("files/utopia-brewery.png")
        sheetState.show()
    }

    val (requester, trustPoint) = when (verifierType) {
        VerifierType.KNOWN_VERIFIER -> {
            Pair(
                Requester(),
                TrustPoint(
                    certificate = X509Cert.fromPem(IACA_CERT_PEM),
                    displayName = "Utopia Brewery",
                    displayIcon = relyingPartyDisplayIcon
                )
            )
        }
        VerifierType.UNKNOWN_VERIFIER_PROXIMITY ->  {
            Pair(
                Requester(),
                null
            )
        }
        VerifierType.UNKNOWN_VERIFIER_WEBSITE ->  {
            Pair(
                Requester(websiteOrigin = "https://www.example.com"),
                null
            )
        }
    }

    if (sheetState.isVisible && cardArt.size > 0) {
        ConsentModalBottomSheet(
            sheetState = sheetState,
            request = request,
            ConsentDocument(
                name = "Erika's Driving License",
                cardArt = cardArt,
                description = "Driving License",
            ),
            trustPoint = trustPoint,
            onConfirm = {
                scope.launch {
                    sheetState.hide()
                    onSheetConfirmed()
                }
            },
            onCancel = {
                scope.launch {
                    sheetState.hide()
                    showToast("The sheet was dismissed")
                    onSheetDismissed()
                }
            }
        )
    }
}
