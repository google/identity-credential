package com.android.identity.appsupport.ui.certificateviewer

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.android.identity.appsupport.ui.certificateviewer.CertificateViewData.Companion.from
import com.android.identity.asn1.ASN1Integer
import com.android.identity.asn1.OID
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.X500Name
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import identitycredential.identity_appsupport.generated.resources.Res
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_accessibility_error_icon
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_accessibility_info_icon
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_common_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_country_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_expired
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_issued
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_locality_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_org_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_org_unit_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_other_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_pk_algorithm
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_pk_named_curve
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_pk_value
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_serial_number
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_state_name
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_type
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_k_version
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_no_certificates_in_chain
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_sub_basic_info
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_sub_extensions
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_sub_issuer
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_sub_public_key_info
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_sub_subject
import identitycredential.identity_appsupport.generated.resources.certificate_viewer_version_text
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview
import kotlin.time.Duration.Companion.hours

private val PAGER_INDICATOR_HEIGHT = 30.dp
private val PAGER_INDICATOR_PADDING = 8.dp

/**
 * Display X509CertChain or x509Cert, with corresponding list of additional warnings and infos.
 * Accepts one certificate type parameter only (more types will be added later).
 * Will throw if more than one certificate type passed.
 * Will trow if the passed list of infos or warnings size (bar null) not equal to the chain size.
 *
 * @param infos list of strings with information messages. If provided, the list must match the
 *     chain size and sequence with nulls where no info is needed.
 * @param warnings list of strings with warning messages. If provided, the list must match the
 *     chain size and sequence with nulls where no warning is needed.
 */
@Composable
fun CertificateViewer(
    x509CertChain: X509CertChain? = null,
    x509Cert: X509Cert? = null,
    infos: List<String>? = null,
    warnings: List<String>? = null
) {
    validateParameters(infos, warnings, x509CertChain, x509Cert)

    val certDataList =
        when {
            x509CertChain != null -> x509CertChain.certificates.map { from(it) }
            x509Cert != null -> listOf(from(x509Cert))
            // Add more cert types here.
            else -> null
        }

    Box(
        modifier = Modifier.fillMaxHeight()
    ) {
        if (certDataList.isNullOrEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    modifier = Modifier.padding(8.dp),
                    text = stringResource(Res.string.certificate_viewer_no_certificates_in_chain),
                    style = MaterialTheme.typography.titleLarge,
                    textAlign = TextAlign.Center
                )
            }
        } else {
            val listSize = certDataList.size
            val pagerState = rememberPagerState(pageCount = { listSize })

            Column(
                modifier = Modifier.then(
                    if (listSize > 1)
                        Modifier.padding(bottom = PAGER_INDICATOR_HEIGHT + PAGER_INDICATOR_PADDING)
                    else // No pager, no padding.
                        Modifier
                )
            ) {
                HorizontalPager(
                    state = pagerState,
                ) { page ->
                    Column {
                        val info = infos?.getOrNull(page)
                        val warning = warnings?.getOrNull(page)
                        CertificateView(
                            certDataList[page],
                            info,
                            warning
                        )
                    }
                }
            }

            if (listSize > 1) { // Don't show pager for single cert on the list.
                Row(
                    horizontalArrangement = Arrangement.Center,
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .wrapContentHeight()
                        .fillMaxWidth()
                        .height(PAGER_INDICATOR_HEIGHT)
                        .padding(PAGER_INDICATOR_PADDING),
                ) {
                    repeat(pagerState.pageCount) { iteration ->
                        val color =
                            if (pagerState.currentPage == iteration) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                                    .copy(alpha = .2f)
                            }
                        Box(
                            modifier = Modifier
                                .padding(2.dp)
                                .clip(CircleShape)
                                .background(color)
                                .size(8.dp)
                        )
                    }
                }
            }
        }
    }
}

/**
 * Display certificate page data.
 *
 * @param data certificate content displayed on the page.
 * @param info optional info card to display.
 * @param warning optional warning card to display.
 */
@Composable
private fun CertificateView(
    data: CertificateViewData,
    info: String?,
    warning: String?,
) {
    Column {
        val scrollState = rememberScrollState()
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(scrollState)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            info?.let { InfoCard(it) }
            warning?.let { WarningCard(it) }

            Subtitle(stringResource(Res.string.certificate_viewer_sub_basic_info))
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_type), data.type)
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_version),
                stringResource(Res.string.certificate_viewer_version_text, data.version))
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_serial_number),
                data.serialNumber)
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_issued), data.issued)
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_expired), data.expired)

            if (data.subject.isNotEmpty()) {
                Subtitle(stringResource(Res.string.certificate_viewer_sub_subject))
                data.subject.forEach { (key, value) ->
                    KeyValuePairLine(stringResource(resFromName(key)), value)
                }
            }

            if (data.issuer.isNotEmpty()) {
                Subtitle(stringResource(Res.string.certificate_viewer_sub_issuer))
                data.issuer.forEach { (key, value) ->
                    KeyValuePairLine(stringResource(resFromName(key)), value)
                }
            }

            Subtitle(stringResource(Res.string.certificate_viewer_sub_public_key_info))
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_pk_algorithm),
                data.pkAlgorithm)
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_pk_named_curve),
                data.pkNamedCurve)
            KeyValuePairLine(stringResource(Res.string.certificate_viewer_k_pk_value),
                data.pkValue)

            // TODO: Extensions are going to need a bit more work, like conveying criticality and
            //  pretty-printing well-known extensions.
            if (data.extensions.isNotEmpty()) {
                Subtitle(stringResource(Res.string.certificate_viewer_sub_extensions))
                data.extensions.forEach { (key, value) -> KeyValuePairLine(key, value) }
            }
        }
    }
}

@Composable
private fun Subtitle(text: String) {
    Text(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface
    )
}

@Composable
private fun KeyValuePairLine(
    key: String,
    valueText: String
) {
    if (valueText.isEmpty()) {
        return
    }

    Column(
        Modifier.fillMaxWidth()
            .padding(horizontal = 8.dp)
    ) {
        Text(
            text = key,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            text = valueText,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
private fun InfoCard(text: String) {
    Column(
        modifier = Modifier
            .padding(8.dp)
            .fillMaxWidth()
            .clip(shape = RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.primaryContainer),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
        ) {
            Icon(
                modifier = Modifier.padding(end = 16.dp),
                imageVector = Icons.Filled.Info,
                contentDescription = stringResource(Res.string.certificate_viewer_accessibility_info_icon),
                tint = MaterialTheme.colorScheme.onPrimaryContainer
            )

            Text(
                text = text,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

@Composable
private fun WarningCard(text: String) {
    Column(
        modifier = Modifier
            .padding(8.dp)
            .fillMaxWidth()
            .clip(shape = RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.errorContainer),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
        ) {
            Icon(
                modifier = Modifier.padding(end = 16.dp),
                imageVector = Icons.Filled.Warning,
                contentDescription = stringResource(Res.string.certificate_viewer_accessibility_error_icon),
                tint = MaterialTheme.colorScheme.onErrorContainer
            )

            Text(
                text = text,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
        }
    }
}

@Preview
@Composable
private fun PreviewCertificate() {
    val key = Crypto.createEcPrivateKey(EcCurve.P256)
    val now = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
    val x509 = X509Cert.Builder(
        publicKey = key.publicKey,
        signingKey = key,
        signatureAlgorithm = key.curve.defaultSigningAlgorithm,
        serialNumber = ASN1Integer(1),
        subject = X500Name.fromName("CN=Foobar1"),
        issuer = X500Name.fromName("CN=Foobar2"),
        validFrom = now - 1.hours,
        validUntil = now + 1.hours
    )
        .includeSubjectKeyIdentifier()
        .includeAuthorityKeyIdentifierAsSubjectKeyIdentifier()
        .build()

    CertificateView(from(x509), null, null)
}

/**
 * Verify supported use cases, throw with detailed message on failure. Parameters are passed in
 * partially reversed mode to make adding new certificate objets easier (to the list end).
 */
private fun validateParameters(
    infos: List<String>?,
    warnings: List<String>?,
    x509CertChain: X509CertChain?,
    x509Cert: X509Cert?,
    // Add more types as needed here.
) {
    val certificatesPassed = listOfNotNull(
        x509CertChain,
        x509Cert,
        // Add more types as needed here.
    )
    if (certificatesPassed.isEmpty()) {
        throw IllegalArgumentException("No certificates provided.")
    }
    if (certificatesPassed.size > 1) {
        throw IllegalArgumentException("Only one certificate object should be provided.")
    }

    // Test chain size to match warnings and infos sizes.
    if (x509CertChain != null) {
        val listSize = x509CertChain.certificates.size
        if ((infos != null && infos.size != listSize)
            || (warnings != null && warnings.size != listSize)) {
            val message = buildString {
                append("The list size of ")
                if (infos != null && infos.size != listSize) {
                    append("infos")
                    if (warnings != null && warnings.size != listSize) {
                        append(" and warnings")
                    }
                } else if (warnings != null && warnings.size != listSize) {
                    append("warnings")
                }
                append(" parameters provided, must be equal to the certificates chain size.")
            }
            throw IllegalArgumentException(message)
        }
    }
}

private fun resFromName(nameId: String): StringResource {
    val nMap = mapOf(
        OID.COMMON_NAME.oid to Res.string.certificate_viewer_k_common_name,
        OID.SERIAL_NUMBER.oid to Res.string.certificate_viewer_k_serial_number,
        OID.COUNTRY_NAME.oid to Res.string.certificate_viewer_k_country_name,
        OID.LOCALITY_NAME.oid to Res.string.certificate_viewer_k_locality_name,
        OID.STATE_OR_PROVINCE_NAME.oid to Res.string.certificate_viewer_k_state_name,
        OID.ORGANIZATION_NAME.oid to Res.string.certificate_viewer_k_org_name,
        OID.ORGANIZATIONAL_UNIT_NAME.oid to Res.string.certificate_viewer_k_org_unit_name,
        // TODO: Add support for other OIDs from RFC 5280 Annex A, as needed.
    )
    return nMap[nameId] ?: Res.string.certificate_viewer_k_other_name
}

