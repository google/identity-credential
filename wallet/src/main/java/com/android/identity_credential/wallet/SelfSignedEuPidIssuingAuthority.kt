package com.android.identity_credential.wallet

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.toDataItemDateTimeString
import com.android.identity.cbor.toDataItemFullDate
import com.android.identity.document.NameSpacedData
import com.android.identity.documenttype.DocumentType
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.issuance.DocumentConfiguration
import com.android.identity.issuance.DocumentPresentationFormat
import com.android.identity.issuance.IssuingAuthorityConfiguration
import com.android.identity.issuance.evidence.EvidenceResponse
import com.android.identity.issuance.evidence.EvidenceResponseIcaoNfcTunnelResult
import com.android.identity.issuance.evidence.EvidenceResponseIcaoPassiveAuthentication
import com.android.identity.issuance.evidence.EvidenceResponseMessage
import com.android.identity.issuance.evidence.EvidenceResponseQuestionMultipleChoice
import com.android.identity.issuance.simple.SimpleIcaoNfcTunnelDriver
import com.android.identity.issuance.simple.SimpleIssuingAuthorityProofingGraph
import com.android.identity.storage.StorageEngine
import com.android.identity_credential.mrtd.MrtdNfcData
import com.android.identity_credential.mrtd.MrtdNfcDataDecoder
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.plus
import kotlinx.datetime.toLocalDateTime
import java.io.ByteArrayOutputStream
import kotlin.time.Duration.Companion.days

class SelfSignedEuPidIssuingAuthority(
    application: WalletApplication,
    storageEngine: StorageEngine
) : SelfSignedMdocIssuingAuthority(application, storageEngine) {
    companion object {
        private const val EUPID_NAMESPACE = EUPersonalID.EUPID_NAMESPACE
        private const val EUPID_DOCTYPE = EUPersonalID.EUPID_DOCTYPE
    }

    override val docType: String = EUPID_DOCTYPE
    override lateinit var configuration: IssuingAuthorityConfiguration
    private val tosAssets: Map<String, ByteArray>;

    init {
        val baos = ByteArrayOutputStream()
        BitmapFactory.decodeResource(
            application.applicationContext.resources,
            R.drawable.utopia_pid_issuing_authority_logo
        ).compress(Bitmap.CompressFormat.PNG, 90, baos)
        val icon: ByteArray = baos.toByteArray()
        configuration = IssuingAuthorityConfiguration(
            identifier = "euPid_Utopia",
            issuingAuthorityName = resourceString(R.string.utopia_eu_pid_issuing_authority_name),
            issuingAuthorityLogo = icon,
            description = resourceString(R.string.utopia_eu_pid_issuing_authority_description),
            documentFormats = setOf(DocumentPresentationFormat.MDOC_MSO),
            pendingDocumentInformation = createDocumentConfiguration(null)
        )
        tosAssets = mapOf("utopia_logo.png" to resourceBytes(R.drawable.utopia_pid_issuing_authority_logo))
    }

    override fun getProofingGraphRoot(): SimpleIssuingAuthorityProofingGraph.Node {
        return SimpleIssuingAuthorityProofingGraph.create {
            message(
                "tos",
                resourceString(R.string.utopia_eu_pid_issuing_authority_tos),
                tosAssets,
                resourceString(R.string.utopia_eu_pid_issuing_authority_accept),
                resourceString(R.string.utopia_eu_pid_issuing_authority_reject),
            )
            choice(
                id = "path",
                message = resourceString(R.string.utopia_eu_pid_issuing_authority_hardcoded_or_derived),
                assets = mapOf(),
                acceptButtonText = "Continue"
            ) {
                on(id = "hardcoded", text = resourceString(R.string.utopia_eu_pid_issuing_authority_hardcoded_option)) {
                }
                on(id = "passport", text = resourceString(R.string.utopia_eu_pid_issuing_authority_passport_option)) {
                    icaoTunnel("tunnel", listOf(1, 2, 7)) {
                        whenChipAuthenticated {}
                        whenActiveAuthenticated {}
                        whenNotAuthenticated {}
                    }
                }
            }
            message(
                "message",
                resourceString(R.string.utopia_eu_pid_issuing_authority_application_finish),
                mapOf(),
                resourceString(R.string.utopia_eu_pid_issuing_authority_continue),
                null
            )
            requestNotificationPermission(
                "notificationPermission",
                permissionNotAvailableMessage = resourceString(R.string.permission_post_notifications_rationale_md),
                grantPermissionButtonText = resourceString(R.string.permission_post_notifications_grant_permission_button_text),
                continueWithoutPermissionButtonText = resourceString(R.string.permission_post_notifications_continue_without_permission_button_text),
                assets = mapOf()
            )
        }
    }

    override fun createNfcTunnelHandler(): SimpleIcaoNfcTunnelDriver {
        return NfcTunnelDriver()
    }

    override fun checkEvidence(collectedEvidence: Map<String, EvidenceResponse>): Boolean {
        return (collectedEvidence["tos"] as EvidenceResponseMessage).acknowledged
    }

    override fun generateDocumentConfiguration(collectedEvidence: Map<String, EvidenceResponse>): DocumentConfiguration {
        return createDocumentConfiguration(collectedEvidence)
    }

    private fun createDocumentConfiguration(collectedEvidence: Map<String, EvidenceResponse>?): DocumentConfiguration {
        val baos = ByteArrayOutputStream()
        BitmapFactory.decodeResource(
            application.applicationContext.resources, R.drawable.utopia_pid_card_art
        ).compress(Bitmap.CompressFormat.PNG, 90, baos)
        val cardArt: ByteArray = baos.toByteArray()

        if (collectedEvidence == null) {
            return DocumentConfiguration(
                resourceString(R.string.utopia_eu_pid_issuing_authority_pending_document_title),
                cardArt,
                EUPID_DOCTYPE,
                NameSpacedData.Builder().build()
            )
        }

        val staticData: NameSpacedData

        val now = Clock.System.now()
        val issueDate = now
        val expiryDate = now + 365.days * 5

        println("foo1 " + application)
        println("foo2 " + application.documentTypeRepository)
        println("foo3 " + EUPID_DOCTYPE)
        val credType = application.documentTypeRepository.getDocumentTypeForMdoc(EUPID_DOCTYPE)!!

        val path = (collectedEvidence["path"] as EvidenceResponseQuestionMultipleChoice).answerId
        if (path == "hardcoded") {
            staticData = getSampleData(credType).build()
        } else {
            val icaoPassiveData = collectedEvidence["passive"]
            val icaoTunnelData = collectedEvidence["tunnel"]
            val mrtdData = if (icaoTunnelData is EvidenceResponseIcaoNfcTunnelResult)
                MrtdNfcData(icaoTunnelData.dataGroups, icaoTunnelData.securityObject)
            else if (icaoPassiveData is EvidenceResponseIcaoPassiveAuthentication)
                MrtdNfcData(icaoPassiveData.dataGroups, icaoPassiveData.securityObject)
            else
                throw IllegalStateException("Should not happen")
            val decoder = MrtdNfcDataDecoder(application.cacheDir)
            val decoded = decoder.decode(mrtdData)
            val firstName = decoded.firstName
            val lastName = decoded.lastName
            val sex = when (decoded.gender) {
                "MALE" -> 1L
                "FEMALE" -> 2L
                else -> 0L
            }
            val timeZone = TimeZone.currentSystemDefault()
            val dateOfBirth = LocalDate.parse(input = decoded.dateOfBirth,
                format = LocalDate.Format {
                    // date of birth cannot be in future
                    yearTwoDigits(now.toLocalDateTime(timeZone).year - 99)
                    monthNumber()
                    dayOfMonth()
                })
            val dateOfBirthInstant = dateOfBirth.atStartOfDayIn(timeZone)
            // over 18/21 is calculated purely based on calendar date (not based on the birth time zone)
            val ageOver18 = now > dateOfBirthInstant.plus(18, DateTimeUnit.YEAR, timeZone)
            val ageOver21 = now > dateOfBirthInstant.plus(21, DateTimeUnit.YEAR, timeZone)

            // Make sure we set at least all the mandatory data elements
            staticData = NameSpacedData.Builder()
                .putEntryString(EUPID_NAMESPACE, "given_name", firstName)
                .putEntryString(EUPID_NAMESPACE, "family_name", lastName)
                .putEntry(EUPID_NAMESPACE, "birth_date",
                    Cbor.encode(dateOfBirth.toDataItemFullDate))
                .putEntryNumber(EUPID_NAMESPACE, "gender", sex)
                .putEntry(EUPID_NAMESPACE, "issuance_date",
                    Cbor.encode(issueDate.toDataItemDateTimeString))
                .putEntry(EUPID_NAMESPACE, "expiry_date",
                    Cbor.encode(expiryDate.toDataItemDateTimeString)
                )
                .putEntryString(EUPID_NAMESPACE, "issuing_authority",
                    resourceString(R.string.utopia_eu_pid_issuing_authority_name))
                .putEntryString(EUPID_NAMESPACE, "issuing_country",
                    "UT")
                .putEntryBoolean(EUPID_NAMESPACE, "age_over_18", ageOver18)
                .putEntryBoolean(EUPID_NAMESPACE, "age_over_21", ageOver21)
                .putEntryString(EUPID_NAMESPACE, "document_number", "1234567890")
                .putEntryString(EUPID_NAMESPACE, "administrative_number", "123456789")
                .build()
        }

        val firstName = staticData.getDataElementString(EUPID_NAMESPACE, "given_name")
        return DocumentConfiguration(
            resourceString(R.string.utopia_eu_pid_issuing_authority_document_title, firstName),
            cardArt,
            EUPID_DOCTYPE,
            staticData
        )
    }

    override fun developerModeRequestUpdate(currentConfiguration: DocumentConfiguration): DocumentConfiguration {
        // The update consists of just slapping an extra 0 at the end of `administrative_number`
        val newAdministrativeNumber = currentConfiguration.staticData
            .getDataElementString(EUPID_NAMESPACE, "administrative_number") + "0"

        val builder = NameSpacedData.Builder(currentConfiguration.staticData)
        builder.putEntryString(
            EUPID_NAMESPACE,
            "administrative_number",
            newAdministrativeNumber
        )

        return DocumentConfiguration(
            displayName = currentConfiguration.displayName,
            cardArt = currentConfiguration.cardArt,
            mdocDocType = currentConfiguration.mdocDocType,
            staticData = builder.build(),
        )
    }

    private fun getSampleData(documentType: DocumentType): NameSpacedData.Builder {
        val builder = NameSpacedData.Builder()
        for ((namespaceName, namespace) in documentType.mdocDocumentType!!.namespaces) {
            for ((dataElementName, dataElement) in namespace.dataElements) {
                if (dataElement.attribute.sampleValue != null) {
                    builder.putEntry(
                        namespaceName,
                        dataElementName,
                        Cbor.encode(dataElement.attribute.sampleValue!!)
                    )
                }
            }
        }
        return builder
    }
}