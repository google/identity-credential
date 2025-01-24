package com.android.identity.wallet.util

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import com.android.identity.android.direct_access.DirectAccess
import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.RawCbor
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.toDataItem
import com.android.identity.cose.Cose
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.X509Cert
import com.android.identity.crypto.X509CertChain
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.crypto.javaPublicKey
import com.android.identity.crypto.toEcPrivateKey
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.document.Document
import com.android.identity.document.DocumentUtil
import com.android.identity.document.NameSpacedData
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.wallet.HolderApp
import com.android.identity.wallet.document.DocumentInformation
import com.android.identity.wallet.document.KeysAndCertificates
import com.android.identity.wallet.selfsigned.ProvisionInfo
import com.android.identity.wallet.support.SecureAreaSupport
import com.android.identity.wallet.util.DocumentData.MICOV_DOCTYPE
import com.android.identity.wallet.util.DocumentData.MVR_DOCTYPE
import java.io.ByteArrayOutputStream
import java.time.Instant as JavaInstant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.random.Random
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.interfaces.ECPublicKey
import java.util.Arrays

class ProvisioningUtil private constructor(
    private val context: Context
) {

    val secureAreaRepository = SecureAreaRepository()
    val documentStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        HolderApp.createDocumentStore(context, secureAreaRepository)
    }

    fun provisionSelfSigned(
        nameSpacedData: NameSpacedData,
        provisionInfo: ProvisionInfo,
    ) {
        val document = documentStore.createDocument(provisionInfo.documentName())
        documentStore.addDocument(document)
        document.applicationData.setNameSpacedData("documentData", nameSpacedData)

        val authKeySecureArea: SecureArea = provisionInfo.currentSecureArea.secureArea

        // Store all settings for the document that are not SecureArea specific
        document.applicationData.setString(USER_VISIBLE_NAME, provisionInfo.docName)
        document.applicationData.setString(DOCUMENT_TYPE, provisionInfo.docType)
        document.applicationData.setString(DATE_PROVISIONED, dateTimeFormatter.format(ZonedDateTime.now()))
        document.applicationData.setNumber(CARD_ART, provisionInfo.docColor.toLong())
        document.applicationData.setBoolean(IS_SELF_SIGNED, true)
        document.applicationData.setNumber(MAX_USAGES_PER_KEY, provisionInfo.maxUseMso.toLong())
        document.applicationData.setNumber(VALIDITY_IN_DAYS, provisionInfo.validityInDays.toLong())
        document.applicationData.setNumber(MIN_VALIDITY_IN_DAYS, provisionInfo.minValidityInDays.toLong())
        document.applicationData.setNumber(LAST_TIME_USED, -1)
        document.applicationData.setString(AUTH_KEY_SECURE_AREA_IDENTIFIER, authKeySecureArea.identifier)
        document.applicationData.setNumber(NUM_CREDENTIALS, provisionInfo.numberMso.toLong())

        // Store settings for auth-key creation, these are all SecureArea-specific and we store
        // them in a single blob at AUTH_KEY_SETTINGS
        val support = SecureAreaSupport.getInstance(context, authKeySecureArea)
        document.applicationData.setData(
            AUTH_KEY_SETTINGS,
            support.createAuthKeySettingsConfiguration(provisionInfo.secureAreaSupportState))

        // Create initial batch of credentials
        if (provisionInfo.provisionDirectAccess) {
            val documentSlot = DirectAccess.allocateDocumentSlot()
            refreshDaCredentials(document, provisionInfo.docType, documentSlot)
        }

        refreshMdocCredentials(document, provisionInfo.docType)
    }

    private fun ProvisionInfo.documentName(): String {
        val regex = Regex("[^A-Za-z0-9 ]")
        return regex.replace(docName, "").replace(" ", "_").lowercase()
    }

    fun trackUsageTimestamp(document: Document) {
        val now = Clock.System.now()
        document.applicationData.setNumber(LAST_TIME_USED, now.toEpochMilliseconds())
    }

    fun refreshMdocCredentials(document: Document, docType: String) {
        val secureAreaIdentifier = document.applicationData.getString(AUTH_KEY_SECURE_AREA_IDENTIFIER)
        val minValidTimeDays = document.applicationData.getNumber(MIN_VALIDITY_IN_DAYS)
        val maxUsagesPerCred = document.applicationData.getNumber(MAX_USAGES_PER_KEY)
        val numCreds = document.applicationData.getNumber(NUM_CREDENTIALS)
        val validityInDays = document.applicationData.getNumber(VALIDITY_IN_DAYS).toInt()

        val now = Clock.System.now()
        val validFrom = now
        val validUntil = Instant.fromEpochMilliseconds(
            validFrom.toEpochMilliseconds() + validityInDays*86400*1000L)

        val secureArea = secureAreaRepository.getImplementation(secureAreaIdentifier)
            ?: throw IllegalStateException("No Secure Area with id ${secureAreaIdentifier} for document ${document.name}")

        val support = SecureAreaSupport.getInstance(context, secureArea)
        val settings = support.createAuthKeySettingsFromConfiguration(
            document.applicationData.getData(AUTH_KEY_SETTINGS),
            "challenge".toByteArray(),
            validFrom,
            validUntil
        )

        val pendingCredsCount = DocumentUtil.managedCredentialHelper(
            document,
            MDOC_CREDENTIAL_DOMAIN,
            {toBeReplaced -> MdocCredential(
                document,
                toBeReplaced,
                MDOC_CREDENTIAL_DOMAIN,
                secureArea,
                settings,
                docType
            )},
            now,
            numCreds.toInt(),
            maxUsagesPerCred.toInt(),
            minValidTimeDays*24*60*60*1000L,
            false
        )
        if (pendingCredsCount <= 0) {
            return
        }

        for (pendingCred in document.pendingCredentials.filter { it.domain == MDOC_CREDENTIAL_DOMAIN }) {
            pendingCred as MdocCredential
            val msoGenerator = MobileSecurityObjectGenerator(
                "SHA-256",
                docType,
                pendingCred.attestation.publicKey
            )
            msoGenerator.setValidityInfo(now, validFrom, validUntil, null)

            // For mDLs, override the portrait with AuthenticationKeyCounter on top
            //
            var dataElementExceptions: Map<String, List<String>>? = null
            var dataElementOverrides: Map<String, Map<String, ByteArray>>? = null
            if (docType.equals("org.iso.18013.5.1.mDL")) {
                val portrait = document.applicationData.getNameSpacedData("documentData")
                    .getDataElementByteString("org.iso.18013.5.1", "portrait")
                val portrait_override = overridePortrait(portrait,
                    pendingCred.credentialCounter)

                dataElementExceptions =
                    mapOf("org.iso.18013.5.1" to listOf("given_name", "portrait"))
                dataElementOverrides =
                    mapOf("org.iso.18013.5.1" to mapOf(
                        "portrait" to Cbor.encode(Bstr(portrait_override))))
            }

            val issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
                document.applicationData.getNameSpacedData("documentData"),
                Random.Default,
                16,
                dataElementOverrides
            )

            for (nameSpaceName in issuerNameSpaces.keys) {
                val digests = MdocUtil.calculateDigestsForNameSpace(
                    nameSpaceName,
                    issuerNameSpaces,
                    Algorithm.SHA256
                )
                msoGenerator.addDigestIdsForNamespace(nameSpaceName, digests)
            }

            val mso = msoGenerator.generate()
            val taggedEncodedMso = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(mso)))

            val issuerKeyPair = when (docType) {
                MVR_DOCTYPE -> KeysAndCertificates.getMekbDsKeyPair(context)
                MICOV_DOCTYPE -> KeysAndCertificates.getMicovDsKeyPair(context)
                else -> KeysAndCertificates.getMdlDsKeyPair(context)
            }

            val issuerCert = when (docType) {
                MVR_DOCTYPE -> KeysAndCertificates.getMekbDsCertificate(context)
                MICOV_DOCTYPE -> KeysAndCertificates.getMicovDsCertificate(context)
                else -> KeysAndCertificates.getMdlDsCertificate(context)
            }

            val encodedIssuerAuth = Cbor.encode(
                Cose.coseSign1Sign(
                    issuerKeyPair.private.toEcPrivateKey(issuerKeyPair.public, EcCurve.P256),
                    taggedEncodedMso,
                    true,
                    Algorithm.ES256,
                    protectedHeaders = mapOf(
                        Pair(
                            CoseNumberLabel(Cose.COSE_LABEL_ALG),
                            Algorithm.ES256.coseAlgorithmIdentifier.toDataItem()
                        )
                    ),
                    unprotectedHeaders = mapOf(
                        Pair(
                            CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                            X509CertChain(
                                listOf(X509Cert(issuerCert.encoded))
                            ).toDataItem()
                        )
                    ),
                ).toDataItem()
            )

            val issuerProvidedAuthenticationData = StaticAuthDataGenerator(
                MdocUtil.stripIssuerNameSpaces(issuerNameSpaces, dataElementExceptions),
                encodedIssuerAuth
            ).generate()

            pendingCred.certify(
                issuerProvidedAuthenticationData,
                validFrom,
                validUntil
            )
        }
    }

    fun refreshDaCredentials(document: Document, docType: String, documentSlot: Int) {
        val minValidTimeDays = document.applicationData.getNumber(MIN_VALIDITY_IN_DAYS)
        val maxUsagesPerCred = document.applicationData.getNumber(MAX_USAGES_PER_KEY)
        val numCreds = 1 // todo, need to think through
        val validityInDays = document.applicationData.getNumber(VALIDITY_IN_DAYS).toInt()

        val now = Clock.System.now()
        val validFrom = now
        val validUntil = Instant.fromEpochMilliseconds(
            validFrom.toEpochMilliseconds() + validityInDays*86400*1000L)

        val pendingCredsCount = DocumentUtil.managedCredentialHelper(
            document,
            DA_CREDENTIAL_DOMAIN,
            {toBeReplaced -> DirectAccessCredential(
                document,
                toBeReplaced,
                DA_CREDENTIAL_DOMAIN,
                docType,
                documentSlot
            )},
            now,
            numCreds,
            maxUsagesPerCred.toInt(),
            minValidTimeDays*24*60*60*1000L,
            false
        )
        if (pendingCredsCount <= 0) {
            return
        }

        var lastCertified: DirectAccessCredential? = null
        for (pendingCred in document.pendingCredentials.filter { it.domain == DA_CREDENTIAL_DOMAIN }) {
            lastCertified = pendingCred as DirectAccessCredential
            val msoGenerator = MobileSecurityObjectGenerator(
                "SHA-256",
                docType,
                pendingCred.attestation.publicKey
            )
            msoGenerator.setValidityInfo(now, validFrom, validUntil, null)

            // For mDLs, override the portrait with AuthenticationKeyCounter on top
            //
            var dataElementExceptions: Map<String, List<String>>? = null
            var dataElementOverrides: Map<String, Map<String, ByteArray>>? = null
            if (docType.equals("org.iso.18013.5.1.mDL")) {
                val portrait = document.applicationData.getNameSpacedData("documentData")
                    .getDataElementByteString("org.iso.18013.5.1", "portrait")
                val portrait_override = overridePortrait(portrait,
                    pendingCred.credentialCounter)

                dataElementExceptions =
                    mapOf("org.iso.18013.5.1" to listOf("given_name", "portrait"))
                dataElementOverrides =
                    mapOf("org.iso.18013.5.1" to mapOf(
                        "portrait" to Cbor.encode(Bstr(portrait_override))))
            }

            val issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
                document.applicationData.getNameSpacedData("documentData"),
                Random.Default,
                16,
                dataElementOverrides
            )

            for (nameSpaceName in issuerNameSpaces.keys) {
                val digests = MdocUtil.calculateDigestsForNameSpace(
                    nameSpaceName,
                    issuerNameSpaces,
                    Algorithm.SHA256
                )
                msoGenerator.addDigestIdsForNamespace(nameSpaceName, digests)
            }

            val mso = msoGenerator.generate()
            val taggedEncodedMso = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(mso)))

            val issuerKeyPair = when (docType) {
                MVR_DOCTYPE -> KeysAndCertificates.getMekbDsKeyPair(context)
                MICOV_DOCTYPE -> KeysAndCertificates.getMicovDsKeyPair(context)
                else -> KeysAndCertificates.getMdlDsKeyPair(context)
            }

            val issuerCert = when (docType) {
                MVR_DOCTYPE -> KeysAndCertificates.getMekbDsCertificate(context)
                MICOV_DOCTYPE -> KeysAndCertificates.getMicovDsCertificate(context)
                else -> KeysAndCertificates.getMdlDsCertificate(context)
            }

            val encodedIssuerAuth = Cbor.encode(
                Cose.coseSign1Sign(
                    issuerKeyPair.private.toEcPrivateKey(issuerKeyPair.public, EcCurve.P256),
                    taggedEncodedMso,
                    true,
                    Algorithm.ES256,
                    protectedHeaders = mapOf(
                        Pair(
                            CoseNumberLabel(Cose.COSE_LABEL_ALG),
                            Algorithm.ES256.coseAlgorithmIdentifier.toDataItem()
                        )
                    ),
                    unprotectedHeaders = mapOf(
                        Pair(
                            CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                            X509CertChain(
                                listOf(X509Cert(issuerCert.encoded))
                            ).toDataItem()
                        )
                    ),
                ).toDataItem()
            )

            val readerBuilder = CborArray.builder()
            for (cert in X509CertChain(KeysAndCertificates.getTrustedReaderCertificates(context)
                .map {X509Cert(it.encoded) }).certificates) {
                val pubKey = cert.ecPublicKey as EcPublicKeyDoubleCoordinate
                readerBuilder.add(pubKey.asUncompressedPointEncoding)
            }
            val readerAuth = readerBuilder.end().build()

            val digestIdMapping = MdocUtil.stripIssuerNameSpaces(issuerNameSpaces, dataElementExceptions)
            val issuerProvidedAuthenticationData =
                CborMap.builder().apply {
                    for ((namespace, bytesList) in digestIdMapping) {
                        putArray(namespace).let { innerBuilder ->
                            bytesList.forEach { encodedIssuerSignedItemMetadata ->
                                innerBuilder.add(RawCbor(encodedIssuerSignedItemMetadata))
                            }
                        }
                    }
                }.end().build().let { digestIdMappingItem ->
                    Cbor.encode(
                        CborMap.builder()
                            .put("docType", docType)
                            .put("issuerNameSpaces", digestIdMappingItem)
                            .put("issuerAuth", RawCbor(encodedIssuerAuth))
                            .put("readerAccess", readerAuth)
                            .end()
                            .build()
                    )
                }

            pendingCred.certify(
                issuerProvidedAuthenticationData,
                validFrom,
                validUntil
            )
        }
        lastCertified?.setAsActiveCredential()
    }

    // Puts the string "MSO ${counter}" on top of the portrait image.
    private fun overridePortrait(encodedPortrait: ByteArray, counter: Number): ByteArray {
        val options = BitmapFactory.Options()
        options.inMutable = true
        val bitmap = BitmapFactory.decodeByteArray(
            encodedPortrait,
            0,
            encodedPortrait.size,
            options)

        val text = "MSO ${counter}"
        val canvas = Canvas(bitmap)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        paint.setColor(Color.WHITE)
        paint.textSize = bitmap.width / 5.0f
        paint.setShadowLayer(2.0f, 1.0f, 1.0f, Color.BLACK)
        val bounds = Rect()
        paint.getTextBounds(text, 0, text.length, bounds)
        val x: Float = (bitmap.width - bounds.width()) / 2.0f
        val y: Float = (bitmap.height - bounds.height()) / 4.0f
        canvas.drawText(text, x, y, paint)

        val baos = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.JPEG, 50, baos)
        val encodedModifiedPortrait: ByteArray = baos.toByteArray()

        return encodedModifiedPortrait
    }

    companion object {

        const val MDOC_CREDENTIAL_DOMAIN = "mdoc/MSO"
        const val DA_CREDENTIAL_DOMAIN = "directaccess/mdoc/MSO"
        private const val USER_VISIBLE_NAME = "userVisibleName"
        const val DOCUMENT_TYPE = "documentType"
        private const val DATE_PROVISIONED = "dateProvisioned"
        private const val CARD_ART = "cardArt"
        private const val IS_SELF_SIGNED = "isSelfSigned"
        private const val MAX_USAGES_PER_KEY = "maxUsagesPerCredential"
        private const val VALIDITY_IN_DAYS = "validityInDays"
        private const val MIN_VALIDITY_IN_DAYS = "minValidityInDays"
        private const val LAST_TIME_USED = "lastTimeUsed"
        private const val NUM_CREDENTIALS = "numCredentials"
        private const val AUTH_KEY_SETTINGS = "authKeySettings"
        private const val AUTH_KEY_SECURE_AREA_IDENTIFIER = "authKeySecureAreaIdentifier"

        private val dateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME

        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: ProvisioningUtil? = null

        fun getInstance(context: Context) = instance ?: synchronized(this) {
            instance ?: ProvisioningUtil(context).also { instance = it }
        }

        val defaultSecureArea: SecureArea
            get() = requireNotNull(instance?.secureAreaRepository?.implementations?.first())

        fun Document?.toDocumentInformation(): DocumentInformation? {
            return this?.let {

                val authKeySecureAreaIdentifier = it.applicationData.getString(AUTH_KEY_SECURE_AREA_IDENTIFIER)
                val authKeySecureArea = instance!!.secureAreaRepository.getImplementation(authKeySecureAreaIdentifier)
                    ?: throw IllegalStateException("No Secure Area with id ${authKeySecureAreaIdentifier} for document ${it.name}")

                val mdocCredentials = ArrayList<DocumentInformation.KeyData>()
                val directAccessCredentials = ArrayList<DocumentInformation.DirectAccessCredInfo>()
                for (key in certifiedCredentials) {
                    when (key) {
                        is MdocCredential -> {
                            val info = authKeySecureArea.getKeyInfo(key.alias)
                            mdocCredentials.add(DocumentInformation.KeyData(
                                counter = key.credentialCounter.toInt(),
                                validFrom = key.validFrom.formatted(),
                                validUntil = key.validUntil.formatted(),
                                domain = key.domain,
                                issuerDataBytesCount = key.issuerProvidedData.size,
                                usagesCount = key.usageCount,
                                keyPurposes = info.keyPurposes.first(),
                                ecCurve = info.publicKey.curve,
                                isHardwareBacked = false,  // TODO: remove
                                secureAreaDisplayName = authKeySecureArea.displayName
                            ))
                        }

                        is DirectAccessCredential -> {
                            directAccessCredentials.add(DocumentInformation.DirectAccessCredInfo(
                                counter = key.credentialCounter.toInt(),
                                validFrom = key.validFrom.formatted(),
                                validUntil = key.validUntil.formatted(),
                                domain = key.domain,
                                issuerDataBytesCount = key.issuerProvidedData.size,
                                usagesCount = key.usageCount,
                                secureAreaDisplayName = authKeySecureArea.displayName
                            ))
                        }

                        else -> { }
                    }

                }
                val lastTimeUsedMillis = it.applicationData.getNumber(LAST_TIME_USED)
                val lastTimeUsed = if (lastTimeUsedMillis == -1L) {
                    ""
                } else {
                    Instant.fromEpochMilliseconds(lastTimeUsedMillis).formatted()
                }
                DocumentInformation(
                    userVisibleName = it.applicationData.getString(USER_VISIBLE_NAME),
                    docName = it.name,
                    docType = it.applicationData.getString(DOCUMENT_TYPE),
                    dateProvisioned = it.applicationData.getString(DATE_PROVISIONED),
                    documentColor = it.applicationData.getNumber(CARD_ART).toInt(),
                    selfSigned = it.applicationData.getBoolean(IS_SELF_SIGNED),
                    maxUsagesPerKey = it.applicationData.getNumber(MAX_USAGES_PER_KEY).toInt(),
                    lastTimeUsed = lastTimeUsed,
                    authKeys = mdocCredentials,
                    daCreds = directAccessCredentials
                )
            }
        }

        private fun Instant.formatted(): String {
            val javaInstant = JavaInstant.ofEpochMilli(this.toEpochMilliseconds())
            val dateTime = ZonedDateTime.ofInstant(javaInstant, ZoneId.systemDefault())
            return dateTimeFormatter.format(dateTime)
        }
    }
}
