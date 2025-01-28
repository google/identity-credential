package com.android.identity_credential.wallet

import android.Manifest
import android.app.ActivityManager
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Process
import android.preference.PreferenceManager
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.res.ResourcesCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.securearea.cloud.CloudSecureArea
import com.android.identity.credential.CredentialFactory
import com.android.identity.document.Document
import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.crypto.X509Cert
import com.android.identity.documenttype.knowntypes.EUCertificateOfResidence
import com.android.identity.documenttype.knowntypes.GermanPersonalID
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.documenttype.knowntypes.UtopiaMovieTicket
import com.android.identity.documenttype.knowntypes.UtopiaNaturalization
import com.android.identity.issuance.DocumentExtensions.documentConfiguration
import com.android.identity.issuance.WalletApplicationCapabilities
import com.android.identity.issuance.remote.WalletServerProvider
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.vical.SignedVical
import com.android.identity.sdjwt.credential.KeyBoundSdJwtVcCredential
import com.android.identity.sdjwt.credential.KeylessSdJwtVcCredential
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.Storage
import com.android.identity.storage.android.AndroidStorage
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.logging.EventLogger
import com.android.identity_credential.wallet.util.toByteArray
import kotlinx.datetime.Clock
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.net.URLDecoder
import java.security.Security
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours
import kotlin.time.toJavaDuration

class WalletApplication : Application() {
    companion object {
        private const val TAG = "WalletApplication"

        private const val NOTIFICATION_CHANNEL_ID = "walletNotifications"

        private const val NOTIFICATION_ID_FOR_MISSING_PROXIMITY_PRESENTATION_PERMISSIONS = 42

        const val CREDENTIAL_DOMAIN_MDOC = "mdoc/MSO"
        const val CREDENTIAL_DOMAIN_SD_JWT_VC = "SD-JWT"

        // OID4VCI url scheme used for filtering OID4VCI Urls from all incoming URLs (deep links or QR)
        const val OID4VCI_CREDENTIAL_OFFER_URL_SCHEME = "openid-credential-offer://"
        // The permissions needed to perform 18013-5 presentations. This only include the
        // BLE permissions because that's the only transport we currently support in the
        // application.
        val MDOC_PROXIMITY_PERMISSIONS: List<String> =
            if (Build.VERSION.SDK_INT >= 31) {
                listOf(
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT
                )
            } else {
                listOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }
    }


    // immediate instantiations
    val readerTrustManager = TrustManager()
    val issuerTrustManager = TrustManager()

    // lazy instantiations
    val sharedPreferences: SharedPreferences by lazy {
        PreferenceManager.getDefaultSharedPreferences(applicationContext)
    }

    // late instantiations
    lateinit var storage: Storage
    lateinit var documentTypeRepository: DocumentTypeRepository
    lateinit var secureAreaRepository: SecureAreaRepository
    lateinit var credentialFactory: CredentialFactory
    lateinit var documentStore: DocumentStore
    lateinit var settingsModel: SettingsModel
    lateinit var documentModel: DocumentModel
    lateinit var readerModel: ReaderModel
    lateinit var eventLogger: EventLogger
    private lateinit var secureAreaProvider: SecureAreaProvider<AndroidKeystoreSecureArea>
    lateinit var walletServerProvider: WalletServerProvider

    override fun onCreate() {
        super.onCreate()
        if (isAusweisSdkProcess()) {
            Logger.d(TAG, "Ausweis SDK - onCreate")
            return
        }
        Logger.d(TAG, "onCreate")

        // This is needed to prefer BouncyCastle bundled with the app instead of the Conscrypt
        // based implementation included in the OS itself.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())

        // init documentTypeRepository
        documentTypeRepository = DocumentTypeRepository()
        documentTypeRepository.addDocumentType(DrivingLicense.getDocumentType())
        documentTypeRepository.addDocumentType(EUPersonalID.getDocumentType())
        documentTypeRepository.addDocumentType(GermanPersonalID.getDocumentType())
        documentTypeRepository.addDocumentType(PhotoID.getDocumentType())
        documentTypeRepository.addDocumentType(EUCertificateOfResidence.getDocumentType())
        documentTypeRepository.addDocumentType(UtopiaNaturalization.getDocumentType())
        documentTypeRepository.addDocumentType(UtopiaMovieTicket.getDocumentType())

        // init storage
        val storageFile = File(applicationContext.noBackupFilesDir.path, "main.db")
        storage = AndroidStorage(storageFile.absolutePath)

        // init EventLogger
        eventLogger = EventLogger(storage)

        settingsModel = SettingsModel(this, sharedPreferences)

        // init AndroidKeyStoreSecureArea
        secureAreaProvider = SecureAreaProvider {
            AndroidKeystoreSecureArea.create(applicationContext, storage)
        }

        // init SecureAreaRepository
        secureAreaRepository = SecureAreaRepository.build {
            add(SoftwareSecureArea.create(storage))
            add(secureAreaProvider.get())
            addFactory(CloudSecureArea.IDENTIFIER_PREFIX) { identifier ->
                val queryString = identifier.substring(CloudSecureArea.IDENTIFIER_PREFIX.length + 1)
                val params = queryString.split("&").map {
                    val parts = it.split("=", ignoreCase = false, limit = 2)
                    parts[0] to URLDecoder.decode(parts[1], "UTF-8")
                }.toMap()
                val givenUrl = params["url"]!!
                val cloudSecureAreaUrl =
                    if (givenUrl.startsWith("/")) {
                        settingsModel.walletServerUrl.value + givenUrl
                    } else {
                        givenUrl
                    }
                Logger.i(TAG, "Creating CSA with url $cloudSecureAreaUrl for $identifier")
                CloudSecureArea.create(
                    storage,
                    identifier,
                    cloudSecureAreaUrl
                )
            }
        }

        // init credentialFactory
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(MdocCredential::class) {
            document, dataItem -> MdocCredential(document).apply { deserialize(dataItem) }
        }
        credentialFactory.addCredentialImplementation(KeyBoundSdJwtVcCredential::class) {
            document, dataItem -> KeyBoundSdJwtVcCredential(document).apply { deserialize(dataItem) }
        }
        credentialFactory.addCredentialImplementation(KeylessSdJwtVcCredential::class) {
            document, dataItem -> KeylessSdJwtVcCredential(document).apply { deserialize(dataItem) }
        }

        // init documentStore
        documentStore = DocumentStore(storage, secureAreaRepository, credentialFactory)

        // init Wallet Server
        walletServerProvider = WalletServerProvider(
            this,
            storage,
            secureAreaProvider,
            settingsModel
        ) {
            getWalletApplicationInformation()
        }

        // init TrustManager for readers (used in consent dialog)
        //
        readerTrustManager.addTrustPoint(
            displayName = "OWF Identity Credential Reader",
            certificateResourceId = R.raw.owf_identity_credential_reader_cert,
            displayIconResourceId = R.drawable.owf_identity_credential_reader_display_icon
        )
        for (certResourceId in listOf(
            R.raw.austroad_test_event_reader_credence_id,
            R.raw.austroad_test_event_reader_fast_enterprises,
            R.raw.austroad_test_event_reader_fime_reader_ca1,
            R.raw.austroad_test_event_reader_fime_reader_ca2,
            R.raw.austroad_test_event_reader_idemia,
            R.raw.austroad_test_event_reader_mattr_labs,
            R.raw.austroad_test_event_reader_nist,
            R.raw.austroad_test_event_reader_panasonic_root,
            R.raw.austroad_test_event_reader_panasonic_remote_root,
            R.raw.austroad_test_event_reader_scytales,
            R.raw.austroad_test_event_reader_snsw_labs,
            R.raw.austroad_test_event_reader_thales_root,
            R.raw.austroad_test_event_reader_zetes,
        )) {
            val pemEncodedCert = resources.openRawResource(certResourceId).readBytes().decodeToString()
            Logger.i(TAG, "PEMEncoded\n$pemEncodedCert")
            val cert = X509Cert.fromPem(pemEncodedCert)
            Logger.iHex(TAG, "x509cert", cert.encodedCertificate)
            readerTrustManager.addTrustPoint(
                TrustPoint(
                    cert,
                    null,
                    null,
                )
            )
        }

        // init TrustManager for issuers (used in reader)
        //
        val signedVical = SignedVical.parse(
            resources.openRawResource(R.raw.austroad_test_event_vical_20241002).readBytes()
        )
        for (certInfo in signedVical.vical.certificateInfos) {
            val cert = X509Cert(certInfo.certificate)
            issuerTrustManager.addTrustPoint(
                TrustPoint(
                    cert,
                    null,
                    null
                )
            )
        }
        issuerTrustManager.addTrustPoint(
            displayName = "OWF Identity Credential TEST IACA",
            certificateResourceId = R.raw.iaca_certificate,
            displayIconResourceId = R.drawable.owf_identity_credential_reader_display_icon
        )


        documentModel = DocumentModel(
            applicationContext,
            settingsModel,
            documentStore,
            secureAreaRepository,
            documentTypeRepository,
            walletServerProvider,
            this
        )

        readerModel = ReaderModel(
            applicationContext,
            documentTypeRepository,
            settingsModel
        )

        val notificationChannel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            resources.getString(R.string.app_name),
            NotificationManager.IMPORTANCE_HIGH
        )
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(notificationChannel)

        // Configure a worker for invoking cardModel.periodicSyncForAllCredentials()
        // on a daily basis.
        //
        val workRequest =
            PeriodicWorkRequestBuilder<SyncCredentialWithIssuerWorker>(
                1, TimeUnit.DAYS
            ).setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
            ).setInitialDelay(
                Random.Default.nextInt(1, 24).hours.toJavaDuration()
            ).build()
        WorkManager.getInstance(applicationContext)
            .enqueueUniquePeriodicWork(
                "PeriodicSyncWithIssuers",
                ExistingPeriodicWorkPolicy.KEEP,
                workRequest
            )
    }

    class SyncCredentialWithIssuerWorker(
        context: Context,
        params: WorkerParameters
    ) : Worker(context, params) {
        override fun doWork(): Result {
            Logger.i(TAG, "Starting periodic syncing work")
            try {
                val walletApplication = applicationContext as WalletApplication
                walletApplication.documentModel.periodicSyncForAllDocuments()
            } catch (e: Throwable) {
                Logger.i(TAG, "Ending periodic syncing work (failed)", e)
                return Result.failure()
            }
            Logger.i(TAG, "Ending periodic syncing work (success)")
            return Result.success()
        }
    }

    /**
     * Extend TrustManager to add a TrustPoint via the individual data point resources that make
     * a TrustPoint.
     *
     * This extension function belongs to WalletApplication so it can use context.resources.
     */
    fun TrustManager.addTrustPoint(
        displayName: String,
        certificateResourceId: Int,
        displayIconResourceId: Int?
    ) = addTrustPoint(
        TrustPoint(
            certificate = X509Cert.fromPem(
                String(
                    resources.openRawResource(certificateResourceId).readBytes()
                )
            ),
            displayName = displayName,
            displayIcon = displayIconResourceId?.let { iconId ->
                ResourcesCompat.getDrawable(resources, iconId, null)?.toByteArray()
            }
        )
    )

    fun postNotificationForMissingMdocProximityPermissions() {
        // Go to main page, the user can request the permission there
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE)

        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_name)
            .setLargeIcon(BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher))
            .setContentTitle(applicationContext.getString(R.string.proximity_permissions_nfc_notification_title))
            .setContentText(applicationContext.getString(R.string.proximity_permissions_nfc_notification_content))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        NotificationManagerCompat.from(applicationContext).notify(
            NOTIFICATION_ID_FOR_MISSING_PROXIMITY_PRESENTATION_PERMISSIONS,
            builder.build())
    }

    fun postNotificationForDocument(
        document: Document,
        message: String,
    ) {
        // TODO: include data so the user is brought to the info page for the document
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE)

        val cardArt = document.documentConfiguration.cardArt
        val bitmap = BitmapFactory.decodeByteArray(cardArt, 0, cardArt.size)

        val title = document.documentConfiguration.displayName
        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_name)
            .setLargeIcon(bitmap)
            .setContentTitle(title)
            .setContentText(message)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        val notificationId = document.name.hashCode()
        NotificationManagerCompat.from(applicationContext).notify(notificationId, builder.build())
    }

    private suspend fun getWalletApplicationInformation(): WalletApplicationCapabilities {
        val now = Clock.System.now()

        val keystoreCapabilities = AndroidKeystoreSecureArea.Capabilities(applicationContext)

        return WalletApplicationCapabilities(
            generatedAt = now,
            androidKeystoreAttestKeyAvailable = keystoreCapabilities.attestKeySupported,
            androidKeystoreStrongBoxAvailable = keystoreCapabilities.strongBoxSupported,
            androidIsEmulator = isProbablyRunningOnEmulator
        )
    }

    // https://stackoverflow.com/a/21505193/878126
    private val isProbablyRunningOnEmulator: Boolean by lazy {
        // Android SDK emulator
        return@lazy ((Build.MANUFACTURER == "Google" && Build.BRAND == "google" &&
                ((Build.FINGERPRINT.startsWith("google/sdk_gphone_")
                        && Build.FINGERPRINT.endsWith(":user/release-keys")
                        && Build.PRODUCT.startsWith("sdk_gphone_")
                        && Build.MODEL.startsWith("sdk_gphone_"))
                        //alternative
                        || (Build.FINGERPRINT.startsWith("google/sdk_gphone64_")
                        && (Build.FINGERPRINT.endsWith(":userdebug/dev-keys") || Build.FINGERPRINT.endsWith(
                    ":user/release-keys"
                ))
                        && Build.PRODUCT.startsWith("sdk_gphone64_")
                        && Build.MODEL.startsWith("sdk_gphone64_"))))
                //
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                //bluestacks
                || "QC_Reference_Phone" == Build.BOARD && !"Xiaomi".equals(
            Build.MANUFACTURER,
            ignoreCase = true
        )
                //bluestacks
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.HOST.startsWith("Build")
                //MSI App Player
                || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || Build.PRODUCT == "google_sdk")
                // another Android SDK emulator check
                /* || SystemProperties.getProp("ro.kernel.qemu") == "1") */
    }

    private fun isAusweisSdkProcess(): Boolean {
        val ausweisServiceName = "ausweisapp2_service"
        if (Build.VERSION.SDK_INT >= 28) {
            return getProcessName().endsWith(ausweisServiceName)
        }
        val pid = Process.myPid()
        val manager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
        for (appProcess in manager.runningAppProcesses) {
            if (appProcess.pid == pid) {
                return appProcess.processName.endsWith(ausweisServiceName)
            }
        }
        return false
    }
}