package com.android.identity.testapp

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.android.identity.appsupport.ui.AppTheme
import com.android.identity.appsupport.ui.digitalcredentials.DigitalCredentials
import com.android.identity.appsupport.ui.presentment.PresentmentModel
import com.android.identity.asn1.ASN1Integer
import com.android.identity.cbor.Cbor
import com.android.identity.credential.CredentialFactory
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.X500Name
import com.android.identity.crypto.X509Cert
import com.android.identity.document.DocumentStore
import com.android.identity.documenttype.DocumentTypeRepository
import com.android.identity.documenttype.knowntypes.DrivingLicense
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.documenttype.knowntypes.PhotoID
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.secure_area_test_app.ui.CloudSecureAreaScreen
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.StorageTable
import com.android.identity.storage.StorageTableSpec
import com.android.identity.testapp.ui.AboutScreen
import com.android.identity.testapp.ui.AndroidKeystoreSecureAreaScreen
import com.android.identity.testapp.ui.CertificateViewerExamplesScreen
import com.android.identity.testapp.ui.ConsentModalBottomSheetListScreen
import com.android.identity.testapp.ui.ConsentModalBottomSheetScreen
import com.android.identity.testapp.ui.IsoMdocMultiDeviceTestingScreen
import com.android.identity.testapp.ui.IsoMdocProximityReadingScreen
import com.android.identity.testapp.ui.IsoMdocProximitySharingScreen
import com.android.identity.testapp.ui.NfcScreen
import com.android.identity.testapp.ui.PassphraseEntryFieldScreen
import com.android.identity.testapp.ui.PresentmentScreen
import com.android.identity.testapp.ui.ProvisioningTestScreen
import com.android.identity.testapp.ui.QrCodesScreen
import com.android.identity.testapp.ui.SecureEnclaveSecureAreaScreen
import com.android.identity.testapp.ui.SoftwareSecureAreaScreen
import com.android.identity.testapp.ui.StartScreen
import com.android.identity.testapp.ui.VerifierType
import com.android.identity.testapp.ui.CertificateScreen
import com.android.identity.testapp.ui.PassphrasePromptScreen
import com.android.identity.testapp.ui.SettingsScreen
import com.android.identity.trustmanagement.TrustManager
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.util.Logger
import identitycredential.samples.testapp.generated.resources.Res
import identitycredential.samples.testapp.generated.resources.back_button
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.io.bytestring.ByteString
import org.jetbrains.compose.resources.ExperimentalResourceApi
import org.jetbrains.compose.resources.stringResource
import org.jetbrains.compose.ui.tooling.preview.Preview

/**
 * Application singleton.
 *
 * Use [App.Companion.getInstance] to get an instance.
 */
class App private constructor() {

    lateinit var settingsModel: TestAppSettingsModel

    lateinit var documentTypeRepository: DocumentTypeRepository

    lateinit var documentStore: DocumentStore

    lateinit var iacaKey: EcPrivateKey
    lateinit var iacaCert: X509Cert

    lateinit var dsKey: EcPrivateKey
    lateinit var dsCert: X509Cert

    lateinit var readerRootKey: EcPrivateKey
    lateinit var readerRootCert: X509Cert

    lateinit var readerKey: EcPrivateKey
    lateinit var readerCert: X509Cert

    lateinit var issuerTrustManager: TrustManager

    lateinit var readerTrustManager: TrustManager

    private suspend fun init() {
        val initFuncs = listOf<Pair<suspend () -> Unit, String>>(
            Pair(::platformInit, "platformInit"),
            Pair(::settingsInit, "settingsInit"),
            Pair(::documentTypeRepositoryInit, "documentTypeRepositoryInit"),
            Pair(::documentStoreInit, "documentStoreInit"),
            Pair(::keyStorageInit, "keyStorageInit"),
            Pair(::iacaInit, "iacaInit"),
            Pair(::dsInit, "dsInit"),
            Pair(::readerRootInit, "readerRootInit"),
            Pair(::readerInit, "readerInit"),
            Pair(::documentsInit, "documentsInit"),
            Pair(::trustManagersInit, "trustManagersInit"),
        )
        val begin = Clock.System.now()
        for ((func, name) in initFuncs) {
            val funcBegin = Clock.System.now()
            func()
            val funcEnd = Clock.System.now()
            Logger.i(TAG, "$name initialization time: ${(funcEnd - funcBegin).inWholeMilliseconds} ms")
        }
        val end = Clock.System.now()
        Logger.i(TAG, "Total application initialization time: ${(end - begin).inWholeMilliseconds} ms")
    }

    private suspend fun settingsInit() {
        settingsModel = TestAppSettingsModel.create(platformStorage())
    }

    private suspend fun documentTypeRepositoryInit() {
        documentTypeRepository = DocumentTypeRepository()
        documentTypeRepository.addDocumentType(DrivingLicense.getDocumentType())
        documentTypeRepository.addDocumentType(PhotoID.getDocumentType())
        documentTypeRepository.addDocumentType(EUPersonalID.getDocumentType())
    }

    private suspend fun documentStoreInit() {
        val secureAreaRepository: SecureAreaRepository = SecureAreaRepository.build {
            add(SoftwareSecureArea.create(platformStorage()))
            add(platformSecureAreaProvider().get())
        }
        val credentialFactory: CredentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(MdocCredential::class) {
            document -> MdocCredential(document)
        }
        documentStore = DocumentStore(
            platformStorage(),
            secureAreaRepository,
            credentialFactory,
            TestDocumentMetadata::create
        )
    }

    private suspend fun documentsInit() {
        TestAppUtils.provisionDocuments(
            documentStore,
            dsKey,
            dsCert
        )
    }

    private suspend fun trustManagersInit() {
        generateTrustManagers()
    }

    private val certsValidFrom = LocalDate.parse("2024-12-01").atStartOfDayIn(TimeZone.UTC)
    private val certsValidUntil = LocalDate.parse("2034-12-01").atStartOfDayIn(TimeZone.UTC)

    private val bundledIacaKey: EcPrivateKey by lazy {
        val iacaKeyPub = EcPublicKey.fromPem(
            """
                    -----BEGIN PUBLIC KEY-----
                    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+
                    wih+L79b7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH
                    5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                    -----END PUBLIC KEY-----
                """.trimIndent().trim(),
            EcCurve.P384
        )
        EcPrivateKey.fromPem(
            """
                    -----BEGIN PRIVATE KEY-----
                    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                    /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                    7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                    UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                    -----END PRIVATE KEY-----
                """.trimIndent().trim(),
            iacaKeyPub
        )
    }

    val bundledIacaCert: X509Cert by lazy {
        MdocUtil.generateIacaCertificate(
            iacaKey = iacaKey,
            subject = X500Name.fromName("C=ZZ,CN=OWF Identity Credential TEST IACA"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
            issuerAltNameUrl = "https://github.com/openwallet-foundation-labs/identity-credential",
            crlUrl = "https://github.com/openwallet-foundation-labs/identity-credential"
        )
    }

    private val bundledReaderRootKey: EcPrivateKey by lazy {
        val readerRootKeyPub = EcPublicKey.fromPem(
            """
                    -----BEGIN PUBLIC KEY-----
                    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+
                    wih+L79b7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH
                    5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                    -----END PUBLIC KEY-----
                """.trimIndent().trim(),
            EcCurve.P384
        )
        EcPrivateKey.fromPem(
            """
                    -----BEGIN PRIVATE KEY-----
                    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                    /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                    7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                    UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                    -----END PRIVATE KEY-----
                """.trimIndent().trim(),
            readerRootKeyPub
        )
    }

    private val bundledReaderRootCert: X509Cert by lazy {
        MdocUtil.generateReaderRootCertificate(
            readerRootKey = iacaKey,
            subject = X500Name.fromName("CN=OWF IC TestApp Reader Root"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
        )
    }

    private lateinit var keyStorage: StorageTable

    private suspend fun keyStorageInit() {
        keyStorage = platformStorage().getTable(
            StorageTableSpec(
                name = "TestAppKeys",
                supportPartitions = false,
                supportExpiration = false
            )
        )
    }

    private suspend fun iacaInit() {
        iacaKey = keyStorage.get("iacaKey")?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                keyStorage.insert("iacaKey", ByteString(Cbor.encode(bundledIacaKey.toDataItem())))
                bundledIacaKey
            }
        iacaCert = keyStorage.get("iacaCert")?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                keyStorage.insert("iacaCert", ByteString(Cbor.encode(bundledIacaCert.toDataItem())))
                bundledIacaCert
            }
    }

    private suspend fun dsInit() {
        dsKey = keyStorage.get("dsKey")?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                val key = Crypto.createEcPrivateKey(EcCurve.P256)
                keyStorage.insert("dsKey", ByteString(Cbor.encode(key.toDataItem())))
                key
            }
        dsCert = keyStorage.get("dsCert")?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                val cert = MdocUtil.generateDsCertificate(
                    iacaCert = iacaCert,
                    iacaKey = iacaKey,
                    dsKey = dsKey.publicKey,
                    subject = X500Name.fromName("C=ZZ,CN=OWF Identity Credential TEST DS"),
                    serial = ASN1Integer(1L),
                    validFrom = certsValidFrom,
                    validUntil = certsValidUntil,
                )
                keyStorage.insert("dsCert", ByteString(Cbor.encode(cert.toDataItem())))
                cert
            }
    }

    private suspend fun readerRootInit() {
        readerRootKey = keyStorage.get("readerRootKey")?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                keyStorage.insert("readerRootKey", ByteString(Cbor.encode(bundledReaderRootKey.toDataItem())))
                bundledReaderRootKey
            }
        readerRootCert = keyStorage.get("readerRootCert")?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                keyStorage.insert("readerRootCert", ByteString(Cbor.encode(bundledReaderRootCert.toDataItem())))
                bundledReaderRootCert
            }
    }

    private suspend fun readerInit() {
        readerKey = keyStorage.get("readerKey")?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                val key = Crypto.createEcPrivateKey(EcCurve.P256)
                keyStorage.insert("readerKey", ByteString(Cbor.encode(key.toDataItem())))
                key
            }
        readerCert = keyStorage.get("readerCert")?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
            ?: run {
                val cert = MdocUtil.generateReaderCertificate(
                    readerRootCert = readerRootCert,
                    readerRootKey = readerRootKey,
                    readerKey = readerKey.publicKey,
                    subject = X500Name.fromName("CN=OWF IC TestApp Reader Cert"),
                    serial = ASN1Integer(1L),
                    validFrom = certsValidFrom,
                    validUntil = certsValidUntil,
                )
                keyStorage.insert("readerCert", ByteString(Cbor.encode(cert.toDataItem())))
                cert
            }
    }

    @OptIn(ExperimentalResourceApi::class)
    private suspend fun generateTrustManagers() {
        issuerTrustManager = TrustManager()
        issuerTrustManager.addTrustPoint(
            TrustPoint(
                certificate = iacaCert,
                displayName = "OWF IC TestApp Issuer",
                displayIcon = null
            )
        )

        readerTrustManager = TrustManager()
        readerTrustManager.addTrustPoint(
            TrustPoint(
                certificate = readerRootCert,
                displayName = "OWF IC TestApp",
                displayIcon = Res.readBytes("files/utopia-brewery.png")
            )
        )
    }

    /**
     * Starts export documents via the W3C Digital Credentials API on the platform, if available.
     *
     * This should be called when the main wallet application UI is running.
     */
    fun startExportDocumentsToDigitalCredentials() {
        CoroutineScope(Dispatchers.IO).launch {
            if (DigitalCredentials.Default.available) {
                DigitalCredentials.Default.startExportingCredentials(
                    documentStore = documentStore,
                    documentTypeRepository = documentTypeRepository,
                )
            }
        }
    }

    companion object {
        private const val TAG = "App"

        private var app: App? = null
        private val appLock = Mutex()

        suspend fun getInstance(): App {
            appLock.withLock {
                if (app == null) {
                    app = App()
                    app!!.init()
                }
            }
            return app!!
        }

        // TODO: Only used in MainViewController.kt because of deadlocks when doing
        //       `val app = runBlocking { App.getInstance() }`. Investigate.
        //
        fun getInstanceAndInitializeInBackground(): App {
            if (app != null) {
                return app!!
            }
            app = App()
            CoroutineScope(Dispatchers.IO).launch {
                app!!.init()
            }
            return app!!
        }
    }

    private lateinit var snackbarHostState: SnackbarHostState

    private val presentmentModel = PresentmentModel()

    @Composable
    @Preview
    fun Content(navController: NavHostController = rememberNavController()) {
        val backStackEntry by navController.currentBackStackEntryAsState()
        val routeWithoutArgs = backStackEntry?.destination?.route?.substringBefore('/')

        val currentDestination = appDestinations.find {
            it.route == routeWithoutArgs
        } ?: StartDestination

        snackbarHostState = remember { SnackbarHostState() }
        AppTheme {
            // A surface container using the 'background' color from the theme
            Scaffold(
                topBar = {
                    AppBar(
                        currentDestination = currentDestination,
                        canNavigateBack = navController.previousBackStackEntry != null,
                        navigateUp = { navController.navigateUp() },
                        navigateToSettings = { navController.navigate(SettingsDestination.route) },
                        includeSettingsIcon = (currentDestination != SettingsDestination)
                    )
                },
                snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            ) { innerPadding ->

                NavHost(
                    navController = navController,
                    startDestination = StartDestination.route,
                    modifier = Modifier
                        .fillMaxSize()
                        //.verticalScroll(rememberScrollState())
                        .padding(innerPadding)
                ) {
                    composable(route = StartDestination.route) {
                        StartScreen(
                            onClickAbout = { navController.navigate(AboutDestination.route) },
                            onClickSoftwareSecureArea = { navController.navigate(SoftwareSecureAreaDestination.route) },
                            onClickAndroidKeystoreSecureArea = { navController.navigate(AndroidKeystoreSecureAreaDestination.route) },
                            onClickCloudSecureArea = { navController.navigate(CloudSecureAreaDestination.route) },
                            onClickSecureEnclaveSecureArea = { navController.navigate(SecureEnclaveSecureAreaDestination.route) },
                            onClickPassphraseEntryField = { navController.navigate(PassphraseEntryFieldDestination.route) },
                            onClickPassphrasePrompt = { navController.navigate(PassphrasePromptDestination.route) },
                            onClickIssuanceTestField = { navController.navigate(ProvisioningTestDestination.route) },
                            onClickConsentSheetList = { navController.navigate(ConsentModalBottomSheetListDestination.route) },
                            onClickQrCodes = { navController.navigate(QrCodesDestination.route) },
                            onClickNfc = { navController.navigate(NfcDestination.route) },
                            onClickIsoMdocProximitySharing = { navController.navigate(IsoMdocProximitySharingDestination.route) },
                            onClickIsoMdocProximityReading = { navController.navigate(IsoMdocProximityReadingDestination.route) },
                            onClickMdocTransportMultiDeviceTesting = { navController.navigate(IsoMdocMultiDeviceTestingDestination.route) },
                            onClickCertificatesViewerExamples = { navController.navigate(CertificatesViewerExamplesDestination.route) },
                        )
                    }
                    composable(route = SettingsDestination.route) {
                        SettingsScreen(this@App)
                    }
                    composable(route = AboutDestination.route) {
                        AboutScreen()
                    }
                    composable(route = SoftwareSecureAreaDestination.route) {
                        SoftwareSecureAreaScreen(showToast = { message -> showToast(message) })
                    }
                    composable(route = AndroidKeystoreSecureAreaDestination.route) {
                        AndroidKeystoreSecureAreaScreen(
                            showToast = { message -> showToast(message) },
                            onViewCertificate = { encodedCertificateData ->
                                navController.navigate(CertificateViewerDestination.route + "/${encodedCertificateData}")
                            }
                        )
                    }
                    composable(route = SecureEnclaveSecureAreaDestination.route) {
                        SecureEnclaveSecureAreaScreen(showToast = { message -> showToast(message) })
                    }
                    composable(route = CloudSecureAreaDestination.route) {
                        CloudSecureAreaScreen(
                            app = this@App,
                            showToast = { message -> showToast(message) },
                            onViewCertificate = { encodedCertificateData ->
                                navController.navigate(CertificateViewerDestination.route + "/${encodedCertificateData}")
                            }
                        )
                    }
                    composable(route = PassphraseEntryFieldDestination.route) {
                        PassphraseEntryFieldScreen(showToast = { message -> showToast(message) })
                    }
                    composable(route = PassphrasePromptDestination.route) {
                        PassphrasePromptScreen(showToast = { message -> showToast(message) })
                    }
                    composable(route = ProvisioningTestDestination.route) {
                        ProvisioningTestScreen()
                    }
                    composable(route = ConsentModalBottomSheetListDestination.route) {
                        ConsentModalBottomSheetListScreen(
                            onConsentModalBottomSheetClicked =
                            { mdlSampleRequest, verifierType ->
                                navController.navigate(
                                    ConsentModalBottomSheetDestination.route + "/$mdlSampleRequest/$verifierType")
                            }
                        )
                    }
                    composable(
                        route = ConsentModalBottomSheetDestination.routeWithArgs,
                        arguments = ConsentModalBottomSheetDestination.arguments
                    ) { navBackStackEntry ->
                        val mdlSampleRequest = navBackStackEntry.arguments?.getString(
                            ConsentModalBottomSheetDestination.mdlSampleRequestArg
                        )!!
                        val verifierType = VerifierType.valueOf(navBackStackEntry.arguments?.getString(
                            ConsentModalBottomSheetDestination.verifierTypeArg
                        )!!)
                        ConsentModalBottomSheetScreen(
                            mdlSampleRequest = mdlSampleRequest,
                            verifierType = verifierType,
                            showToast = { message -> showToast(message) },
                            onSheetConfirmed = { navController.popBackStack() },
                            onSheetDismissed = { navController.popBackStack() },
                        )
                    }
                    composable(route = QrCodesDestination.route) {
                        QrCodesScreen(
                            showToast = { message -> showToast(message) }
                        )
                    }
                    composable(route = NfcDestination.route) {
                        NfcScreen(
                            showToast = { message -> showToast(message) }
                        )
                    }
                    composable(route = IsoMdocProximitySharingDestination.route) {
                        IsoMdocProximitySharingScreen(
                            presentmentModel = presentmentModel,
                            settingsModel = settingsModel,
                            onNavigateToPresentmentScreen = {
                                navController.navigate(PresentmentDestination.route)
                            },
                            showToast = { message -> showToast(message) },
                        )
                    }
                    composable(route = IsoMdocProximityReadingDestination.route) {
                        IsoMdocProximityReadingScreen(
                            app = this@App,
                            showToast = { message -> showToast(message) }
                        )
                    }
                    composable(route = IsoMdocMultiDeviceTestingDestination.route) {
                        IsoMdocMultiDeviceTestingScreen(
                            showToast = { message -> showToast(message) }
                        )
                    }
                    composable(route = PresentmentDestination.route) {
                        PresentmentScreen(
                            app = this@App,
                            presentmentModel = presentmentModel,
                            onPresentationComplete = { navController.popBackStack() },
                        )
                    }
                    composable(route = CertificatesViewerExamplesDestination.route) {
                        CertificateViewerExamplesScreen(
                            onViewCertificate = { encodedCertificateData ->
                                navController.navigate(CertificateViewerDestination.route + "/${encodedCertificateData}")
                            }
                        )
                    }
                    composable(
                        route = CertificateViewerDestination.routeWithArgs,
                        arguments = CertificateViewerDestination.arguments
                    ) { backStackEntry ->
                        val certData = backStackEntry.arguments?.getString(
                            CertificateViewerDestination.CERTIFICATE_DATA
                        )!!
                        CertificateScreen(certData)
                    }
                }
            }
        }
    }

    private fun showToast(message: String) {
        CoroutineScope(Dispatchers.Main).launch {
            when (snackbarHostState.showSnackbar(
                message = message,
                actionLabel = "OK",
                duration = SnackbarDuration.Short,
            )) {
                SnackbarResult.Dismissed -> {
                }

                SnackbarResult.ActionPerformed -> {
                }
            }
        }
    }
}

/**
 * Composable that displays the topBar and displays back button if back navigation is possible.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppBar(
    currentDestination: Destination,
    canNavigateBack: Boolean,
    navigateUp: () -> Unit,
    navigateToSettings: () -> Unit,
    includeSettingsIcon: Boolean,
    modifier: Modifier = Modifier
) {
    TopAppBar(
        title = { Text(stringResource(currentDestination.title)) },
        colors = TopAppBarDefaults.mediumTopAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        ),
        modifier = modifier,
        navigationIcon = {
            if (canNavigateBack) {
                IconButton(onClick = navigateUp) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(Res.string.back_button)
                    )
                }
            }
        },
        actions = {
            if (includeSettingsIcon) {
                IconButton(onClick = navigateToSettings) {
                    Icon(
                        imageVector = Icons.Filled.Settings,
                        contentDescription = null
                    )
                }
            }
        },
    )
}