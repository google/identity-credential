package com.android.identity.wallet

import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.nfc.NfcAdapter
import android.os.Bundle
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.GravityCompat
import androidx.navigation.Navigation
import androidx.navigation.findNavController
import androidx.navigation.ui.NavigationUI
import androidx.navigation.ui.NavigationUI.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import com.android.identity.android.direct_access.DirectAccess
import com.android.identity.mdoc.origininfo.OriginInfo
import com.android.identity.mdoc.origininfo.OriginInfoDomain
import com.android.identity.util.AndroidInitializer
import com.android.identity.util.Logger
import com.android.identity.wallet.databinding.ActivityMainBinding
import com.android.identity.wallet.util.PreferencesHelper
import com.android.identity.wallet.document.DocumentManager
import com.android.identity.wallet.dynamicregistration.AidRegistrationUtil
import com.android.identity.wallet.util.log
import com.android.identity.wallet.util.logError
import com.android.identity.wallet.util.logInfo
import com.android.identity.wallet.util.logWarning
import com.android.identity.wallet.viewmodel.ShareDocumentViewModel
import com.google.android.material.elevation.SurfaceColors

class MainActivity : AppCompatActivity() {

    private val viewModel: ShareDocumentViewModel by viewModels()
    private lateinit var binding: ActivityMainBinding
    private lateinit var pendingIntent: PendingIntent
    private var nfcAdapter: NfcAdapter? = null

    private val navController by lazy {
        Navigation.findNavController(this, R.id.nav_host_fragment)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AndroidInitializer.initialize(applicationContext)
        DirectAccess.warmupTransport()
        val color = SurfaceColors.SURFACE_2.getColor(this)
        window.statusBarColor = color
        window.navigationBarColor = color
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        DocumentManager.getInstance(this).registerDocuments()
        setupDrawerLayout()
        setupNfc()
        onNewIntent(intent)
        Logger.isDebugEnabled = PreferencesHelper.isDebugLoggingEnabled()
        // route aids to host by default
        AidRegistrationUtil.routeAidsToHost(this)
    }

    private fun setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        // Create a generic PendingIntent that will be deliver to this activity. The NFC stack
        // will fill in the intent with the details of the discovered tag before delivering to
        // this activity.
        val intent = Intent(this, javaClass).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
    }

    private fun setupDrawerLayout() {
        binding.nvSideDrawer.setupWithNavController(navController)
        setupActionBarWithNavController(this, navController, binding.dlMainDrawer)
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        log("New intent on Activity $intent")

        if (intent == null) {
            return
        }

        var mdocUri: String? = null
        var mdocReferrerUri: String? = null
        if (intent.scheme.equals("mdoc")) {
            val uri = Uri.parse(intent.toUri(0))
            mdocUri = "mdoc://" + uri.authority

            mdocReferrerUri = intent.extras?.get(Intent.EXTRA_REFERRER)?.toString()
        }

        if (mdocUri == null) {
            logError("No mdoc:// URI")
            return
        }
        logInfo("uri: $mdocUri")

        val originInfos = ArrayList<OriginInfo>()
        if (mdocReferrerUri == null) {
            logWarning("No referrer URI")
            // TODO: maybe bail in the future if this isn't set.
        } else {
            logInfo("referrer: $mdocReferrerUri")
            originInfos.add(
                OriginInfoDomain(
                    mdocReferrerUri
                )
            )
        }

        viewModel.startPresentationReverseEngagement(mdocUri, originInfos)
        val navController = findNavController(R.id.nav_host_fragment)
        navController.navigate(R.id.transferDocumentFragment)
    }

    override fun onSupportNavigateUp(): Boolean {
        return NavigationUI.navigateUp(navController, binding.dlMainDrawer)
    }

    override fun onBackPressed() {
        if (binding.dlMainDrawer.isDrawerOpen(GravityCompat.START)) {
            binding.dlMainDrawer.closeDrawer(GravityCompat.START)
        } else {
            super.onBackPressed()
        }
    }
}