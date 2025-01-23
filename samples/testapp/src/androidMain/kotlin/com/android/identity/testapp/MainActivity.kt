package com.android.identity.testapp

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import androidx.fragment.app.FragmentActivity
import com.android.identity.util.AndroidContexts
import com.android.identity.util.Logger
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class MainActivity : FragmentActivity() {

    companion object {
        private const val TAG = "MainActivity"

        private var bcInitialized = false

        fun initBouncyCastle() {
            if (bcInitialized) {
                return
            }
            // This is needed to prefer BouncyCastle bundled with the app instead of the Conscrypt
            // based implementation included in the OS itself.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())
            bcInitialized = true
        }

        init {
            initBouncyCastle()
        }
    }

    private val app = App()

    override fun onResume() {
        super.onResume()
        AndroidContexts.setCurrentActivity(this)
    }

    override fun onPause() {
        super.onPause()
        AndroidContexts.setCurrentActivity(null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        initBouncyCastle()

        setContent {
            app.Content()
        }
    }
}

private val previewApp: App by lazy { App() }

@Preview
@Composable
fun AppAndroidPreview() {
    previewApp.Content()
}