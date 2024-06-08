package com.android.identity_credential.wallet

/**
 * Configuration for the Wallet Application.
 *
 * This class contains configuration/settings intended to be overridden by downstream
 * consumers of this application through the flavor-system.
 *
 * This is the file with customized configuration/settings.
 */
object WalletApplicationConfiguration {
    /**
     * If `true`, the Settings screen will enable functionality to enable/disable developer mode.
     */
    const val DEVELOPER_MODE_TOGGLE_AVAILABLE = false

    /**
     * If `true`, the Settings screen will allow the user to configure the Wallet Server URL.
     */
    const val WALLET_SERVER_SETTING_AVAILABLE = false

    /**
     * The default Wallet Server URL.
     */
    const val WALLET_SERVER_DEFAULT_URL = "https://ws.example.com/server"
}