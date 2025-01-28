package com.android.identity.issuance.remote

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Handler
import androidx.annotation.RawRes
import com.android.identity.device.DeviceAssertionMaker
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.Resources
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.handler.FlowNotifications
import com.android.identity.issuance.ApplicationSupport
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.storage.Storage
import com.android.identity.storage.android.AndroidStorage
import com.android.identity_credential.wallet.R
import com.android.identity_credential.wallet.SettingsModel
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import kotlin.reflect.KClass
import kotlin.reflect.cast


/**
 * This implementation of [FlowEnvironment] can be used to run wallet server locally in the app,
 * which is useful for development, but should never be done in production.
 */
internal class LocalDevelopmentEnvironment(
    context: Context,
    settingsModel: SettingsModel,
    private val assertionMaker: DeviceAssertionMaker,
    private val secureAreaProvider: SecureAreaProvider<SecureArea>,
    private val notifications: FlowNotifications,
    private val applicationSupportSupplier: WalletServerProvider.ApplicationSupportSupplier
) : FlowEnvironment {
    private var configuration = ConfigurationImpl(context, settingsModel)
    private val storage = AndroidStorage(
        File(context.dataDir, "local_dev.db").absolutePath
    )
    private val resources = ResourcesImpl(context)
    private val httpClient = HttpClient(Android) {
        followRedirects = false
    }

    init {
        Handler(context.mainLooper).post {
            settingsModel.cloudSecureAreaUrl.observeForever {
                // this signals config change
                configuration = ConfigurationImpl(context, settingsModel)
            }
        }
    }

    override fun <T : Any> getInterface(clazz: KClass<T>): T? {
        return clazz.cast(when(clazz) {
            Configuration::class -> configuration
            Resources::class -> resources
            Storage::class -> storage
            FlowNotifications::class -> notifications
            HttpClient::class -> httpClient
            SecureAreaProvider::class -> secureAreaProvider
            DeviceAssertionMaker::class -> assertionMaker
            ApplicationSupport::class -> runBlocking {
                // We do not want to attempt to obtain applicationSupport ahead of time
                // as there may be connection problems and we want to deal with them only
                // if we have to, thus runBlocking is used. But this code is only used for
                // "dev:" Wallet Server.
                applicationSupportSupplier.getApplicationSupport().applicationSupport
            }
            else -> return null
        })
    }

    class ConfigurationImpl(val context: Context, val settingsModel: SettingsModel): Configuration {
        override fun getValue(key: String): String? {
            val value = when (key) {
                "developerMode" -> "true"
                "waitForNotificationSupported" -> "false"
                "androidRequireGmsAttestation" -> "false"
                "androidRequireVerifiedBootGreen" -> "false"
                "androidRequireAppSignatureCertificateDigests" -> ""
                "issuingAuthorityList" -> "utopia_local utopia_local_pid utopia_local_photoid"
                "issuingAuthority.utopia_local.name" -> "Utopia DMV (Local)"
                "issuingAuthority.utopia_local.type" -> "DrivingLicense"
                "issuingAuthority.utopia_local.description" -> "Utopia Driver's License (Local)"
                "issuingAuthority.utopia_local.logo" -> "utopia_local/logo.png"
                "issuingAuthority.utopia_local.cardArt" -> "utopia_local/card_art.png"
                "issuingAuthority.utopia_local.requireUserAuthenticationToViewDocument" -> "false"
                "issuingAuthority.utopia_local_pid.name" -> "Utopia Gov (Local)"
                "issuingAuthority.utopia_local_pid.type" -> "EuPid"
                "issuingAuthority.utopia_local_pid.description" -> "Utopia Personal ID (Local)"
                "issuingAuthority.utopia_local_pid.logo" -> "utopia_local_pid/logo.png"
                "issuingAuthority.utopia_local_pid.cardArt" -> "utopia_local_pid/card_art.png"
                "issuingAuthority.utopia_local_pid.requireUserAuthenticationToViewDocument" -> "false"
                "issuingAuthority.utopia_local_photoid.name" -> "Utopia Gov (Local)"
                "issuingAuthority.utopia_local_photoid.type" -> "PhotoId"
                "issuingAuthority.utopia_local_photoid.description" -> "Utopia Photo ID (Local)"
                "issuingAuthority.utopia_local_photoid.logo" -> "utopia_local_photoid/logo.png"
                "issuingAuthority.utopia_local_photoid.cardArt" -> "utopia_local_photoid/card_art.png"
                "issuingAuthority.utopia_local_photoid.requireUserAuthenticationToViewDocument" -> "false"
                "cloudSecureAreaUrl" -> settingsModel.cloudSecureAreaUrl.value
                else -> null
            }
            return value
        }

    }

    class ResourcesImpl(val context: Context): Resources {
        override fun getRawResource(name: String): ByteString? {
            return when(name) {
                "experiment_icon.svg" ->
                    ByteString(getRawResourceAsBytes(R.raw.experiment_icon))
                "utopia_local/card_art.png" ->
                    bitmapData(
                        R.drawable.utopia_driving_license_card_art,
                        Bitmap.CompressFormat.PNG
                    )
                "utopia_local_pid/card_art.png" ->
                    bitmapData(
                        R.drawable.utopia_pid_card_art,
                        Bitmap.CompressFormat.PNG
                    )
                "utopia_local_photoid/card_art.png" ->
                    bitmapData(
                        R.drawable.utopia_photoid_card_art,
                        Bitmap.CompressFormat.PNG
                    )
                "utopia_local/logo.png" ->
                    bitmapData(
                        R.drawable.utopia_dmv_issuing_authority_logo,
                        Bitmap.CompressFormat.PNG
                    )
                "utopia_local_pid/logo.png" ->
                    bitmapData(
                        R.drawable.utopia_pid_issuing_authority_logo,
                        Bitmap.CompressFormat.PNG
                    )
                "utopia_local_photoid/logo.png" ->
                    bitmapData(
                        R.drawable.utopia_pid_issuing_authority_logo,
                        Bitmap.CompressFormat.PNG
                    )
                "funke/card_art_funke_generic.png"  ->
                    bitmapData(
                        R.drawable.card_art_funke_generic,
                        Bitmap.CompressFormat.PNG
                    )
                "funke/card_art_funke_mdoc_c.png"  ->
                    bitmapData(
                        R.drawable.card_art_funke_mdoc_c,
                        Bitmap.CompressFormat.PNG
                    )
                "funke/card_art_funke_mdoc_c1.png"  ->
                    bitmapData(
                        R.drawable.card_art_funke_mdoc_c1,
                        Bitmap.CompressFormat.PNG
                    )
                "funke/card_art_funke_sdjwt_c.png"  ->
                    bitmapData(
                        R.drawable.card_art_funke_sdjwt_c,
                        Bitmap.CompressFormat.PNG
                    )
                "funke/card_art_funke_sdjwt_c1.png"  ->
                    bitmapData(
                        R.drawable.card_art_funke_sdjwt_c1,
                        Bitmap.CompressFormat.PNG
                    )
                "funke/logo.png" -> bitmapData(
                    R.drawable.funke_logo,
                    Bitmap.CompressFormat.PNG
                )
                "generic/card_art.png" -> bitmapData(
                    R.drawable.card_art_generic,
                    Bitmap.CompressFormat.PNG
                )
                "img_erika_portrait.jpf" ->
                    ByteString(getRawResourceAsBytes(R.raw.img_erika_portrait))
                "img_erika_signature.jpf" ->
                    ByteString(getRawResourceAsBytes(R.raw.img_erika_signature))
                "img_erika_portrait.jpg" ->
                    bitmapData(
                        R.drawable.img_erika_portrait,
                        Bitmap.CompressFormat.JPEG
                    )
                "img_erika_signature.jpg" ->
                    bitmapData(
                        R.drawable.img_erika_signature,
                        Bitmap.CompressFormat.JPEG
                    )
                else -> null
            }
        }

        override fun getStringResource(name: String): String? {
            return when(name) {
                "ds_private_key.pem" -> getRawResourceAsString(R.raw.ds_private_key)
                "ds_certificate.pem" -> getRawResourceAsString(R.raw.ds_certificate)
                "cloud_secure_area/certificate.pem" ->
                    getRawResourceAsString(R.raw.csa_certificate)
                "utopia_local/tos.html" ->
                    context.resources.getString(R.string.utopia_local_issuing_authority_tos)
                "utopia_local_pid/tos.html" ->
                    context.resources.getString(R.string.utopia_local_issuing_authority_pid_tos)
                "utopia_local_photoid/tos.html" ->
                    context.resources.getString(R.string.utopia_local_issuing_authority_photoid_tos)
                "funke/tos.html" ->
                    context.resources.getString(R.string.funke_issuing_authority_tos)
                "generic/tos.html" ->
                    context.resources.getString(R.string.generic_issuing_authority_tos)
                else -> null
            }
        }

        private fun getRawResourceAsString(@RawRes resourceId: Int): String {
            return String(getRawResourceAsBytes(resourceId), StandardCharsets.UTF_8)
        }

        private fun getRawResourceAsBytes(@RawRes resourceId: Int): ByteArray {
            return context.resources.openRawResource(resourceId).readBytes()
        }

        private fun bitmapData(resourceId: Int, format: Bitmap.CompressFormat): ByteString {
            val baos = ByteArrayOutputStream()
            BitmapFactory.decodeResource(context.resources, resourceId)
                .compress(format, 90, baos)
            return ByteString(baos.toByteArray())
        }
    }
}