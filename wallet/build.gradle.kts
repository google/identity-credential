plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.jetbrainsCompose)
    id("kotlin-android")
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "com.android.identity_credential.wallet"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "com.android.identity_credential.wallet"
        minSdk = 27
        targetSdk = libs.versions.android.targetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            setProguardFiles(
                listOf(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro"
                )
            )
        }
    }

    flavorDimensions.addAll(listOf("standard"))
    productFlavors {
        create("upstream") {
            dimension = "standard"
            isDefault = true
        }
        create("customized") {
            dimension = "standard"
            applicationId = "com.example.wallet.customized"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += listOf("/META-INF/{AL2.0,LGPL2.1}")
            excludes += listOf("/META-INF/versions/9/OSGI-INF/MANIFEST.MF")
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation(project(":processor-annotations"))
    implementation(project(":identity"))
    implementation(project(":identity-doctypes"))
    implementation(project(":identity-mdoc"))
    implementation(project(":identity-sdjwt"))
    implementation(project(":identity-flow"))
    implementation(project(":identity-android"))
    implementation(project(":identity-issuance"))
    implementation(project(":mrtd-reader"))
    implementation(project(":mrtd-reader-android"))
    implementation(project(":jpeg2k"))

    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.io.core)
    implementation(libs.kotlinx.io.bytestring)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.net.sf.scuba.scuba.sc.android)
    implementation(libs.org.jmrtd.jmrtd)
    implementation(libs.ausweis.sdk)

    implementation(compose.runtime)
    implementation(compose.foundation)
    implementation(compose.material)
    implementation(compose.ui)
    implementation(compose.components.resources)
    implementation(compose.components.uiToolingPreview)
    implementation(compose.material)

    debugImplementation(compose.uiTooling)
    implementation(compose.preview)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.biometrics)
    implementation(compose.material3)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.androidx.navigation.runtime)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.compose.runtime.livedata)
    implementation(libs.accompanist.permissions)
    implementation(libs.androidx.work)
    implementation(libs.nimbus.oauth2.oidc.sdk)
    implementation(libs.androidx.camera.view)
    implementation(libs.androidx.material)
    implementation(libs.zxing.core)

    implementation(files("../third-party/play-services-identity-credentials-0.0.1-eap01.aar"))
    implementation(libs.bundles.google.play.services)

    implementation(libs.bouncy.castle.bcprov)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutine.test)
    testImplementation(libs.ktor.client.mock)

    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.compose.junit4)
    debugImplementation(libs.compose.test.manifest)
}
