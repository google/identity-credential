rootProject.name = "IdentityCredential"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        maven("https://jitpack.io") {
            mavenContent {
                includeGroup("com.github.yuriy-budiyev")
            }
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version("0.9.0")
}

include(":processor")
include(":processor-annotations")
include(":identity")
include(":identity:SwiftBridge")
include(":identity-flow")
include(":identity-mdoc")
include(":identity-sdjwt")
include(":identity-doctypes")
include(":identity-android")
include(":identity-issuance")
include(":identity-issuance-api")
include(":identity-appsupport")
include(":identity-csa")
include(":identity-android-csa")
include(":identity-android-legacy")
include(":identityctl")
include(":mrtd-reader")
include(":mrtd-reader-android")
include(":jpeg2k")
include(":samples:testapp")
include(":samples:preconsent-mdl")
include(":samples:age-verifier-mdl")
include(":samples:simple-verifier")
include(":wallet")
include(":server")
include(":appverifier")
include(":server-env")
include(":server-openid4vci")
