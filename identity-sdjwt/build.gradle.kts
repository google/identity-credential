plugins {
    id("java-library")
    id("org.jetbrains.kotlin.jvm")
}

kotlin {
    jvmToolchain(17)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":identity"))
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.io.bytestring)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.bouncy.castle.bcprov)
    testImplementation(libs.bouncy.castle.bcpkix)
    testImplementation(libs.kotlinx.coroutine.test)
}
