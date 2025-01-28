package com.android.identity.server

import com.android.identity.flow.handler.FlowNotifications
import com.android.identity.flow.server.Configuration
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.Resources
import com.android.identity.securearea.SecureAreaProvider
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.Storage
import com.android.identity.storage.jdbc.JdbcStorage
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import java.io.File
import kotlin.reflect.KClass
import kotlin.reflect.cast

internal class ServerEnvironment(
    servletConfiguration: Configuration,
    environmentInitializer: (env: FlowEnvironment) -> FlowNotifications? = { null }
) : FlowEnvironment {
    private val configuration: Configuration = object : Configuration {
        override fun getValue(key: String): String? {
            return servletConfiguration.getValue(key) ?: CommonConfiguration.getValue(key)
        }
    }
    private var notifications: FlowNotifications? = environmentInitializer(this)

    override fun <T : Any> getInterface(clazz: KClass<T>): T? {
        return clazz.cast(when(clazz) {
            Configuration::class -> configuration
            Resources::class -> ServerResources
            Storage::class -> storage
            FlowNotifications::class -> notifications
            HttpClient::class -> httpClient
            SecureAreaProvider::class -> secureAreaProvider
            else -> return null
        })
    }
}

private val storage = JdbcStorage(
    CommonConfiguration.getValue("databaseConnection") ?: defaultDatabase(),
    CommonConfiguration.getValue("databaseUser") ?: "",
    CommonConfiguration.getValue("databasePassword") ?: ""
)

fun defaultDatabase(): String {
    val dbFile = File("environment/db/db.hsqldb").absoluteFile
    if (!dbFile.canRead()) {
        val parent = File(dbFile.parent)
        if (!parent.exists()) {
            if (!parent.mkdirs()) {
                throw Exception("Cannot create database folder ${parent.absolutePath}")
            }
        }
    }
    return "jdbc:hsqldb:file:${dbFile.absolutePath}"
}

private val httpClient = HttpClient(Java) {
    followRedirects = false
}

private val secureAreaProvider = SecureAreaProvider {
    SoftwareSecureArea.create(storage)
}

