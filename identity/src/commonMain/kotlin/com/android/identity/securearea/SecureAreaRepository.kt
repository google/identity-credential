/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.securearea

import com.android.identity.util.Logger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.CoroutineContext

/**
 * A repository of [SecureArea] implementations.
 *
 * This is used by to provide fine-grained control for which [SecureArea]
 * implementation to use when loading keys and objects using different implementations.
 *
 *
 * can be used for Secure Areas where it's possible to have multiple instances. For
 * example for a [CloudSecureArea] the URL of the server is part of the identifier e.g.
 * `CloudSecureArea?id=SOME_UNIQUE_ID&url=https://csa.example.com/server`. An application
 * can use this method to register a factory for establishing a connection to the
 * requested URL and configure the instance as needed. Key to the map is Secure Area
 * identifier prefix of the Secure Area identifier up until the '?' character.
 * @param factoryFunc a function to create a new Secure Area with the requested identifier.
 *
 */
class SecureAreaRepository private constructor(
    private val holder: Deferred<SecureAreaHolder>
) {
    /**
     * Gets a [SecureArea] by identifier
     *
     * The identifier being used is the one returned by [SecureArea.identifier].
     *
     * @param identifier the identifier for the Secure Area.
     * @return the implementation or `null` if no implementation has been registered.
     */
    suspend fun getImplementation(identifier: String): SecureArea? {
        val holder = this.holder.await()
        val secureAreaDeferred = holder.lock.withLock {
            val existing = holder.secureAreaByIdentifier[identifier]
            if (existing != null) {
                existing
            } else {
                val questionMarkLocation = identifier.indexOf('?')
                if (questionMarkLocation == -1) {
                    return null
                }
                val identifierPrefix = identifier.substring(0, questionMarkLocation)
                val factoryFunc = holder.implementationFactories[identifierPrefix] ?: return null
                val deferred = CoroutineScope(holder.context).async {
                    // NB: lock is not held in this scope!
                    val newSecureArea = factoryFunc(identifier)
                    if (newSecureArea != null && identifier != newSecureArea.identifier) {
                        Logger.e(TAG, "Requested identifier `$identifier` got `${newSecureArea.identifier}`")
                    }
                    newSecureArea
                }
                holder.secureAreaByIdentifier[identifier] = deferred
                deferred
            }
        }
        return secureAreaDeferred.await()
    }

    internal class SecureAreaHolder(
        internal val context: CoroutineContext,
        // protected by lock
        internal val secureAreaByIdentifier: MutableMap<String, Deferred<SecureArea?>>,
        internal val implementationFactories: Map<String, suspend (String) -> SecureArea?>
    ) {
        internal val lock = Mutex()
    }

    class Builder(private val context: CoroutineContext) {
        private val byIdentifier = mutableMapOf<String, Deferred<SecureArea?>>()
        private val factories = mutableMapOf<String, suspend (String) -> SecureArea?>()

        fun addFactory(identifierPrefix: String, factory: suspend (String) -> SecureArea?) {
            if (factories.contains(identifierPrefix)) {
                throw IllegalArgumentException("Duplicate SecureArea factory: $identifierPrefix")
            }
            factories[identifierPrefix] = factory
        }

        fun add(secureArea: SecureArea) {
            if (byIdentifier.contains(secureArea.identifier)) {
                throw IllegalArgumentException("Duplicate SecureArea: ${secureArea.identifier}")
            }
            byIdentifier[secureArea.identifier] = CompletableDeferred(secureArea)
        }

        internal fun build(): SecureAreaHolder {
            return SecureAreaHolder(context, byIdentifier, factories.toMap())
        }
    }

    companion object {
        private const val TAG = "SecureAreaRepository"

        fun build(
            context: CoroutineContext = Dispatchers.Default,
            block: suspend Builder.() -> Unit
        ): SecureAreaRepository {
            val builder = Builder(context)
            return SecureAreaRepository(CoroutineScope(context).async {
                builder.block()
                builder.build()
            })
        }
    }
}