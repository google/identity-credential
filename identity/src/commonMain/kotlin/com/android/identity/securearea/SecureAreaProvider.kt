package com.android.identity.securearea

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlin.coroutines.CoroutineContext

/**
 * Lazily creates a [SecureArea].
 *
 * [SecureArea] creation is typically asynchronous and cannot be completed in a
 * synchronous scopes (such as at static initialization or callbacks like `onCreate`).
 * This class provides a wrapper to hold an asynchronously-created [SecureArea]. To create
 * a [SecureArea] in synchronous context, use
 * ```
 * // synchronous initialization code
 * val fooSecureAreaProvider = SecureAreaProvider { FooSecureArea.create(storage, ...) }
 * ```
 *
 * Then when using secure area in an asynchronous context (which is required as [SecureArea] APIs
 * are asynchronous):
 * ```
 * // asynchronous code
 * val fooSecureArea = fooSecureAreaProvider.get()
 * fooSecureArea.someApiCall()
 * ```
 */
class SecureAreaProvider<out T: SecureArea>(
    context: CoroutineContext = Dispatchers.Main,
    provider: suspend CoroutineScope.() -> T
) {
    private val deferred: Deferred<T> =
        CoroutineScope(context).async(context, CoroutineStart.LAZY, provider)

    suspend fun get(): T = deferred.await()
}