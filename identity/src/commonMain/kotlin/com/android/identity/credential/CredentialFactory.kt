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
package com.android.identity.credential

import com.android.identity.cbor.DataItem
import com.android.identity.document.Document
import kotlin.reflect.KClass

/**
 * A class that aids in creation of credentials from serialized data.
 *
 * The [CredentialFactory] is initially empty, but in the
 * [com.android.identity.credential] package, there are well known [Credential] implementations
 * which can be added using the [addCredentialImplementation] method. In addition,
 * applications may add their own [Credential] implementations.
 */
class CredentialFactory {
    private val createCredentialFunctions:
            MutableMap<String, (Document, DataItem) -> Credential> = mutableMapOf()

    /**
     * Add a new [Credential] implementation to the repository.
     *
     * @param credentialType the credential type
     * @param createCredentialFunction a function to create a [Credential] of the given type.
     */
    fun addCredentialImplementation(
        credentialType: KClass<out Credential>,
        createCredentialFunction: (Document, DataItem) -> Credential
    ) = createCredentialFunctions.put(credentialType.simpleName!!, createCredentialFunction)

    /**
     * Creates a [Credential] from serialized data.
     *
     * @param document The document associated with the credential
     * @param dataItem The serialized credential
     * @return a credential instance
     * @throws IllegalStateException if there is no registered type for the serialized data.
     */
    fun createCredential(document: Document, dataItem: DataItem): Credential {
        val credentialType = dataItem["credentialType"].asTstr
        val createCredentialFunction = createCredentialFunctions.get(credentialType)
        if (createCredentialFunction == null) {
            throw IllegalStateException("Credential type $credentialType not registered")
        }
        return createCredentialFunction.invoke(document, dataItem)
    }
}