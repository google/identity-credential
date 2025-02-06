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
package com.android.identity.document

import com.android.identity.credential.Credential
import kotlinx.datetime.Instant;

/**
 * A set of utilities and helpers for working with documents.
 */
object DocumentUtil {
    private const val TAG = "DocumentUtil"

    /**
     * A helper for managing a set of [Credential]s.
     *
     * This helper provides a high-level way to manage credentials on a
     * [Document]. Its goal is to always have a fixed number of
     * credentials of a specific type available within the following constraints
     *
     * - If a credential is used more than `maxUsesPerCredential` times, a replacement is generated.
     * - If a credential expires within `minValidTimeMillis` milliseconds, a replacement is generated.
     *
     * This is all implemented on top of [Credential] creation
     * and [Credential.certify]. The application should examine the return
     * value and if positive, collect the not-yet-certified credentials via
     * [Document.pendingCredentials], send them to the issuer for certification,
     * and then call [Credential.certify] when receiving the certification
     * from the issuer.
     *
     * @param document the document to manage credentials for.
     * @param domain the domain to use for created credentials.
     * @param createCredential a lambda for creating the credential which only takes in an optional
     * parameter for a replacement credential. This must not be null if dryRun is false.
     * @param now the time right now, used for determining which existing credentials to replace.
     * @param numCredentials the number of credentials that should be kept.
     * @param maxUsesPerCredential the maximum number of uses per credential.
     * @param minValidTimeMillis requests a replacement for a credential if it expires within this window.
     * @param dryRun don't actually create the credentials, just return how many would be created.
     * @return the number of credentials created.
     */
    suspend fun managedCredentialHelper(
        document: Document,
        domain: String,
        createCredential: (suspend (credentialIdentifierToReplace: String?) -> Credential)?,
        now: Instant,
        numCredentials: Int,
        maxUsesPerCredential: Int,
        minValidTimeMillis: Long,
        dryRun: Boolean
    ): Int {
        check(dryRun || createCredential != null)
        // First determine which of the existing credentials need a replacement...
        var numCredentialsNotNeedingReplacement = 0
        var numReplacementsGenerated = 0
        for (authCredential in document.getCertifiedCredentialsForDomain(domain)) {
            var credentialExceededUseCount = false
            var credentialBeyondExpirationDate = false
            if (authCredential.usageCount >= maxUsesPerCredential) {
                credentialExceededUseCount = true
            }
            val expirationDate = Instant.fromEpochMilliseconds(
                authCredential.validUntil.toEpochMilliseconds() - minValidTimeMillis
            )
            if (now > expirationDate) {
                credentialBeyondExpirationDate = true
            }
            if (credentialExceededUseCount || credentialBeyondExpirationDate) {
                val replacement = document.getReplacementCredentialFor(authCredential.identifier)
                if (replacement == null) {
                    if (!dryRun) {
                        createCredential!!.invoke(authCredential.identifier)
                    }
                    numReplacementsGenerated++
                    continue
                }
            }
            numCredentialsNotNeedingReplacement++
        }

        var numExistingPendingCredentials = document.getPendingCredentialsForDomain(domain).size
        if (dryRun) {
            numExistingPendingCredentials += numReplacementsGenerated
        }

        // It's possible we need to generate pending credentials that aren't replacements
        val numNonReplacementsToGenerate = (numCredentials
                - numCredentialsNotNeedingReplacement
                - numExistingPendingCredentials)

        if (!dryRun) {
            if (numNonReplacementsToGenerate > 0) {
                for (n in 0 until numNonReplacementsToGenerate) {
                    createCredential!!.invoke(null)
                }
            }
        }

        return numReplacementsGenerated + numNonReplacementsToGenerate
    }
}
