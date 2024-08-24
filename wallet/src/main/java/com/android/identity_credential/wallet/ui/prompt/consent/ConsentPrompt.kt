package com.android.identity_credential.wallet.ui.prompt.consent

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.platform.ComposeView
import androidx.fragment.app.FragmentActivity
import com.android.identity.trustmanagement.TrustPoint
import com.android.identity_credential.wallet.ui.theme.IdentityCredentialTheme
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Show the Consent prompt
 *
 * Async function that renders the Consent Prompt (Composable) from a Dialog Fragment.
 * Returns a [Boolean] identifying that user tapped on Confirm or Cancel button.
 */
suspend fun showConsentPrompt(
    activity: FragmentActivity,
    documentName: String,
    consentFields: List<ConsentField>,
    trustPoint: TrustPoint?
): Boolean =
    suspendCancellableCoroutine { continuation ->
        // new instance of the ConsentPrompt bottom sheet dialog fragment but not shown yet
        val consentPrompt = ConsentPrompt(
            consentFields = consentFields,
            documentName = documentName,
            verifier = trustPoint,
            onConsentPromptResult = { promptWasSuccessful ->
                continuation.resume(promptWasSuccessful)
            }
        )
        // show the consent prompt fragment
        consentPrompt.show(activity.supportFragmentManager, "consent_prompt")
    }

/**
 * ConsentPrompt Dialog Fragment class that renders Consent prompt via Composition for the purposes
 * of running Consent Prompt synchronously and return the prompt's result as a [Boolean] rather than
 * deal with callback hell.
 *
 * Extends [BottomSheetDialogFragment] and shows up as an overlay above the current UI.
 */
class ConsentPrompt(
    private val consentFields: List<ConsentField>,
    private val documentName: String,
    private val verifier: TrustPoint?,
    private val onConsentPromptResult: (Boolean) -> Unit,
) : BottomSheetDialogFragment() {
    /**
     * Define the composable [ConsentPromptEntryField] and issue callbacks to [onConsentPromptResult]
     * based on which button is tapped.
     */
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View =
        ComposeView(requireContext()).apply {
            setContent {
                IdentityCredentialTheme {
                    // define the ConsentPromptComposable (and show)
                    ConsentPromptEntryField(
                        consentFields = consentFields,
                        documentName = documentName,
                        verifier = verifier,
                        // user accepted to send requested credential data
                        onConfirm = {
                            // notify that the user tapped on the 'Confirm' button
                            onConsentPromptResult.invoke(true)
                            dismiss()
                        },
                        // user declined submitting data to requesting party
                        onCancel = {
                            // notify that the user tapped on the 'Cancel' button
                            onConsentPromptResult.invoke(false)
                            dismiss()
                        }
                    )
                }
            }
        }
}