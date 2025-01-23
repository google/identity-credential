package com.android.identity_credential.wallet.ui.prompt.consent

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.ui.platform.ComposeView
import androidx.fragment.app.FragmentActivity
import com.android.identity.request.Claim
import com.android.identity.appsupport.ui.consent.ConsentModalBottomSheet
import com.android.identity.appsupport.ui.consent.ConsentDocument
import com.android.identity.request.Request
import com.android.identity.request.Requester
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
    document: ConsentDocument,
    request: Request,
    trustPoint: TrustPoint?
): Boolean =
    suspendCancellableCoroutine { continuation ->
        // new instance of the ConsentPrompt bottom sheet dialog fragment but not shown yet
        val consentPrompt = ConsentPrompt(
            request = request,
            trustPoint = trustPoint,
            document = document,
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
    private val request: Request,
    private val trustPoint: TrustPoint?,
    private val document: ConsentDocument,
    private val onConsentPromptResult: (Boolean) -> Unit,
) : BottomSheetDialogFragment() {
    /**
     * Define the composable [ConsentModalBottomSheet] and issue callbacks to [onConsentPromptResult]
     * based on which button is tapped.
     */
    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View =
        ComposeView(requireContext()).apply {
            setContent {
                IdentityCredentialTheme {
                    // TODO: use sheetGesturesEnabled=false when available instead of confirmValueChanged
                    //  hack - see https://issuetracker.google.com/issues/288211587 for details
                    //
                    val sheetState = rememberModalBottomSheetState(
                        skipPartiallyExpanded = true,
                        confirmValueChange = { it != SheetValue.Hidden }
                    )

                    // define the ConsentPromptComposable (and show)
                    ConsentModalBottomSheet(
                        sheetState = sheetState,
                        request = request,
                        document = document,
                        trustPoint = trustPoint,
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