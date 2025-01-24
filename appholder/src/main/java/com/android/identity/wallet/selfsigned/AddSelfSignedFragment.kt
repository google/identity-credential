package com.android.identity.wallet.selfsigned

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.platform.ComposeView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.android.identity.wallet.theme.HolderAppTheme

class AddSelfSignedFragment : Fragment() {

    private val viewModel: AddSelfSignedViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return ComposeView(requireContext()).apply {
            setContent {
                HolderAppTheme {
                    AddSelfSignedDocumentScreen(
                        viewModel = viewModel,
                        onNext = { onNext() }
                    )
                }
            }
        }
    }

    private fun onNext() {
        val state = viewModel.screenState.value
        val secureAreaScreenState = requireNotNull(state.secureAreaSupportState)
        val provisionInfo = ProvisionInfo(
            docType = state.documentType,
            docName = state.documentName,
            docColor = state.cardArt.value,
            currentSecureArea = state.currentSecureArea,
            secureAreaSupportState = secureAreaScreenState,
            validityInDays = state.validityInDays,
            minValidityInDays = state.minValidityInDays,
            numberMso = state.numberOfMso,
            maxUseMso = state.maxUseOfMso,
            provisionDirectAccess = state.provisionDirectAccessCredential,
        )
        val destination = AddSelfSignedFragmentDirections
            .actionAddSelfSignedToSelfSignedDetails(provisionInfo)
        findNavController().navigate(destination)
    }
}