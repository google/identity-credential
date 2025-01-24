package com.android.identity.wallet.documentinfo

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.android.identity.wallet.HolderApp
import com.android.identity.wallet.composables.toCardArt
import com.android.identity.wallet.document.DocumentInformation
import com.android.identity.wallet.document.DocumentManager
import com.android.identity.wallet.fragment.DocumentDetailFragmentArgs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DocumentInfoViewModel(
    private val documentManager: DocumentManager,
    savedStateHandle: SavedStateHandle
) : ViewModel() {

    private val args = DocumentDetailFragmentArgs.fromSavedStateHandle(savedStateHandle)
    private val _state = MutableStateFlow(DocumentInfoScreenState())
    val screenState: StateFlow<DocumentInfoScreenState> = _state.asStateFlow()

    fun loadDocument(documentName: String) {
        _state.update { it.copy(isLoading = true) }
        viewModelScope.launch {
            val documentInfo = withContext(Dispatchers.IO) {
                documentManager.getDocumentInformation(documentName)
            }
            onDocumentInfoLoaded(documentInfo)
        }
    }

    fun promptDocumentDelete() {
        _state.update { it.copy(isDeletingPromptShown = true) }
    }

    fun confirmDocumentDelete() {
        documentManager.deleteDocumentByName(args.documentName)
        _state.update { it.copy(isDeleted = true, isDeletingPromptShown = false) }
    }

    fun cancelDocumentDelete() {
        _state.update { it.copy(isDeletingPromptShown = false) }
    }

    fun refreshCredentials() {
        _state.update { it.copy(isLoading = true) }
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                documentManager.refreshCredentials(args.documentName)
            }
            loadDocument(args.documentName)
        }
    }

    private fun onDocumentInfoLoaded(documentInformation: DocumentInformation?) {
        documentInformation?.let {
            _state.update {
                it.copy(
                    isLoading = false,
                    documentName = documentInformation.userVisibleName,
                    documentType = documentInformation.docType,
                    documentColor = documentInformation.documentColor.toCardArt(),
                    provisioningDate = documentInformation.dateProvisioned,
                    isSelfSigned = documentInformation.selfSigned,
                    lastTimeUsedDate = documentInformation.lastTimeUsed,
                    authKeys = documentInformation.authKeys.asScreenStateKeys(),
                    daKeys = documentInformation.daCreds.asScreenStateDaKeys()
                )
            }
        }
    }

    private fun List<DocumentInformation.KeyData>.asScreenStateKeys(): List<DocumentInfoScreenState.KeyInformation> {
        return map { keyData ->
            DocumentInfoScreenState.KeyInformation(
                counter = keyData.counter,
                validFrom = keyData.validFrom,
                validUntil = keyData.validUntil,
                domain = keyData.domain,
                issuerDataBytesCount = keyData.issuerDataBytesCount,
                usagesCount = keyData.usagesCount,
                keyPurposes = keyData.keyPurposes,
                ecCurve = keyData.ecCurve,
                isHardwareBacked = keyData.isHardwareBacked,
                secureAreaDisplayName = keyData.secureAreaDisplayName
            )
        }
    }

    private fun List<DocumentInformation.DirectAccessCredInfo>.asScreenStateDaKeys(): List<DocumentInfoScreenState.DaKeyInformation> {
        return map { keyData ->
            DocumentInfoScreenState.DaKeyInformation(
                counter = keyData.counter,
                validFrom = keyData.validFrom,
                validUntil = keyData.validUntil,
                domain = keyData.domain,
                issuerDataBytesCount = keyData.issuerDataBytesCount,
                usagesCount = keyData.usagesCount,
                secureAreaDisplayName = keyData.secureAreaDisplayName
            )
        }
    }

    companion object {
        fun Factory(documentManager: DocumentManager): ViewModelProvider.Factory =
            viewModelFactory {
                initializer {
                    DocumentInfoViewModel(documentManager, createSavedStateHandle())
                }
            }
    }
}
