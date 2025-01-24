package com.android.identity.wallet.selfsigned

import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.android.identity.wallet.HolderApp
import com.android.identity.wallet.R
import com.android.identity.wallet.composables.CounterInput
import com.android.identity.wallet.composables.DropDownIndicator
import com.android.identity.wallet.composables.LabeledUserInput
import com.android.identity.wallet.composables.OutlinedContainerHorizontal
import com.android.identity.wallet.composables.TextDropDownRow
import com.android.identity.wallet.composables.ValueLabel
import com.android.identity.wallet.composables.gradientFor
import com.android.identity.wallet.document.DocumentColor
import com.android.identity.wallet.support.CurrentSecureArea
import com.android.identity.wallet.support.SecureAreaSupport
import com.android.identity.wallet.support.SecureAreaSupportState
import com.android.identity.wallet.support.toSecureAreaState
import com.android.identity.wallet.util.ProvisioningUtil

@Composable
fun AddSelfSignedDocumentScreen(
    viewModel: AddSelfSignedViewModel,
    onNext: () -> Unit
) {
    val screenState by viewModel.screenState.collectAsState()

    AddSelfSignedDocumentScreenContent(
        modifier = Modifier.fillMaxSize(),
        screenState = screenState,
        documentItems = viewModel.documentItems,
        onDocumentTypeChanged = viewModel::updateDocumentType,
        onCardArtSelected = viewModel::updateCardArt,
        onDocumentNameChanged = viewModel::updateDocumentName,
        onKeystoreImplementationChanged = viewModel::updateKeystoreImplementation,
        onSecureAreaSupportStateUpdated = viewModel::updateSecureAreaSupportState,
        onNumberOfMsoChanged = viewModel::updateNumberOfMso,
        onMaxUseOfMsoChanged = viewModel::updateMaxUseOfMso,
        onValidityInDaysChanged = viewModel::updateValidityInDays,
        onMinValidityInDaysChanged = viewModel::updateMinValidityInDays,
        onDirectAccessSelectionChanged = viewModel::updateDirectAccessSelected,
        onNext = onNext,
    )
}

@Composable
private fun AddSelfSignedDocumentScreenContent(
    modifier: Modifier,
    screenState: AddSelfSignedScreenState,
    documentItems: List<DocumentItem>,
    onDocumentTypeChanged: (newType: String, newName: String) -> Unit,
    onCardArtSelected: (newCardArt: DocumentColor) -> Unit,
    onDocumentNameChanged: (newValue: String) -> Unit,
    onKeystoreImplementationChanged: (newImplementation: CurrentSecureArea) -> Unit,
    onSecureAreaSupportStateUpdated: (newState: SecureAreaSupportState) -> Unit,
    onNumberOfMsoChanged: (newValue: Int) -> Unit,
    onMaxUseOfMsoChanged: (newValue: Int) -> Unit,
    onValidityInDaysChanged: (newValue: Int) -> Unit,
    onMinValidityInDaysChanged: (newValue: Int) -> Unit,
    onDirectAccessSelectionChanged: (newValue: Boolean) -> Unit,
    onNext: () -> Unit,
) {
    Scaffold(modifier = modifier) { paddingValues ->
        val scrollState = rememberScrollState()
        var directAccessRequested by remember { mutableStateOf(false) }
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .verticalScroll(scrollState),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(modifier = Modifier.fillMaxWidth())
            DocumentTypeChooser(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                documentItems = documentItems,
                currentDocumentType = screenState.documentType,
                onDocumentTypeSelected = onDocumentTypeChanged
            )
            if (HolderApp.isDirectAccessSupported) {
                Row(modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                ) {
                    Checkbox(
                        checked = directAccessRequested,
                        onCheckedChange = {
                            onDirectAccessSelectionChanged(it)
                            directAccessRequested = it
                        }
                    )
                    Text(
                        modifier = Modifier.align(Alignment.CenterVertically),
                        text = "I would like to present this document when my phone is off.",
                        fontSize = 15.sp,
                    )
                }
            }
            CardArtChooser(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                currentCardArt = screenState.cardArt,
                onCardArtSelected = onCardArtSelected
            )
            DocumentNameInput(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                value = screenState.documentName,
                onValueChanged = onDocumentNameChanged
            )
            KeystoreImplementationChooser(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                currentImplementation = screenState.currentSecureArea,
                onKeystoreImplementationChanged = onKeystoreImplementationChanged
            )
            SecureAreaSupport.getInstance(
                LocalContext.current,
                screenState.currentSecureArea
            ).SecureAreaAuthUi(onUiStateUpdated = onSecureAreaSupportStateUpdated)
            CounterInput(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                label = stringResource(id = R.string.txt_number_mso),
                value = screenState.numberOfMso,
                onValueChange = onNumberOfMsoChanged
            )
            CounterInput(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                label = stringResource(id = R.string.txt_max_use_mso),
                value = screenState.maxUseOfMso,
                onValueChange = onMaxUseOfMsoChanged
            )
            CounterInput(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                label = stringResource(id = R.string.validity_in_days),
                value = screenState.validityInDays,
                onValueChange = onValidityInDaysChanged
            )
            CounterInput(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                label = stringResource(id = R.string.minimum_validity_in_days),
                value = screenState.minValidityInDays,
                onValueChange = onMinValidityInDaysChanged
            )
            Button(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                onClick = onNext
            ) {
                Text(text = "Next")
            }
        }
    }
}

@Composable
private fun DocumentTypeChooser(
    modifier: Modifier = Modifier,
    documentItems: List<DocumentItem>,
    currentDocumentType: String,
    onDocumentTypeSelected: (newType: String, newName: String) -> Unit
) {
    LabeledUserInput(
        modifier = modifier,
        label = stringResource(id = R.string.txt_document_type)
    ) {
        var expanded by remember { mutableStateOf(false) }
        OutlinedContainerHorizontal(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = true }
        ) {
            documentItems.find {it.docType == currentDocumentType}?.let {
                ValueLabel(
                    modifier = Modifier.weight(1f),
                    label = it.displayName
                )
            }
            DropDownIndicator()
        }
        DropdownMenu(
            modifier = Modifier
                .fillMaxWidth(0.8f),
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            documentItems.forEach{
                TextDropDownRow(
                    label = it.displayName,
                    onSelected = {
                        onDocumentTypeSelected(it.docType, it.displayName)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
private fun CardArtChooser(
    modifier: Modifier,
    currentCardArt: DocumentColor,
    onCardArtSelected: (newCardArt: DocumentColor) -> Unit
) {
    LabeledUserInput(
        modifier = modifier,
        label = stringResource(id = R.string.txt_card_art)
    ) {
        var expanded by remember { mutableStateOf(false) }
        OutlinedContainerHorizontal(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = true },
            outlineBrush = gradientFor(currentCardArt)
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(gradientFor(currentCardArt), RoundedCornerShape(8.dp)),
            )
            ValueLabel(
                modifier = Modifier
                    .padding(horizontal = 12.dp)
                    .weight(1f),
                label = stringResource(id = colorNameFor(currentCardArt))
            )
            DropDownIndicator()
        }
        DropdownMenu(
            modifier = Modifier
                .fillMaxWidth(0.8f),
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            CardArtDropDownRow(
                cardArt = DocumentColor.Green,
                onSelected = {
                    onCardArtSelected(DocumentColor.Green)
                    expanded = false
                }
            )
            CardArtDropDownRow(
                cardArt = DocumentColor.Yellow,
                onSelected = {
                    onCardArtSelected(DocumentColor.Yellow)
                    expanded = false
                }
            )
            CardArtDropDownRow(
                cardArt = DocumentColor.Blue,
                onSelected = {
                    onCardArtSelected(DocumentColor.Blue)
                    expanded = false
                }
            )
            CardArtDropDownRow(
                cardArt = DocumentColor.Red,
                onSelected = {
                    onCardArtSelected(DocumentColor.Red)
                    expanded = false
                }
            )
        }
    }
}

@Composable
private fun DocumentNameInput(
    modifier: Modifier = Modifier,
    value: String,
    onValueChanged: (newValue: String) -> Unit
) {
    LabeledUserInput(
        modifier = modifier,
        label = stringResource(id = R.string.txt_document_name)
    ) {
        OutlinedContainerHorizontal(modifier = Modifier.fillMaxWidth()) {
            BasicTextField(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 10.dp),
                textStyle = MaterialTheme.typography.labelMedium.copy(
                    color = MaterialTheme.colorScheme.onSurface,
                ),
                value = value,
                onValueChange = onValueChanged,
                cursorBrush = SolidColor(MaterialTheme.colorScheme.onSurface)
            )
        }
    }
}

@Composable
private fun KeystoreImplementationChooser(
    modifier: Modifier = Modifier,
    currentImplementation: CurrentSecureArea,
    onKeystoreImplementationChanged: (newImplementation: CurrentSecureArea) -> Unit
) {
    LabeledUserInput(
        modifier = modifier,
        label = stringResource(id = R.string.txt_keystore_implementation)
    ) {
        var expanded by remember { mutableStateOf(false) }
        OutlinedContainerHorizontal(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = true }
        ) {
            ValueLabel(
                modifier = Modifier.weight(1f),
                label = currentImplementation.displayName
            )
            DropDownIndicator()
        }
        DropdownMenu(
            modifier = Modifier
                .fillMaxWidth(0.8f),
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            ProvisioningUtil.getInstance(LocalContext.current)
                .secureAreaRepository.implementations.forEach { implementation ->
                    TextDropDownRow(
                        label = implementation.displayName,
                        onSelected = {
                            onKeystoreImplementationChanged(implementation.toSecureAreaState())
                            expanded = false
                        }
                    )
                }
        }
    }
}

@Composable
private fun CardArtDropDownRow(
    modifier: Modifier = Modifier,
    cardArt: DocumentColor,
    onSelected: () -> Unit
) {
    DropdownMenuItem(
        text = {
            Row(
                modifier = modifier,
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(gradientFor(cardArt), RoundedCornerShape(8.dp)),
                )
                ValueLabel(label = stringResource(id = colorNameFor(cardArt)))
            }
        },
        onClick = onSelected
    )
}

@Composable
fun OutlinedContainerVertical(
    modifier: Modifier = Modifier,
    outlineBorderWidth: Dp = 2.dp,
    outlineBrush: Brush? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val brush = outlineBrush ?: SolidColor(MaterialTheme.colorScheme.outline)
    Row(
        modifier = modifier
            .heightIn(48.dp)
            .clip(RoundedCornerShape(12.dp))
            .border(outlineBorderWidth, brush, RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.inverseOnSurface),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            content()
        }
    }
}

@StringRes
private fun colorNameFor(cardArt: DocumentColor): Int {
    return when (cardArt) {
        is DocumentColor.Green -> R.string.document_color_green
        is DocumentColor.Yellow -> R.string.document_color_yellow
        is DocumentColor.Blue -> R.string.document_color_blue
        is DocumentColor.Red -> R.string.document_color_red
    }
}