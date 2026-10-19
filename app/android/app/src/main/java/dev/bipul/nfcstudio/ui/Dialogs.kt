package dev.bipul.nfcstudio.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/** Bottom sheet shown while waiting for, and performing, a tap that writes or inspects a card. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TapSheet(vm: AppViewModel) {
    val sheet = vm.sheet ?: return
    val state = rememberModalBottomSheetState(
        skipPartiallyExpanded = true,
        confirmValueChange = { sheet !is TapSheet.Working },
    )
    ModalBottomSheet(onDismissRequest = vm::cancelTap, sheetState = state) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 24.dp).padding(bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            AnimatedContent(sheet, label = "tap", contentKey = { it::class }) { s ->
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    when (s) {
                        is TapSheet.Waiting -> {
                            PulsingNfc(size = 160.dp)
                            Text(waitingTitle(s.pending), style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "Hold it against the back of your phone and keep it still until you feel a vibration.",
                                textAlign = TextAlign.Center,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.height(20.dp))
                            OutlinedButton(onClick = vm::cancelTap) { Text("Cancel") }
                        }
                        is TapSheet.Working -> {
                            Spacer(Modifier.height(40.dp))
                            CircularProgressIndicator(Modifier.size(64.dp))
                            Spacer(Modifier.height(28.dp))
                            Text("Working… keep holding", style = MaterialTheme.typography.titleLarge)
                            Spacer(Modifier.height(40.dp))
                        }
                        is TapSheet.Done -> {
                            Spacer(Modifier.height(24.dp))
                            Icon(Icons.Outlined.CheckCircle, null, Modifier.size(96.dp), tint = Color(0xFF1E8E3E))
                            Spacer(Modifier.height(16.dp))
                            Text(s.message, style = MaterialTheme.typography.titleLarge)
                            Spacer(Modifier.height(40.dp))
                        }
                        is TapSheet.Failed -> {
                            Spacer(Modifier.height(24.dp))
                            Icon(
                                if (s.askPassword) Icons.Outlined.Lock else Icons.Outlined.ErrorOutline,
                                null,
                                Modifier.size(88.dp),
                                tint = if (s.askPassword) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                            )
                            Spacer(Modifier.height(16.dp))
                            Text(if (s.askPassword) "Card password needed" else "That didn't work", style = MaterialTheme.typography.titleLarge)
                            Spacer(Modifier.height(6.dp))
                            Text(s.message, textAlign = TextAlign.Center)
                            Spacer(Modifier.height(20.dp))
                            if (s.askPassword) {
                                var password by rememberSaveable { mutableStateOf("") }
                                PasswordField(password, { password = it }, "Card password")
                                Spacer(Modifier.height(16.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    OutlinedButton(onClick = vm::cancelTap) { Text("Cancel") }
                                    Button(onClick = { vm.retryWithPassword(password) }, enabled = password.isNotEmpty()) {
                                        Text("Continue")
                                    }
                                }
                            } else {
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    OutlinedButton(onClick = vm::cancelTap) { Text("Cancel") }
                                    Button(onClick = vm::retry) { Text("Try again") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun waitingTitle(p: Pending) = when (p) {
    is Pending.Save -> "Hold the card you want to save to"
    Pending.Erase -> "Hold the card to erase"
    Pending.MakeReadOnly -> "Hold the card to lock it"
    is Pending.SetPassword -> "Hold the card to set its password"
    Pending.RemovePassword -> "Hold the card to remove its password"
    is Pending.FactoryReset -> "Hold the card to erase it completely"
    Pending.Dump -> "Hold the card to read its memory"
    is Pending.Apdu -> "Hold the smart card"
}

/** Asks for the PIN of a protected item. */
@Composable
fun UnlockDialog(entry: Entry, vm: AppViewModel, onDone: (unlocked: Boolean) -> Unit) {
    var pin by rememberSaveable { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }
    var wrong by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }

    fun submit() {
        if (pin.isEmpty() || busy) return
        busy = true
        scope.launch {
            val ok = vm.unlock(entry.id, pin)
            busy = false
            if (ok) onDone(true) else wrong = true
        }
    }

    AlertDialog(
        onDismissRequest = { onDone(false) },
        icon = { Icon(Icons.Outlined.Lock, null) },
        title = { Text("Unlock ${AppViewModel.title(entry)}") },
        text = {
            Column {
                Text("Enter the PIN or passphrase used to protect this item.")
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it; wrong = false },
                    label = { Text("PIN") },
                    singleLine = true,
                    isError = wrong,
                    supportingText = if (wrong) ({ Text("Wrong PIN. Try again.") }) else null,
                    visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        IconButton(onClick = { visible = !visible }) {
                            Icon(if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, null)
                        }
                    },
                    modifier = Modifier.focusRequester(focus),
                )
            }
        },
        confirmButton = {
            if (busy) {
                CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            } else {
                TextButton(onClick = ::submit, enabled = pin.isNotEmpty()) { Text("Unlock") }
            }
        },
        dismissButton = { TextButton(onClick = { onDone(false) }) { Text("Cancel") } },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ToolsScreen(vm: AppViewModel, snackbar: SnackbarHostState) {
    var apdus by rememberSaveable { mutableStateOf("00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00") }
    val back = { vm.screen = if (vm.card != null || vm.draft.isNotEmpty()) Screen.CARD else Screen.HOME }
    val listState = rememberLazyListState()
    BackHandler { back() }
    LaunchedEffect(vm.log.size) { if (vm.log.isNotEmpty()) listState.animateScrollToItem(vm.log.size - 1) }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                title = { Text("Advanced tools") },
                actions = { TextButton(onClick = { vm.log.clear() }) { Text("Clear log") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp)) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Card memory", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Shows the raw bytes stored on the card, page by page or block by block.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    FilledTonalButton(onClick = vm::requestDump) { Text("Read memory") }
                }
            }
            Spacer(Modifier.height(12.dp))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Smart card commands (APDU)", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = apdus,
                        onValueChange = { apdus = it },
                        label = { Text("Hex commands, one per line or separated by ;") },
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                        minLines = 2,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    FilledTonalButton(onClick = { vm.requestApdus(apdus) }) { Text("Send") }
                }
            }
            Spacer(Modifier.height(12.dp))
            Text("Log", style = MaterialTheme.typography.titleMedium)
            LazyColumn(state = listState, modifier = Modifier.fillMaxWidth().weight(1f)) {
                if (vm.log.isEmpty()) {
                    item { Text("Results appear here.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
                items(vm.log) { line ->
                    Text(line, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
