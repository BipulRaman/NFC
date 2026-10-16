package dev.bipul.nfcstudio.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import dev.bipul.nfcstudio.data.CardItem

private sealed interface Page {
    data class Main(val screen: Screen) : Page
    data class Edit(val request: EditRequest) : Page
}

@Composable
fun NfcStudioApp(vm: AppViewModel, setSecure: (Boolean) -> Unit) {
    val snackbar = remember { SnackbarHostState() }
    val haptics = LocalHapticFeedback.current
    var editing by remember { mutableStateOf<EditRequest?>(null) }
    var unlocking by remember { mutableStateOf<Pair<Entry, Boolean>?>(null) }

    LaunchedEffect(Unit) {
        vm.messages.collect { m ->
            val result = snackbar.showSnackbar(
                m.text,
                actionLabel = if (m.undo != null) "Undo" else null,
                duration = SnackbarDuration.Short,
            )
            if (result == SnackbarResult.ActionPerformed) m.undo?.invoke()
        }
    }
    LaunchedEffect(vm.taps) {
        if (vm.taps > 0) haptics.performHapticFeedback(HapticFeedbackType.LongPress)
    }
    // Keep secrets out of screenshots and the recent-apps preview while they're on screen.
    val secure = vm.revealed.isNotEmpty() || editing != null
    LaunchedEffect(secure) { setSecure(secure) }

    fun edit(entry: Entry) {
        val item = entry.item
        if (item is CardItem.Locked) {
            val inner = vm.revealed[entry.id]
            if (inner == null) {
                unlocking = entry to true
                return
            }
            editing = EditRequest(entry.id, inner, locked = true, pin = vm.pinFor(entry.id), label = item.label)
        } else {
            editing = EditRequest(entry.id, item)
        }
    }

    val page: Page = editing?.let { Page.Edit(it) } ?: Page.Main(vm.screen)
    AnimatedContent(page, label = "page", transitionSpec = { fadeIn() togetherWith fadeOut() }) { p ->
        when (p) {
            is Page.Edit -> key(p.request) { ItemEditor(p.request, vm) { editing = null } }
            is Page.Main -> when (p.screen) {
                Screen.HOME -> HomeScreen(vm, snackbar)
                Screen.CARD -> CardScreen(
                    vm = vm,
                    snackbar = snackbar,
                    onAdd = { editing = EditRequest(null, null) },
                    onEdit = ::edit,
                    onUnlock = { unlocking = it to false },
                )
                Screen.TOOLS -> ToolsScreen(vm, snackbar)
            }
        }
    }

    unlocking?.let { (entry, thenEdit) ->
        UnlockDialog(entry, vm) { ok ->
            unlocking = null
            if (ok && thenEdit) edit(entry)
        }
    }

    if (vm.incoming != null) {
        AlertDialog(
            onDismissRequest = { vm.acceptIncoming(discard = false) },
            title = { Text("You have unsaved changes") },
            text = { Text("A card was tapped, but your changes haven't been saved yet. Discard them and open that card?") },
            confirmButton = { TextButton(onClick = { vm.acceptIncoming(discard = true) }) { Text("Discard and open") } },
            dismissButton = { TextButton(onClick = { vm.acceptIncoming(discard = false) }) { Text("Keep editing") } },
        )
    }

    TapSheet(vm)
}
