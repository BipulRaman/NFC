package dev.bipul.nfcstudio.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.bipul.nfcstudio.data.Seal
import dev.bipul.nfcstudio.nfc.CardSnapshot
import dev.bipul.nfcstudio.nfc.PasswordScheme
import dev.bipul.nfcstudio.nfc.Type2Tag
import dev.bipul.nfcstudio.nfc.WriteProtection

private val Good = Color(0xFF1E8E3E)

/** Seal and write-protection state shown at the top of the card screen. */
@Composable
fun ProtectionBanners(card: CardSnapshot, sealedByMe: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        when (val s = card.seal) {
            Seal.Status.None -> {}
            is Seal.Status.Valid -> StatusCard(
                Icons.Outlined.VerifiedUser,
                if (sealedByMe) "Sealed by you" else "Sealed by another device",
                if (sealedByMe) "Nothing has changed since you sealed it."
                else "Nothing has changed since it was sealed. Key ${Seal.fingerprint(s.key)}.",
                Good,
            )
            Seal.Status.Broken -> StatusCard(
                Icons.Outlined.GppBad,
                "Seal broken",
                "This card was changed, or its content was copied from another card, after it was sealed. " +
                    "Don't trust what's on it.",
                MaterialTheme.colorScheme.error,
            )
        }
        when (card.protection?.status) {
            is WriteProtection.Password -> StatusCard(
                Icons.Outlined.Key,
                "Write-protected",
                "Anyone can read this card, but changing it needs its password.",
                MaterialTheme.colorScheme.primary,
            )
            WriteProtection.Locked -> StatusCard(
                Icons.Outlined.Lock,
                "Locked permanently",
                "Nobody can ever change or erase this card.",
                MaterialTheme.colorScheme.primary,
            )
            else -> {}
        }
    }
}

@Composable
private fun StatusCard(icon: ImageVector, title: String, text: String, color: Color) {
    Card(
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = color)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, style = MaterialTheme.typography.titleSmall, color = color)
                Text(text, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

enum class PasswordMode { SET, CHANGE, REMOVE }

/** Everything about protecting a card against changes, copies and tampering. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ProtectionSheet(vm: AppViewModel, onDismiss: () -> Unit, onLock: () -> Unit, onErase: () -> Unit) {
    val card = vm.card
    var passwordMode by remember { mutableStateOf<PasswordMode?>(null) }
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).navigationBarsPadding()
                .padding(horizontal = 24.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Protect this card", style = MaterialTheme.typography.titleLarge)

            Section(Icons.Outlined.Shield, "Tamper seal") {
                Text(
                    "A digital signature tied to this card's ID. If anyone changes the content, or copies it to " +
                        "another card, NFC Studio shows “Seal broken”.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (card != null && !Seal.uidIsStable(card.id)) {
                    Text("This card's ID changes on every tap, so it can't be sealed.", color = MaterialTheme.colorScheme.error)
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Seal whenever I save", Modifier.weight(1f))
                        Switch(checked = vm.sealOnSave, onCheckedChange = { vm.sealOnSave = it })
                    }
                    val canSealNow = card != null && card.supported && card.writable && vm.draft.isNotEmpty() &&
                        !vm.isDirty && !vm.sealedByMe
                    if (canSealNow) {
                        FilledTonalButton(onClick = { onDismiss(); vm.requestSave(seal = true) }) { Text("Seal what's on the card now") }
                    }
                    vm.mySealKey?.let {
                        Text("This phone's seal key: ${Seal.fingerprint(it)}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            Section(Icons.Outlined.Key, "Write password") {
                val p = card?.protection
                when {
                    card == null -> Text("Tap a card first.")
                    p?.model == null -> Text(
                        "A write password is available for NTAG213/215/216 and MIFARE Ultralight EV1 tags. " +
                            "Use the tamper seal to protect this card.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    p.status == WriteProtection.Locked -> Text("This card is locked permanently.")
                    p.status is WriteProtection.Password -> {
                        val pw = p.status as WriteProtection.Password
                        Text(
                            if (pw.readProtected) "Reading and changing this card both need its password."
                            else "Changes need the card password. Anyone can still read it.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        if (pw.limited) {
                            Text(
                                "After ${p.model.maxAttempts} wrong passwords in a row the card can never be changed again.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { passwordMode = PasswordMode.CHANGE }) { Text("Change password") }
                            OutlinedButton(onClick = { passwordMode = PasswordMode.REMOVE }) { Text("Remove password") }
                        }
                    }
                    else -> {
                        Text(
                            "Anyone can change this card. Set a password so only you can; it's stored in the card's chip.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        FilledTonalButton(onClick = { passwordMode = PasswordMode.SET }) { Text("Set password") }
                    }
                }
            }

            if (card?.canMakeReadOnly == true) {
                Section(Icons.Outlined.Lock, "Lock permanently") {
                    Text(
                        "Make the card read-only forever. Nobody, including you, will ever be able to change it.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedButton(onClick = { onDismiss(); onLock() }) {
                        Text("Lock permanently…", color = MaterialTheme.colorScheme.error)
                    }
                }
            }

            if (card?.protection?.model != null) {
                Section(Icons.Outlined.DeleteForever, "Erase completely") {
                    if (card.protection.status == WriteProtection.Locked) {
                        Text(Type2Tag.LOCKED_FOREVER, style = MaterialTheme.typography.bodyMedium)
                    } else {
                        Text(
                            "Wipe every byte and remove the password, so the card is like new. Works with passwords " +
                                "set in NFC Studio, NFC Tools and similar apps.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        OutlinedButton(onClick = { onDismiss(); onErase() }) {
                            Text("Erase completely…", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }

            HorizontalDivider()
            Text(
                "Write protection stops changes but not reading. Keep secrets in PIN-protected items.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    passwordMode?.let { mode ->
        CardPasswordDialog(mode, attempts = card?.protection?.model?.maxAttempts ?: 8, onDismiss = { passwordMode = null }) { current, new, limit ->
            passwordMode = null
            onDismiss()
            if (current.isNotEmpty()) vm.rememberCardPassword(current)
            when (mode) {
                PasswordMode.SET, PasswordMode.CHANGE -> vm.requestSetPassword(new, limit)
                PasswordMode.REMOVE -> vm.requestRemovePassword()
            }
        }
    }
}

/** Confirms wiping a card completely; asks for its password (and which app set it) when protected. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun FullEraseDialog(card: CardSnapshot, onDismiss: () -> Unit, onConfirm: (password: String, scheme: PasswordScheme) -> Unit) {
    val status = card.protection?.status
    val needsPassword = status is WriteProtection.Password
    var password by rememberSaveable { mutableStateOf("") }
    var scheme by rememberSaveable { mutableStateOf(PasswordScheme.NFC_STUDIO) }
    var understood by rememberSaveable { mutableStateOf(false) }
    val ready = understood && (!needsPassword || password.isNotEmpty())

    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.DeleteForever, null) },
        title = { Text("Erase card completely?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Every byte of the card's memory is wiped, including any seal" +
                        (if (needsPassword) ", and its password is removed" else "") +
                        ". The card ends up empty and unprotected, like new.",
                )
                if (needsPassword) {
                    Text("The password was set with:", style = MaterialTheme.typography.labelLarge)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PasswordScheme.entries.forEach { s ->
                            FilterChip(selected = scheme == s, onClick = { scheme = s }, label = { Text(s.label) })
                        }
                    }
                    PasswordField(
                        password,
                        { password = it },
                        if (scheme == PasswordScheme.HEX) "Password (8 hex digits)" else "Card password",
                    )
                    if ((status as WriteProtection.Password).limited) {
                        Text(
                            "Careful: this card freezes for good after ${card.protection?.model?.maxAttempts ?: 8} wrong passwords in a row.",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Text(
                        "If the password is forgotten, the card can't be erased. The chip itself enforces this.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = understood, onCheckedChange = { understood = it })
                    Text("I understand everything on the card will be lost")
                }
            }
        },
        confirmButton = {
            TextButton(enabled = ready, onClick = { onConfirm(password, scheme) }) {
                Text("Erase everything", color = if (ready) MaterialTheme.colorScheme.error else Color.Unspecified)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun Section(icon: ImageVector, title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(10.dp))
                Text(title, style = MaterialTheme.typography.titleMedium)
            }
            content()
        }
    }
}

@Composable
fun PasswordField(value: String, onChange: (String) -> Unit, label: String, isError: Boolean = false) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        isError = isError,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        trailingIcon = {
            IconButton(onClick = { visible = !visible }) {
                Icon(if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, if (visible) "Hide" else "Show")
            }
        },
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
fun CardPasswordDialog(
    mode: PasswordMode,
    attempts: Int,
    onDismiss: () -> Unit,
    onConfirm: (current: String, new: String, limitAttempts: Boolean) -> Unit,
) {
    var current by rememberSaveable { mutableStateOf("") }
    var new1 by rememberSaveable { mutableStateOf("") }
    var new2 by rememberSaveable { mutableStateOf("") }
    var limit by rememberSaveable { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    val needsNew = mode != PasswordMode.REMOVE
    val needsCurrent = mode != PasswordMode.SET

    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(if (mode == PasswordMode.REMOVE) Icons.Outlined.LockOpen else Icons.Outlined.Key, null) },
        title = {
            Text(
                when (mode) {
                    PasswordMode.SET -> "Set a card password"
                    PasswordMode.CHANGE -> "Change card password"
                    PasswordMode.REMOVE -> "Remove card password"
                },
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    when (mode) {
                        PasswordMode.SET -> "The card stays readable by anyone, but changing or erasing it will need this password."
                        PasswordMode.CHANGE -> "Enter the current password, then the new one."
                        PasswordMode.REMOVE -> "Anyone will be able to change the card again."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (needsCurrent) PasswordField(current, { current = it; error = null }, "Current card password")
                if (needsNew) {
                    PasswordField(new1, { new1 = it; error = null }, "New password")
                    PasswordField(new2, { new2 = it; error = null }, "Repeat new password")
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = limit, onCheckedChange = { limit = it })
                        Text("Freeze the card after $attempts wrong passwords (stops guessing)")
                    }
                    Text(
                        "Tags only hold a short password, so keep the freeze on. A forgotten password can't be " +
                            "recovered, though the card stays readable.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Spacer(Modifier.height(2.dp))
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                error = when {
                    needsCurrent && current.isEmpty() -> "Enter the current password."
                    needsNew && new1.length < 4 -> "Choose a password of at least 4 characters."
                    needsNew && new1 != new2 -> "The two passwords don't match."
                    else -> null
                }
                if (error == null) onConfirm(current, new1, limit)
            }) { Text("Continue") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
