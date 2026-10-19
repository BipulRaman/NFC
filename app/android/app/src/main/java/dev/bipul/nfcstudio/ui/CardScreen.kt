package dev.bipul.nfcstudio.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.outlined.DataObject
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Call
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.CopyAll
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.PersonAdd
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.bipul.nfcstudio.data.CardItem
import dev.bipul.nfcstudio.data.ItemKind
import dev.bipul.nfcstudio.data.RawJson
import dev.bipul.nfcstudio.data.Seal
import dev.bipul.nfcstudio.data.WifiSecurity
import dev.bipul.nfcstudio.nfc.CardSnapshot
import dev.bipul.nfcstudio.nfc.WriteProtection
import org.json.JSONArray
import org.json.JSONObject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardScreen(
    vm: AppViewModel,
    snackbar: SnackbarHostState,
    onAdd: () -> Unit,
    onEdit: (Entry) -> Unit,
    onUnlock: (Entry) -> Unit,
) {
    val card = vm.card
    val dirty = vm.isDirty
    val capacity = card?.capacity
    val size = if (vm.draft.isEmpty()) 0 else vm.draftSize
    var confirmLeave by remember { mutableStateOf(false) }
    var confirmErase by remember { mutableStateOf(false) }
    var confirmLock by remember { mutableStateOf(false) }
    var showProtection by remember { mutableStateOf(false) }
    var confirmFullErase by remember { mutableStateOf(false) }
    var showRaw by remember { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val fabExpanded by remember { derivedStateOf { listState.firstVisibleItemIndex == 0 } }

    BackHandler { if (dirty) confirmLeave = true else vm.close() }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = { if (dirty) confirmLeave = true else vm.close() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                title = { Text(if (card == null) "New card" else "Your card") },
                actions = {
                    if (card != null) {
                        IconButton(onClick = { showRaw = !showRaw }) {
                            Icon(
                                Icons.Outlined.DataObject,
                                if (showRaw) "Hide raw data" else "Show raw data",
                                tint = if (showRaw) MaterialTheme.colorScheme.primary else LocalContentColor.current,
                            )
                        }
                    }
                    if (card != null && card.supported) {
                        IconButton(onClick = { showProtection = true }) { Icon(Icons.Outlined.Shield, "Protect card") }
                    }
                    IconButton(onClick = { menu = true }) { Icon(Icons.Outlined.MoreVert, "More options") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        if (vm.draft.isNotEmpty()) {
                            MenuItem("Copy to another card", Icons.Outlined.CopyAll) { menu = false; vm.requestSave() }
                        }
                        if (card != null && card.supported) {
                            MenuItem("Protect card", Icons.Outlined.Shield) { menu = false; showProtection = true }
                        }
                        if (card != null && card.supported && card.writable && !card.blank) {
                            MenuItem("Erase card", Icons.Outlined.DeleteSweep) { menu = false; confirmErase = true }
                        }
                        if (card?.protection?.model != null && card.protection.status != WriteProtection.Locked) {
                            MenuItem("Erase completely…", Icons.Outlined.DeleteForever) { menu = false; confirmFullErase = true }
                        }
                        if (card?.canMakeReadOnly == true) {
                            MenuItem("Lock card permanently", Icons.Outlined.Lock) { menu = false; confirmLock = true }
                        }
                        MenuItem("Advanced tools", Icons.Outlined.Build) { menu = false; vm.screen = Screen.TOOLS }
                    }
                },
            )
        },
        floatingActionButton = {
            if (vm.canEdit && !dirty) {
                ExtendedFloatingActionButton(
                    onClick = onAdd,
                    expanded = fabExpanded,
                    icon = { Icon(Icons.Outlined.Add, null) },
                    text = { Text("Add item") },
                )
            }
        },
        bottomBar = {
            AnimatedVisibility(dirty, enter = slideInVertically { it }, exit = slideOutVertically { it }) {
                SaveBar(
                    size = size,
                    capacity = capacity,
                    sealed = vm.willSeal,
                    onAdd = onAdd.takeIf { vm.canEdit },
                    onDiscard = vm::discardChanges,
                    onSave = { vm.requestSave() },
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 112.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "header") { CardHeader(card, size, vm.draft.size) }
            if (showRaw && card != null) {
                item(key = "raw") { RawDataCard(card, vm) { showRaw = false } }
            }
            if (card != null && (card.seal != Seal.Status.None || card.protection?.status !in listOf(null, WriteProtection.Open))) {
                item(key = "protection") { ProtectionBanners(card, vm.sealedByMe) }
            }
            card?.notice?.let { notice ->
                item(key = "notice") { Banner(Icons.Outlined.Info, notice) }
            }
            if (card?.damaged == true) {
                item(key = "damaged") {
                    Banner(
                        Icons.Outlined.WarningAmber,
                        "The data on this card is damaged. Add items and save, or erase the card, to fix it.",
                        MaterialTheme.colorScheme.errorContainer,
                    )
                }
            }
            if (card?.blank == true) {
                item(key = "blank") {
                    Banner(Icons.Outlined.Info, "This card is blank. Add items and save; it will be set up automatically.")
                }
            }
            if (card != null && card.supported && !card.writable) {
                item(key = "ro") { Banner(Icons.Outlined.Lock, "This card is locked, so it can only be read.") }
            }
            if (vm.draft.isEmpty() && vm.canEdit) {
                item(key = "empty") { EmptyState(onAdd) }
            }
            items(vm.draft, key = { it.id }) { entry ->
                ItemCard(
                    entry = entry,
                    revealed = vm.revealed[entry.id],
                    canEdit = vm.canEdit,
                    isFirst = vm.draft.firstOrNull()?.id == entry.id,
                    isLast = vm.draft.lastOrNull()?.id == entry.id,
                    vm = vm,
                    onEdit = { onEdit(entry) },
                    onUnlock = { onUnlock(entry) },
                )
            }
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text("Discard changes?") },
            text = { Text("Your changes haven't been saved to a card yet.") },
            confirmButton = { TextButton(onClick = { confirmLeave = false; vm.close() }) { Text("Discard") } },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text("Keep editing") } },
        )
    }
    if (confirmErase) {
        AlertDialog(
            onDismissRequest = { confirmErase = false },
            icon = { Icon(Icons.Outlined.DeleteSweep, null) },
            title = { Text("Erase this card?") },
            text = { Text("Everything on the card will be deleted. This can't be undone.") },
            confirmButton = {
                TextButton(onClick = { confirmErase = false; vm.requestErase() }) {
                    Text("Erase", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmErase = false }) { Text("Cancel") } },
        )
    }
    if (showProtection) {
        ProtectionSheet(
            vm,
            onDismiss = { showProtection = false },
            onLock = { confirmLock = true },
            onErase = { confirmFullErase = true },
        )
    }
    if (confirmFullErase && card != null) {
        FullEraseDialog(card, onDismiss = { confirmFullErase = false }) { password, scheme ->
            confirmFullErase = false
            if (password.isNotEmpty()) vm.rememberCardPassword(password)
            vm.requestFactoryReset(scheme)
        }
    }
    if (confirmLock) {
        var understood by rememberSaveable { mutableStateOf(false) }
        var password by rememberSaveable { mutableStateOf("") }
        val needsPassword = card?.needsPassword == true
        AlertDialog(
            onDismissRequest = { confirmLock = false },
            icon = { Icon(Icons.Outlined.Lock, null) },
            title = { Text("Lock card permanently?") },
            text = {
                Column {
                    Text("The card will become read-only forever. Nobody, including you, will ever be able to change or erase it.")
                    if (needsPassword) {
                        Spacer(Modifier.height(8.dp))
                        PasswordField(password, { password = it }, "Current card password")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = understood, onCheckedChange = { understood = it })
                        Text("I understand this can't be undone")
                    }
                }
            },
            confirmButton = {
                val ready = understood && (!needsPassword || password.isNotEmpty())
                TextButton(enabled = ready, onClick = {
                    confirmLock = false
                    if (needsPassword) vm.rememberCardPassword(password)
                    vm.requestMakeReadOnly()
                }) {
                    Text("Lock forever", color = if (ready) MaterialTheme.colorScheme.error else Color.Unspecified)
                }
            },
            dismissButton = { TextButton(onClick = { confirmLock = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun MenuItem(text: String, icon: ImageVector, onClick: () -> Unit) {
    DropdownMenuItem(text = { Text(text) }, leadingIcon = { Icon(icon, null) }, onClick = onClick)
}

@Composable
private fun Banner(icon: ImageVector, text: String, color: Color = MaterialTheme.colorScheme.secondaryContainer) {
    Card(colors = CardDefaults.cardColors(containerColor = color), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null)
            Spacer(Modifier.width(12.dp))
            Text(text, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun EmptyState(onAdd: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Nothing here yet", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(6.dp))
        Text(
            "Add a password, note, Wi-Fi network, website or contact, then save it to the card.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        FilledTonalButton(onClick = onAdd) {
            Icon(Icons.Outlined.Add, null)
            Spacer(Modifier.width(8.dp))
            Text("Add your first item")
        }
    }
}

@Composable
private fun SaveBar(
    size: Int,
    capacity: Int?,
    sealed: Boolean,
    onAdd: (() -> Unit)?,
    onDiscard: () -> Unit,
    onSave: () -> Unit,
) {
    val tooBig = capacity != null && size > capacity
    Surface(tonalElevation = 3.dp, shadowElevation = 8.dp) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 16.dp, vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Unsaved changes", style = MaterialTheme.typography.titleSmall)
                    val seal = if (sealed) " · includes tamper seal" else ""
                    Text(
                        when {
                            tooBig -> "Too big by ${size - capacity!!} bytes. Remove or shorten something" +
                                if (sealed) ", or turn off the seal." else "."
                            capacity != null -> "Uses $size of $capacity bytes$seal"
                            else -> "Uses $size bytes$seal"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (tooBig) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (onAdd != null) {
                    IconButton(onClick = onAdd) { Icon(Icons.Outlined.Add, "Add item") }
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                TextButton(onClick = onDiscard, modifier = Modifier.weight(1f)) { Text("Discard") }
                Button(onClick = onSave, enabled = !tooBig, modifier = Modifier.weight(2f).height(48.dp)) {
                    Text("Save to card")
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ItemCard(
    entry: Entry,
    revealed: CardItem?,
    canEdit: Boolean,
    isFirst: Boolean,
    isLast: Boolean,
    vm: AppViewModel,
    onEdit: () -> Unit,
    onUnlock: () -> Unit,
) {
    val context = LocalContext.current
    val item = entry.item
    val locked = item as? CardItem.Locked
    val shown = revealed ?: item
    val (title, subtitle) = describe(item)
    val iconKind = locked?.innerKind ?: item.kind
    var menu by remember { mutableStateOf(false) }

    fun copy(label: String, text: String, sensitive: Boolean = false) {
        copyToClipboard(context, label, text, sensitive)
        vm.say("$label copied")
    }

    fun open(intent: android.content.Intent) {
        if (!launch(context, intent)) vm.say("No app on this phone can open that.")
    }

    ElevatedCard(
        onClick = {
            when {
                locked != null && revealed == null -> onUnlock()
                canEdit && item !is CardItem.Unknown -> onEdit()
            }
        },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(start = 16.dp, top = 14.dp, end = 4.dp, bottom = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                KindIcon(iconKind)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    val sub = when {
                        locked != null && revealed == null -> "Locked · tap to unlock"
                        shown is CardItem.Note -> null
                        else -> subtitle.takeIf { it.isNotBlank() }
                    }
                    if (sub != null) {
                        Text(
                            sub,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                if (locked != null) {
                    Icon(
                        if (revealed == null) Icons.Outlined.Lock else Icons.Outlined.LockOpen,
                        contentDescription = "Protected with PIN",
                        tint = kindStyle(ItemKind.LOCKED).color,
                        modifier = Modifier.size(20.dp),
                    )
                }
                Column {
                    IconButton(onClick = { menu = true }) { Icon(Icons.Outlined.MoreVert, "Item options") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        if (canEdit && item !is CardItem.Unknown) {
                            MenuItem("Edit", Icons.Outlined.Edit) { menu = false; onEdit() }
                        }
                        if (locked != null && revealed != null) {
                            MenuItem("Hide", Icons.Outlined.VisibilityOff) { menu = false; vm.hide(entry.id) }
                        }
                        if (canEdit && !isFirst) {
                            MenuItem("Move up", Icons.Outlined.ArrowUpward) { menu = false; vm.move(entry.id, -1) }
                        }
                        if (canEdit && !isLast) {
                            MenuItem("Move down", Icons.Outlined.ArrowDownward) { menu = false; vm.move(entry.id, 1) }
                        }
                        if (canEdit) {
                            HorizontalDivider()
                            MenuItem("Delete", Icons.Outlined.Delete) { menu = false; vm.delete(entry.id) }
                        }
                    }
                }
            }

            Column(Modifier.padding(start = 58.dp, end = 12.dp)) {
                when {
                    locked != null && revealed == null -> {
                        Spacer(Modifier.height(8.dp))
                        FilledTonalButton(onClick = onUnlock) {
                            Icon(Icons.Outlined.LockOpen, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Unlock")
                        }
                    }
                    shown is CardItem.Note -> {
                        Spacer(Modifier.height(4.dp))
                        Text(shown.text, style = MaterialTheme.typography.bodyLarge, maxLines = 8, overflow = TextOverflow.Ellipsis)
                        Actions { Chip("Copy", Icons.Outlined.ContentCopy) { copy("Note", shown.text, locked != null) } }
                    }
                    shown is CardItem.Website -> Actions {
                        Chip("Open", Icons.AutoMirrored.Outlined.OpenInNew) { open(viewIntent(shown.url)) }
                        Chip("Copy", Icons.Outlined.ContentCopy) { copy("Link", shown.url) }
                    }
                    shown is CardItem.Phone -> Actions {
                        Chip("Call", Icons.Outlined.Call) { open(dialIntent(shown.number)) }
                        Chip("Copy", Icons.Outlined.ContentCopy) { copy("Number", shown.number) }
                    }
                    shown is CardItem.Email -> Actions {
                        Chip("Send email", Icons.Outlined.Email) { open(emailIntent(shown.address)) }
                        Chip("Copy", Icons.Outlined.ContentCopy) { copy("Email", shown.address) }
                    }
                    shown is CardItem.Wifi -> {
                        Text(shown.security.label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (shown.security != WifiSecurity.OPEN) {
                            SecretLine("Wi-Fi password", shown.password) { copy("Wi-Fi password", shown.password, true) }
                        }
                        Actions {
                            Chip("Wi-Fi settings", Icons.Outlined.Settings) { open(wifiSettingsIntent()) }
                            Chip("Copy name", Icons.Outlined.ContentCopy) { copy("Network name", shown.ssid) }
                        }
                    }
                    shown is CardItem.Contact -> {
                        if (shown.phone.isNotBlank()) Text("📞 ${shown.phone}", style = MaterialTheme.typography.bodyMedium)
                        if (shown.email.isNotBlank()) Text("✉ ${shown.email}", style = MaterialTheme.typography.bodyMedium)
                        Actions {
                            Chip("Save contact", Icons.Outlined.PersonAdd) { open(addContactIntent(shown)) }
                            if (shown.phone.isNotBlank()) Chip("Call", Icons.Outlined.Call) { open(dialIntent(shown.phone)) }
                        }
                    }
                    shown is CardItem.Password -> {
                        if (shown.username.isNotBlank()) {
                            FieldLine("Username", shown.username) { copy("Username", shown.username) }
                        }
                        SecretLine("Password", shown.password) { copy("Password", shown.password, true) }
                        if (shown.website.isNotBlank()) {
                            FieldLine("Website", shown.website) { open(viewIntent(shown.website)) }
                        }
                        if (shown.notes.isNotBlank()) {
                            Text(shown.notes, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (locked == null) {
                            Spacer(Modifier.height(6.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.WarningAmber, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    "Not protected: anyone who taps this card can read it.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.weight(1f),
                                )
                                if (canEdit) TextButton(onClick = onEdit) { Text("Protect") }
                            }
                        }
                    }
                    shown is CardItem.Unknown -> {
                        val json = remember(shown) { RawJson.pretty(RawJson.record(shown.record)) }
                        Text(
                            "Unrecognised format, shown as raw data. It's kept exactly as it is when you save.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(6.dp))
                        JsonBlock(json, maxLines = 14)
                        Actions { Chip("Copy JSON", Icons.Outlined.ContentCopy) { copy("Raw data", json) } }
                    }
                }
            }
        }
    }
}

@Composable
fun JsonBlock(json: String, maxLines: Int = Int.MAX_VALUE, modifier: Modifier = Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(8.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Text(
            json,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            maxLines = maxLines,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(10.dp),
        )
    }
}

/** Everything on the card as JSON, shown inline under the card header. */
@Composable
private fun RawDataCard(card: CardSnapshot, vm: AppViewModel, onClose: () -> Unit) {
    val context = LocalContext.current
    val json = remember(card) {
        val info = JSONObject()
            .put("id", card.idHex)
            .put("type", card.typeName)
            .put("technologies", JSONArray(card.techs))
            .put("capacity", card.capacity ?: JSONObject.NULL)
            .put("used", card.used)
            .put("writable", card.writable)
            .put(
                "seal",
                when (val s = card.seal) {
                    Seal.Status.None -> "none"
                    is Seal.Status.Valid -> "valid (key ${Seal.fingerprint(s.key)})"
                    Seal.Status.Broken -> "broken"
                },
            )
            .put(
                "protection",
                when (val p = card.protection?.status) {
                    null, WriteProtection.Open -> "none"
                    is WriteProtection.Password -> if (p.readProtected) "password (read and write)" else "password (write)"
                    WriteProtection.Locked -> "locked permanently"
                },
            )
        if (card.notice != null) info.put("note", card.notice)
        RawJson.pretty(JSONObject().put("card", info).put("records", RawJson.records(card.records)))
    }
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(start = 16.dp, top = 8.dp, end = 8.dp, bottom = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                KindIcon(ItemKind.UNKNOWN)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("Raw data", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Everything stored on the card, as JSON",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                IconButton(onClick = onClose) { Icon(Icons.Outlined.Close, "Hide raw data") }
            }
            Spacer(Modifier.height(8.dp))
            Column(Modifier.padding(end = 8.dp)) {
                JsonBlock(json)
                Actions {
                    Chip("Copy JSON", Icons.Outlined.ContentCopy) {
                        copyToClipboard(context, "Card data", json, sensitive = true)
                        vm.say("Raw data copied")
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Actions(content: @Composable () -> Unit) {
    FlowRow(
        Modifier.padding(top = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) { content() }
}

@Composable
private fun Chip(text: String, icon: ImageVector, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(text) },
        leadingIcon = { Icon(icon, null, Modifier.size(AssistChipDefaults.IconSize)) },
    )
}

@Composable
private fun FieldLine(label: String, value: String, onAction: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(vertical = 4.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        IconButton(onClick = onAction) {
            Icon(if (label == "Website") Icons.AutoMirrored.Outlined.OpenInNew else Icons.Outlined.ContentCopy, "Copy $label")
        }
    }
}

@Composable
private fun SecretLine(label: String, value: String, onCopy: () -> Unit) {
    var visible by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(vertical = 4.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                if (visible) value else "•".repeat(value.length.coerceIn(8, 16)),
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = FontFamily.Monospace,
                maxLines = 2,
            )
        }
        IconButton(onClick = { visible = !visible }) {
            Icon(if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, if (visible) "Hide" else "Show")
        }
        IconButton(onClick = onCopy) { Icon(Icons.Outlined.ContentCopy, "Copy $label") }
    }
}
