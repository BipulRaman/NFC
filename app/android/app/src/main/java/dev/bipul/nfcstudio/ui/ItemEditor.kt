package dev.bipul.nfcstudio.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Notes
import androidx.compose.material.icons.outlined.AlternateEmail
import androidx.compose.material.icons.outlined.Business
import androidx.compose.material.icons.outlined.Call
import androidx.compose.material.icons.outlined.Casino
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Label
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Pin
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.bipul.nfcstudio.data.CardItem
import dev.bipul.nfcstudio.data.ItemCodec
import dev.bipul.nfcstudio.data.ItemKind
import dev.bipul.nfcstudio.data.Vault
import dev.bipul.nfcstudio.data.WifiSecurity
import kotlinx.coroutines.launch

/** What the editor opens with: [initial] is the decrypted item when editing a locked one. */
data class EditRequest(
    val entryId: Long?,
    val initial: CardItem?,
    val locked: Boolean = false,
    val pin: String? = null,
    val label: String = "",
)

private val editableKinds = listOf(
    ItemKind.PASSWORD to "Login details, locked with a PIN",
    ItemKind.NOTE to "Any text, optionally locked with a PIN",
    ItemKind.WIFI to "Phones can join your network by tapping the card",
    ItemKind.WEBSITE to "A link that opens when the card is tapped",
    ItemKind.CONTACT to "Your name, number and email to share",
    ItemKind.PHONE to "A number to call",
    ItemKind.EMAIL to "An email address",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemEditor(request: EditRequest, vm: AppViewModel, onClose: () -> Unit) {
    val init = request.initial
    var kind by rememberSaveable { mutableStateOf(init?.kind) }

    // Field state for every kind; only the ones for the chosen kind are shown.
    var text by rememberSaveable { mutableStateOf((init as? CardItem.Note)?.text ?: "") }
    var url by rememberSaveable { mutableStateOf((init as? CardItem.Website)?.url ?: "") }
    var number by rememberSaveable { mutableStateOf((init as? CardItem.Phone)?.number ?: "") }
    var email by rememberSaveable { mutableStateOf((init as? CardItem.Email)?.address ?: "") }
    val wifi = init as? CardItem.Wifi
    var ssid by rememberSaveable { mutableStateOf(wifi?.ssid ?: "") }
    var wifiPass by rememberSaveable { mutableStateOf(wifi?.password ?: "") }
    var security by rememberSaveable { mutableStateOf(wifi?.security ?: WifiSecurity.WPA2) }
    val contact = init as? CardItem.Contact
    var name by rememberSaveable { mutableStateOf(contact?.name ?: "") }
    var phone by rememberSaveable { mutableStateOf(contact?.phone ?: "") }
    var contactEmail by rememberSaveable { mutableStateOf(contact?.email ?: "") }
    var org by rememberSaveable { mutableStateOf(contact?.organization ?: "") }
    val pw = init as? CardItem.Password
    var title by rememberSaveable { mutableStateOf(pw?.title ?: request.label) }
    var username by rememberSaveable { mutableStateOf(pw?.username ?: "") }
    var password by rememberSaveable { mutableStateOf(pw?.password ?: "") }
    var website by rememberSaveable { mutableStateOf(pw?.website ?: "") }
    var notes by rememberSaveable { mutableStateOf(pw?.notes ?: "") }

    var protect by rememberSaveable { mutableStateOf(request.locked || (init == null)) }
    var pin by rememberSaveable { mutableStateOf(request.pin ?: "") }
    var pin2 by rememberSaveable { mutableStateOf(request.pin ?: "") }
    var error by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    BackHandler { if (kind != null && init == null) kind = null else onClose() }

    /** Validates the fields; returns the item or a message explaining what to fix. */
    fun build(): Pair<CardItem?, String?> {
        fun fail(msg: String): Pair<CardItem?, String?> = null to msg
        fun ok(item: CardItem): Pair<CardItem?, String?> = item to null
        return when (kind) {
            ItemKind.NOTE -> if (text.isBlank()) fail("Write something first.") else ok(CardItem.Note(text.trim()))
            ItemKind.WEBSITE -> {
                val u = url.trim()
                when {
                    u.isEmpty() -> fail("Enter a website address.")
                    u.contains(' ') || (!u.contains('.') && !u.contains(':')) -> fail("That doesn't look like a website address.")
                    u.contains("://") || u.startsWith("mailto:") || u.startsWith("tel:") -> ok(CardItem.Website(u))
                    else -> ok(CardItem.Website("https://$u"))
                }
            }
            ItemKind.PHONE -> {
                val digits = number.filter { it.isDigit() }
                if (digits.length < 3 || number.any { !(it.isDigit() || it in " +-().") }) {
                    fail("Enter a valid phone number.")
                } else {
                    ok(CardItem.Phone(number.trim()))
                }
            }
            ItemKind.EMAIL -> if (!isEmail(email)) fail("Enter a valid email address.") else ok(CardItem.Email(email.trim()))
            ItemKind.WIFI -> when {
                ssid.isBlank() -> fail("Enter the Wi-Fi network name.")
                security == WifiSecurity.WPA2 && wifiPass.length < 8 -> fail("Wi-Fi passwords are at least 8 characters.")
                else -> ok(CardItem.Wifi(ssid.trim(), if (security == WifiSecurity.OPEN) "" else wifiPass, security))
            }
            ItemKind.CONTACT -> when {
                name.isBlank() -> fail("Enter a name.")
                contactEmail.isNotBlank() && !isEmail(contactEmail) -> fail("Check the email address.")
                else -> ok(CardItem.Contact(name.trim(), phone.trim(), contactEmail.trim(), org.trim()))
            }
            ItemKind.PASSWORD -> when {
                password.isEmpty() -> fail("Enter the password.")
                else -> ok(CardItem.Password(title.trim(), username.trim(), password, website.trim(), notes.trim()))
            }
            else -> fail("Choose what to add.")
        }
    }

    val lockable = kind == ItemKind.PASSWORD || kind == ItemKind.NOTE
    val label = if (kind == ItemKind.PASSWORD) title.trim() else title.trim().ifEmpty { "Secure note" }

    fun save() {
        val (item, problem) = build()
        error = problem
        if (item == null) return
        if (lockable && protect) {
            if (pin.length < 4) {
                error = "Choose a PIN or passphrase of at least 4 characters."
                return
            }
            if (pin != pin2) {
                error = "The two PINs don't match."
                return
            }
        }
        saving = true
        scope.launch {
            vm.saveItem(request.entryId, item, if (lockable && protect) pin else null, label)
            saving = false
            onClose()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = onClose) { Icon(Icons.Outlined.Close, "Close") } },
                title = {
                    Text(
                        when {
                            kind == null -> "What do you want to add?"
                            init == null -> "New ${kind!!.label.lowercase()}"
                            else -> "Edit ${kind!!.label.lowercase()}"
                        },
                    )
                },
                actions = {
                    if (kind != null) {
                        if (saving) {
                            CircularProgressIndicator(Modifier.size(24.dp).padding(end = 4.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(16.dp))
                        } else {
                            TextButton(onClick = ::save) { Text("Done") }
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            val current = kind
            if (current == null) {
                editableKinds.forEach { (k, desc) ->
                    ElevatedCard(onClick = { kind = k; protect = k == ItemKind.PASSWORD }, modifier = Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            KindIcon(k, 48.dp)
                            Spacer(Modifier.width(16.dp))
                            Column {
                                Text(k.label, style = MaterialTheme.typography.titleMedium)
                                Text(desc, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
                return@Column
            }

            when (current) {
                ItemKind.NOTE -> {
                    if (protect) Field(title, { title = it }, "Title (visible without PIN)", Icons.Outlined.Label)
                    OutlinedTextField(
                        value = text,
                        onValueChange = { text = it },
                        label = { Text("Note") },
                        minLines = 5,
                        modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                    )
                }
                ItemKind.WEBSITE -> Field(url, { url = it }, "Website address", Icons.Outlined.Language, KeyboardType.Uri, hint = "example.com")
                ItemKind.PHONE -> Field(number, { number = it }, "Phone number", Icons.Outlined.Call, KeyboardType.Phone, hint = "+91 98765 43210")
                ItemKind.EMAIL -> Field(email, { email = it }, "Email address", Icons.Outlined.AlternateEmail, KeyboardType.Email)
                ItemKind.WIFI -> {
                    Field(ssid, { ssid = it }, "Network name (SSID)", Icons.Outlined.Wifi)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        WifiSecurity.entries.forEach { s ->
                            FilterChip(selected = security == s, onClick = { security = s }, label = { Text(s.label) })
                        }
                    }
                    if (security == WifiSecurity.WPA2) {
                        SecretField(wifiPass, { wifiPass = it }, "Wi-Fi password")
                    }
                    Hint("Android phones can join this network just by tapping the card.")
                }
                ItemKind.CONTACT -> {
                    Field(name, { name = it }, "Name", Icons.Outlined.Person, capitalize = true)
                    Field(phone, { phone = it }, "Phone", Icons.Outlined.Call, KeyboardType.Phone)
                    Field(contactEmail, { contactEmail = it }, "Email", Icons.Outlined.AlternateEmail, KeyboardType.Email)
                    Field(org, { org = it }, "Company", Icons.Outlined.Business, capitalize = true)
                }
                ItemKind.PASSWORD -> {
                    Field(title, { title = it }, "Title", Icons.Outlined.Label, hint = "e.g. Gmail, Bank, Office PC", capitalize = true)
                    Field(username, { username = it }, "Username or email", Icons.Outlined.Person, KeyboardType.Email)
                    SecretField(password, { password = it }, "Password", allowGenerate = true)
                    Field(website, { website = it }, "Website (optional)", Icons.Outlined.Language, KeyboardType.Uri)
                    Field(notes, { notes = it }, "Notes (optional)", Icons.AutoMirrored.Outlined.Notes, capitalize = true)
                }
                else -> {}
            }

            if (lockable) {
                ProtectSection(
                    protect = protect,
                    onProtect = { protect = it },
                    pin = pin,
                    onPin = { pin = it },
                    pin2 = pin2,
                    onPin2 = { pin2 = it },
                    isPassword = current == ItemKind.PASSWORD,
                )
            }

            build().first?.let { item ->
                SizeInfo(vm, request.entryId, item, lockable && protect, label)
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
            Spacer(Modifier.height(24.dp))
        }
    }
}

private fun isEmail(s: String): Boolean {
    val t = s.trim()
    val at = t.indexOf('@')
    return at > 0 && t.indexOf('.', at) > at + 1 && !t.endsWith('.') && t.none { it.isWhitespace() }
}

@Composable
private fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    icon: ImageVector,
    keyboard: KeyboardType = KeyboardType.Text,
    hint: String? = null,
    capitalize: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = hint?.let { { Text(it) } },
        leadingIcon = { Icon(icon, null) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            keyboardType = keyboard,
            capitalization = if (capitalize) KeyboardCapitalization.Words else KeyboardCapitalization.None,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun SecretField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    allowGenerate: Boolean = false,
    icon: ImageVector = Icons.Outlined.Key,
    keyboard: KeyboardType = KeyboardType.Password,
) {
    var visible by rememberSaveable { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        leadingIcon = { Icon(icon, null) },
        trailingIcon = {
            Row {
                if (allowGenerate) {
                    IconButton(onClick = { onChange(Vault.generatePassword()); visible = true }) {
                        Icon(Icons.Outlined.Casino, "Generate a strong password")
                    }
                }
                IconButton(onClick = { visible = !visible }) {
                    Icon(if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, if (visible) "Hide" else "Show")
                }
            }
        },
        singleLine = true,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun ProtectSection(
    protect: Boolean,
    onProtect: (Boolean) -> Unit,
    pin: String,
    onPin: (String) -> Unit,
    pin2: String,
    onPin2: (String) -> Unit,
    isPassword: Boolean,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (protect) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.Lock, null)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("Protect with a PIN", style = MaterialTheme.typography.titleMedium)
                    Text(
                        if (protect) "Encrypted on the card. Only the title is visible without the PIN."
                        else "Anyone who taps this card with a phone can read it.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Switch(checked = protect, onCheckedChange = onProtect)
            }
            if (protect) {
                SecretField(pin, onPin, "PIN or passphrase", icon = Icons.Outlined.Pin, keyboard = KeyboardType.Password)
                SecretField(pin2, onPin2, "Repeat PIN", icon = Icons.Outlined.Pin, keyboard = KeyboardType.Password)
                val strength = when {
                    pin.isEmpty() -> null
                    pin.length < 6 -> "Weak: short PINs can be guessed by someone who copies your card. Use 8 or more characters."
                    pin.length < 10 -> "OK. A longer passphrase is even safer."
                    else -> "Strong"
                }
                strength?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                Text(
                    "There's no way to recover a forgotten PIN.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else if (isPassword) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.WarningAmber, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "Storing a password without protection isn't recommended.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

@Composable
private fun SizeInfo(vm: AppViewModel, entryId: Long?, item: CardItem, locked: Boolean, label: String) {
    val itemSize = if (locked) Vault.sealedRecordSize(item, label) else ItemCodec.encode(item).byteSize
    val others = vm.draft.filter { it.id != entryId }.sumOf { it.record.byteSize }
    val total = others + itemSize
    val capacity = vm.card?.capacity
    val over = capacity != null && total > capacity
    Text(
        when {
            capacity == null -> "Takes $itemSize bytes on the card"
            over -> "Too big: the card would need $total bytes but holds $capacity. Shorten something."
            else -> "Takes $itemSize bytes · card will use $total of $capacity bytes"
        },
        style = MaterialTheme.typography.bodySmall,
        color = if (over) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
