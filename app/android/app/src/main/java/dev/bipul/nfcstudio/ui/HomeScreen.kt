package dev.bipul.nfcstudio.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.bipul.nfcstudio.data.ItemKind

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun HomeScreen(vm: AppViewModel, snackbar: SnackbarHostState) {
    val context = LocalContext.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("NFC Studio") },
                actions = {
                    IconButton(onClick = { vm.screen = Screen.TOOLS }) {
                        Icon(Icons.Outlined.Build, contentDescription = "Advanced tools")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(24.dp))
            when (vm.nfc) {
                NfcState.READY -> {
                    PulsingNfc(size = 220.dp)
                    Spacer(Modifier.height(16.dp))
                    Text("Ready to scan", style = MaterialTheme.typography.headlineSmall)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Hold an NFC or RFID card, tag or sticker against the back of your phone to see what's on it.",
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    if (vm.deepScan) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    "Deep scan is on: cards your phone normally ignores, such as read-protected ones, are read directly.",
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.weight(1f),
                                )
                                TextButton(onClick = { vm.deepScan = false }) { Text("Turn off") }
                            }
                        }
                    } else {
                        TextButton(onClick = {
                            vm.deepScan = true
                            vm.say("Deep scan is on. Hold the card to the phone again.")
                        }) { Text("Card not detected? Try deep scan") }
                    }
                }
                NfcState.OFF -> {
                    Icon(Icons.Outlined.Nfc, null, Modifier.size(96.dp), tint = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(16.dp))
                    Text("NFC is turned off", style = MaterialTheme.typography.headlineSmall)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Turn on NFC to read and write cards.",
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { launch(context, nfcSettingsIntent()) }) { Text("Open NFC settings") }
                }
                NfcState.MISSING -> {
                    Icon(Icons.Outlined.Nfc, null, Modifier.size(96.dp), tint = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(16.dp))
                    Text("No NFC on this phone", style = MaterialTheme.typography.headlineSmall)
                    Text(
                        "This device doesn't have an NFC reader, so it can't read or write cards.",
                        textAlign = TextAlign.Center,
                    )
                }
            }

            Spacer(Modifier.height(28.dp))
            OutlinedButton(onClick = vm::newCard, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Icon(Icons.Outlined.Add, null)
                Spacer(Modifier.width(8.dp))
                Text("Create content for a new card")
            }

            Spacer(Modifier.height(28.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(20.dp)) {
                    Text("What you can store", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(14.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp),
                    ) {
                        listOf(
                            ItemKind.PASSWORD, ItemKind.NOTE, ItemKind.WIFI, ItemKind.WEBSITE,
                            ItemKind.CONTACT, ItemKind.PHONE, ItemKind.EMAIL,
                        ).forEach { kind ->
                            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.width(72.dp)) {
                                KindIcon(kind, 48.dp)
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    kind.label.substringBefore(' '),
                                    style = MaterialTheme.typography.labelMedium,
                                    textAlign = TextAlign.Center,
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(18.dp))
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(Icons.Outlined.Shield, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            "Passwords and notes can be locked with a PIN. They're encrypted on the card, " +
                                "so anyone without the PIN only sees the title.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(Icons.Outlined.Nfc, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            "Works with 13.56 MHz NFC and RFID tags: NTAG, MIFARE, ICODE / ISO 15693 and FeliCa. " +
                                "125 kHz access badges can't be read by phones; use NFC Studio for desktop with a " +
                                "125 kHz USB reader.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
