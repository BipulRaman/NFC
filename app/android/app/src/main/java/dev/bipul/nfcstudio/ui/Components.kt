package dev.bipul.nfcstudio.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PersistableBundle
import android.provider.ContactsContract
import android.provider.Settings
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Call
import androidx.compose.material.icons.outlined.Contactless
import androidx.compose.material.icons.outlined.DataObject
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.bipul.nfcstudio.data.CardItem
import dev.bipul.nfcstudio.data.ItemKind
import dev.bipul.nfcstudio.nfc.CardSnapshot

data class KindStyle(val icon: ImageVector, val color: Color)

fun kindStyle(kind: ItemKind): KindStyle = when (kind) {
    ItemKind.PASSWORD -> KindStyle(Icons.Outlined.Key, Color(0xFFE8710A))
    ItemKind.NOTE -> KindStyle(Icons.Outlined.Description, Color(0xFF0F9D58))
    ItemKind.WEBSITE -> KindStyle(Icons.Outlined.Language, Color(0xFF1A73E8))
    ItemKind.PHONE -> KindStyle(Icons.Outlined.Call, Color(0xFF188038))
    ItemKind.EMAIL -> KindStyle(Icons.Outlined.Email, Color(0xFFD93025))
    ItemKind.WIFI -> KindStyle(Icons.Outlined.Wifi, Color(0xFF00897B))
    ItemKind.CONTACT -> KindStyle(Icons.Outlined.Person, Color(0xFF9334E6))
    ItemKind.LOCKED -> KindStyle(Icons.Outlined.Lock, Color(0xFF5C6BC0))
    ItemKind.UNKNOWN -> KindStyle(Icons.Outlined.DataObject, Color(0xFF78909C))
}

/** Short description used in item headers and messages. */
fun describe(item: CardItem): Pair<String, String> = when (item) {
    is CardItem.Note -> "Note" to item.text
    is CardItem.Website -> (if (item.url.startsWith("http", true)) "Website" else "Link") to item.url
    is CardItem.Phone -> "Phone" to item.number
    is CardItem.Email -> "Email" to item.address
    is CardItem.Wifi -> "Wi-Fi" to item.ssid
    is CardItem.Contact -> "Contact" to listOf(item.name, item.organization).filter { it.isNotBlank() }.joinToString(" · ")
    is CardItem.Password -> item.title.ifBlank { "Password" } to item.username.ifBlank { item.website }
    is CardItem.Locked -> item.label.ifBlank { item.innerKind.label } to "Protected ${item.innerKind.label.lowercase()}"
    is CardItem.Unknown -> "Other data" to "${item.record.typeString.ifBlank { "Unknown type" }} · ${item.record.payload.size} bytes"
}

@Composable
fun KindIcon(kind: ItemKind, size: Dp = 44.dp) {
    val style = kindStyle(kind)
    Box(
        Modifier.size(size).clip(CircleShape).background(style.color.copy(alpha = 0.14f)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(style.icon, contentDescription = null, tint = style.color, modifier = Modifier.size(size * 0.52f))
    }
}

/** An NFC symbol with expanding rings, inviting the user to tap a card. */
@Composable
fun PulsingNfc(modifier: Modifier = Modifier, size: Dp = 180.dp, color: Color = MaterialTheme.colorScheme.primary) {
    val transition = rememberInfiniteTransition(label = "pulse")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(2200, easing = LinearEasing), RepeatMode.Restart),
        label = "phase",
    )
    Box(
        modifier.size(size).drawBehind {
            val maxR = this.size.minDimension / 2
            for (i in 0 until 3) {
                val p = (phase + i / 3f) % 1f
                drawCircle(
                    color = color.copy(alpha = (1f - p) * 0.35f),
                    radius = maxR * (0.35f + 0.65f * p),
                    style = Stroke(width = 3.dp.toPx()),
                )
            }
            drawCircle(color.copy(alpha = 0.12f), radius = maxR * 0.36f)
        },
        contentAlignment = Alignment.Center,
    ) {
        Icon(Icons.Outlined.Nfc, contentDescription = null, tint = color, modifier = Modifier.size(size * 0.28f))
    }
}

/** The card shown at the top of the card screen, styled like a physical card. */
@Composable
fun CardHeader(card: CardSnapshot?, used: Int, itemCount: Int) {
    val scheme = MaterialTheme.colorScheme
    val brush = Brush.linearGradient(listOf(scheme.primary, scheme.tertiary))
    val capacity = card?.capacity
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(28.dp))
            .background(brush)
            .padding(22.dp),
    ) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.Contactless, null, tint = Color.White, modifier = Modifier.size(28.dp))
                Spacer(Modifier.width(10.dp))
                Text(
                    card?.typeName ?: "New card",
                    color = Color.White,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (card != null && card.supported && !card.writable) {
                    Pill("Read-only", Icons.Outlined.Lock)
                } else if (card?.blank == true) {
                    Pill("Blank", null)
                }
            }
            Spacer(Modifier.height(26.dp))
            Text(
                card?.idHex ?: "Not saved to a card yet",
                color = Color.White.copy(alpha = 0.92f),
                style = MaterialTheme.typography.titleMedium,
                fontFamily = if (card != null) FontFamily.Monospace else FontFamily.Default,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(18.dp))
            if (capacity != null && capacity > 0) {
                LinearProgressIndicator(
                    progress = { (used.toFloat() / capacity).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                    color = if (used > capacity) Color(0xFFFFB4AB) else Color.White,
                    trackColor = Color.White.copy(alpha = 0.25f),
                )
                Spacer(Modifier.height(8.dp))
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    "$itemCount item${if (itemCount == 1) "" else "s"}",
                    color = Color.White.copy(alpha = 0.85f),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    when {
                        capacity != null -> "$used of $capacity bytes"
                        card?.supported == false -> ""
                        else -> "$used bytes"
                    },
                    color = Color.White.copy(alpha = 0.85f),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun Pill(text: String, icon: ImageVector?) {
    Surface(color = Color.White.copy(alpha = 0.2f), shape = RoundedCornerShape(50)) {
        Row(Modifier.padding(horizontal = 10.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) {
                Icon(icon, null, tint = Color.White, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(4.dp))
            }
            Text(text, color = Color.White, style = MaterialTheme.typography.labelMedium)
        }
    }
}

// ---- Platform helpers ----------------------------------------------------------------

fun copyToClipboard(context: Context, label: String, text: String, sensitive: Boolean) {
    val clip = ClipData.newPlainText(label, text)
    if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}

/** Starts [intent], returning false if no app can handle it. */
fun launch(context: Context, intent: Intent): Boolean = try {
    context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    true
} catch (e: ActivityNotFoundException) {
    false
}

fun viewIntent(uri: String) = Intent(Intent.ACTION_VIEW, Uri.parse(uri))

fun dialIntent(number: String) = Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + Uri.encode(number)))

fun emailIntent(address: String) = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:$address"))

fun wifiSettingsIntent() = Intent(Settings.ACTION_WIFI_SETTINGS)

fun nfcSettingsIntent() = Intent(Settings.ACTION_NFC_SETTINGS)

fun addContactIntent(c: CardItem.Contact) = Intent(ContactsContract.Intents.Insert.ACTION).apply {
    type = ContactsContract.RawContacts.CONTENT_TYPE
    putExtra(ContactsContract.Intents.Insert.NAME, c.name)
    if (c.phone.isNotBlank()) putExtra(ContactsContract.Intents.Insert.PHONE, c.phone)
    if (c.email.isNotBlank()) putExtra(ContactsContract.Intents.Insert.EMAIL, c.email)
    if (c.organization.isNotBlank()) putExtra(ContactsContract.Intents.Insert.COMPANY, c.organization)
}
