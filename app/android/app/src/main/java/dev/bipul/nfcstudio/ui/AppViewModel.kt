package dev.bipul.nfcstudio.ui

import android.app.Application
import android.nfc.Tag
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import dev.bipul.nfcstudio.NfcCore
import dev.bipul.nfcstudio.data.CardItem
import dev.bipul.nfcstudio.data.ItemCodec
import dev.bipul.nfcstudio.data.KeystoreSigner
import dev.bipul.nfcstudio.data.RawRecord
import dev.bipul.nfcstudio.data.Seal
import dev.bipul.nfcstudio.data.Vault
import dev.bipul.nfcstudio.data.WrongPinException
import dev.bipul.nfcstudio.data.messageSize
import dev.bipul.nfcstudio.nfc.CardException
import dev.bipul.nfcstudio.nfc.CardIo
import dev.bipul.nfcstudio.nfc.CardSnapshot
import dev.bipul.nfcstudio.nfc.NeedsPasswordException
import dev.bipul.nfcstudio.nfc.WrongPasswordException
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.withContext

enum class NfcState { READY, OFF, MISSING }

enum class Screen { HOME, CARD, TOOLS }

/** One item in the editable list; [raw] keeps the exact original bytes until the item is edited. */
data class Entry(val id: Long, val item: CardItem, val raw: RawRecord? = null) {
    val record: RawRecord get() = raw ?: ItemCodec.encode(item)
}

/** Something that happens on the next tap. */
sealed interface Pending {
    data class Save(val records: List<RawRecord>, val seal: Boolean) : Pending
    data object Erase : Pending
    data object MakeReadOnly : Pending
    data class SetPassword(val password: String, val limitAttempts: Boolean) : Pending
    data object RemovePassword : Pending
    data object Dump : Pending
    data class Apdu(val commands: List<ByteArray>) : Pending
}

sealed interface TapSheet {
    data class Waiting(val pending: Pending) : TapSheet
    data class Working(val pending: Pending) : TapSheet
    data class Done(val message: String) : TapSheet
    /** [askPassword]: the tapped card ([cardId]) needs its write password to continue. */
    data class Failed(
        val pending: Pending,
        val message: String,
        val askPassword: Boolean = false,
        val cardId: String? = null,
    ) : TapSheet
}

data class UserMessage(val text: String, val undo: (() -> Unit)? = null)

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val main = Handler(Looper.getMainLooper())
    private val ids = AtomicLong()

    var nfc by mutableStateOf(NfcState.READY)
    var screen by mutableStateOf(Screen.HOME)
    var card by mutableStateOf<CardSnapshot?>(null)
        private set
    val draft = mutableStateListOf<Entry>()
    private var baseline: List<RawRecord> = emptyList()

    /** Decrypted contents of locked items, kept only in memory while the card is open. */
    val revealed = mutableStateMapOf<Long, CardItem>()
    private val pins = HashMap<Long, String>()

    /** Card write passwords entered this session, by card ID (memory only). */
    private val cardPasswords = java.util.concurrent.ConcurrentHashMap<String, String>()

    /** Add a tamper seal whenever content is saved. */
    var sealOnSave by mutableStateOf(true)

    /** This phone's seal key, once one exists. */
    var mySealKey by mutableStateOf<ByteArray?>(null)
        private set

    init {
        Thread { KeystoreSigner.existingPublicKey()?.let { k -> main.post { mySealKey = k } } }.start()
    }

    var sheet by mutableStateOf<TapSheet?>(null)
        private set
    @Volatile private var pending: Pending? = null

    /** A card tapped while there were unsaved edits, waiting for the user to decide. */
    var incoming by mutableStateOf<CardSnapshot?>(null)
        private set

    /** Bumped on every successful tap so the UI can give haptic feedback. */
    var taps by mutableIntStateOf(0)
        private set

    val log = mutableStateListOf<String>()

    private val messageChannel = Channel<UserMessage>(Channel.BUFFERED)
    val messages = messageChannel.receiveAsFlow()

    fun say(text: String, undo: (() -> Unit)? = null) {
        messageChannel.trySend(UserMessage(text, undo))
    }

    // ---- Derived state -------------------------------------------------------------

    fun draftRecords(): List<RawRecord> = draft.map { it.record }

    val isDirty: Boolean get() = draftRecords() != baseline

    val draftSize: Int get() = messageSize(draftRecords()) + if (willSeal) Seal.RECORD_SIZE else 0

    /** A seal will be added when the draft is saved. */
    val willSeal: Boolean get() = sealOnSave && draft.isNotEmpty() && (card?.let { Seal.uidIsStable(it.id) } ?: true)

    val sealedByMe: Boolean
        get() = (card?.seal as? Seal.Status.Valid)?.key?.let { k -> mySealKey?.contentEquals(k) } == true

    val canEdit: Boolean get() = card?.let { it.supported && it.writable } ?: true

    private fun idOf(tag: Tag) = tag.id.joinToString(":") { "%02X".format(it) }

    // ---- Taps (called on a binder thread) ---------------------------------------------

    fun onTag(tag: Tag) {
        when (val op = pending) {
            null -> {
                val result = runCatching { CardIo.read(tag) }
                main.post {
                    result.fold(
                        onSuccess = ::onCardRead,
                        onFailure = { say(it.message ?: "Couldn't read the card. Try again.") },
                    )
                }
            }
            else -> {
                main.post { sheet = TapSheet.Working(op) }
                val result = runCatching { perform(tag, op) }
                main.post {
                    result.fold(
                        onSuccess = { (message, snap) ->
                            pending = null
                            if (snap != null) loadCard(snap)
                            taps++
                            sheet = TapSheet.Done(message)
                            main.postDelayed({ if (sheet is TapSheet.Done) sheet = null }, 1600)
                        },
                        onFailure = { e ->
                            sheet = when (e) {
                                is NeedsPasswordException ->
                                    TapSheet.Failed(op, "This card is write-protected. Enter its password.", true, idOf(tag))
                                is WrongPasswordException -> {
                                    cardPasswords.remove(idOf(tag))
                                    TapSheet.Failed(op, "Wrong card password. Try again.", true, idOf(tag))
                                }
                                else -> TapSheet.Failed(op, (e as? CardException)?.message ?: e.message ?: "Something went wrong.")
                            }
                        },
                    )
                }
            }
        }
    }

    private fun perform(tag: Tag, op: Pending): Pair<String, CardSnapshot?> {
        val password = cardPasswords[idOf(tag)]
        return when (op) {
            is Pending.Save -> {
                val signer = if (op.seal) KeystoreSigner else null
                CardIo.write(tag, op.records, password, signer)
                if (signer != null) main.post { mySealKey = KeystoreSigner.existingPublicKey() }
                (if (signer != null && Seal.uidIsStable(tag.id)) "Saved and sealed" else "Saved to card") to CardIo.read(tag)
            }
            Pending.Erase -> {
                CardIo.write(tag, emptyList(), password)
                "Card erased" to CardIo.read(tag)
            }
            Pending.MakeReadOnly -> {
                CardIo.makeReadOnly(tag, password)
                cardPasswords.remove(idOf(tag))
                "Card locked permanently" to CardIo.read(tag)
            }
            is Pending.SetPassword -> {
                CardIo.setPassword(tag, op.password, op.limitAttempts, password)
                cardPasswords[idOf(tag)] = op.password
                "Card password set" to CardIo.read(tag)
            }
            Pending.RemovePassword -> {
                CardIo.removePassword(tag, password ?: throw NeedsPasswordException())
                cardPasswords.remove(idOf(tag))
                "Card password removed" to CardIo.read(tag)
            }
            Pending.Dump -> {
                val lines = CardIo.dump(tag)
                main.post { log.addAll(lines); log.add("") }
                "Memory read (${lines.size} lines)" to null
            }
            is Pending.Apdu -> {
                val lines = CardIo.sendApdus(tag, op.commands)
                main.post { log.addAll(lines); log.add("") }
                "Sent ${op.commands.size} command(s)" to null
            }
        }
    }

    /** Remembers the write password for the current card (or [cardId]) for this session. */
    fun rememberCardPassword(password: String, cardId: String? = card?.idHex) {
        if (cardId != null && password.isNotEmpty()) cardPasswords[cardId] = password
    }

    /** Retries the failed tap action with a card password the user just entered. */
    fun retryWithPassword(password: String) {
        val failed = sheet as? TapSheet.Failed ?: return
        rememberCardPassword(password, failed.cardId)
        retry()
    }

    private fun onCardRead(snap: CardSnapshot) {
        if (screen == Screen.CARD && isDirty) {
            incoming = snap
            return
        }
        loadCard(snap)
        taps++
        if (snap.damaged) say("The data on this card is damaged. Erase it or save new content to fix it.")
    }

    private fun loadCard(snap: CardSnapshot) {
        card = snap
        draft.clear()
        draft.addAll(snap.records.map { Entry(ids.incrementAndGet(), ItemCodec.decode(it), it) })
        baseline = snap.records
        hideSecrets()
        incoming = null
        if (screen == Screen.HOME) screen = Screen.CARD
    }

    fun acceptIncoming(discard: Boolean) {
        val snap = incoming ?: return
        if (discard) {
            loadCard(snap)
            taps++
        } else {
            incoming = null
        }
    }

    // ---- Editing ------------------------------------------------------------------

    fun newCard() {
        card = null
        draft.clear()
        baseline = emptyList()
        hideSecrets()
        screen = Screen.CARD
    }

    fun close() {
        screen = Screen.HOME
        card = null
        draft.clear()
        baseline = emptyList()
        hideSecrets()
    }

    fun discardChanges() {
        card?.let(::loadCard) ?: newCard()
    }

    /** Adds or replaces an item. Locking runs off the main thread because key derivation is slow. */
    suspend fun saveItem(id: Long?, item: CardItem, lockWith: String?, label: String) {
        val stored = if (lockWith != null) {
            withContext(Dispatchers.Default) { Vault.seal(item, label, lockWith) }
        } else {
            item
        }
        val entryId = id ?: ids.incrementAndGet()
        val entry = Entry(entryId, stored)
        val index = draft.indexOfFirst { it.id == entryId }
        if (index >= 0) draft[index] = entry else draft.add(entry)
        if (lockWith != null) {
            revealed[entryId] = item
            pins[entryId] = lockWith
        } else {
            revealed.remove(entryId)
            pins.remove(entryId)
        }
    }

    fun delete(id: Long) {
        val index = draft.indexOfFirst { it.id == id }
        if (index < 0) return
        val removed = draft.removeAt(index)
        say("${title(removed)} removed") { draft.add(index.coerceAtMost(draft.size), removed) }
    }

    fun move(id: Long, by: Int) {
        val from = draft.indexOfFirst { it.id == id }
        val to = from + by
        if (from < 0 || to !in draft.indices) return
        draft.add(to, draft.removeAt(from))
    }

    suspend fun unlock(id: Long, pin: String): Boolean {
        val locked = draft.firstOrNull { it.id == id }?.item as? CardItem.Locked ?: return false
        return try {
            val inner = withContext(Dispatchers.Default) { Vault.open(locked, pin) }
            revealed[id] = inner
            pins[id] = pin
            true
        } catch (e: WrongPinException) {
            false
        }
    }

    fun pinFor(id: Long): String? = pins[id]

    fun hide(id: Long) {
        revealed.remove(id)
        pins.remove(id)
    }

    fun hideSecrets() {
        revealed.clear()
        pins.clear()
    }

    /** Called when the app goes to the background. */
    fun forgetCardPasswords() = cardPasswords.clear()

    // ---- Tap actions ----------------------------------------------------------------

    fun requestSave(seal: Boolean = sealOnSave) = arm(Pending.Save(draftRecords(), seal))

    fun requestErase() = arm(Pending.Erase)

    fun requestMakeReadOnly() = arm(Pending.MakeReadOnly)

    fun requestSetPassword(password: String, limitAttempts: Boolean) = arm(Pending.SetPassword(password, limitAttempts))

    fun requestRemovePassword() = arm(Pending.RemovePassword)

    fun requestDump() = arm(Pending.Dump)

    fun requestApdus(text: String) {
        val commands = try {
            text.split(';', '\n').map(String::trim).filter(String::isNotEmpty).map(NfcCore::parseHex)
        } catch (e: IllegalArgumentException) {
            say(e.message ?: "Invalid hex")
            return
        }
        if (commands.isEmpty()) say("Type at least one command, e.g. 00 A4 04 00 00") else arm(Pending.Apdu(commands))
    }

    private fun arm(op: Pending) {
        pending = op
        sheet = TapSheet.Waiting(op)
    }

    fun retry() {
        (sheet as? TapSheet.Failed)?.let { sheet = TapSheet.Waiting(it.pending) }
    }

    fun cancelTap() {
        pending = null
        sheet = null
    }

    companion object {
        fun title(e: Entry): String = when (val i = e.item) {
            is CardItem.Locked -> i.label.ifBlank { i.innerKind.label }
            is CardItem.Password -> i.title.ifBlank { "Password" }
            else -> i.kind.label
        }
    }
}
