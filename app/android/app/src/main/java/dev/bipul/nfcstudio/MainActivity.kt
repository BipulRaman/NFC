package dev.bipul.nfcstudio

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import dev.bipul.nfcstudio.ui.AppViewModel
import dev.bipul.nfcstudio.ui.NfcState
import dev.bipul.nfcstudio.ui.NfcStudioApp
import dev.bipul.nfcstudio.ui.theme.NfcStudioTheme

class MainActivity : ComponentActivity(), NfcAdapter.ReaderCallback {

    private val vm: AppViewModel by viewModels()
    private var adapter: NfcAdapter? = null
    private var resumed = false

    private val nfcStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            refreshNfc()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        adapter = NfcAdapter.getDefaultAdapter(this)
        setContent {
            NfcStudioTheme {
                NfcStudioApp(vm, setSecure = ::setSecure)
            }
        }
        ContextCompat.registerReceiver(
            this,
            nfcStateReceiver,
            IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        if (savedInstanceState == null) handleLaunchTag(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLaunchTag(intent)
    }

    /** The app was opened by tapping a card; read it like any other tap. */
    private fun handleLaunchTag(intent: Intent?) {
        val tag = intent?.let { IntentCompat.getParcelableExtra(it, NfcAdapter.EXTRA_TAG, Tag::class.java) } ?: return
        Thread { vm.onTag(tag) }.start()
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        refreshNfc()
    }

    override fun onPause() {
        super.onPause()
        resumed = false
        adapter?.disableReaderMode(this)
    }

    override fun onStop() {
        super.onStop()
        // Re-lock protected items when the app goes to the background.
        if (!isChangingConfigurations) vm.hideSecrets()
    }

    override fun onDestroy() {
        unregisterReceiver(nfcStateReceiver)
        super.onDestroy()
    }

    private fun refreshNfc() {
        val nfc = adapter
        vm.nfc = when {
            nfc == null -> NfcState.MISSING
            !nfc.isEnabled -> NfcState.OFF
            else -> NfcState.READY
        }
        if (nfc != null && nfc.isEnabled && resumed) {
            val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_NFC_F or NfcAdapter.FLAG_READER_NFC_V
            val extras = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250) }
            nfc.enableReaderMode(this, this, flags, extras)
        }
    }

    /** Called on a binder thread whenever a card enters the field. */
    override fun onTagDiscovered(tag: Tag) = vm.onTag(tag)

    private fun setSecure(secure: Boolean) {
        if (secure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
