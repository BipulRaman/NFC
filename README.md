# NFC Studio

Read and write smart cards / NFC tags from a desktop PC (PC/SC reader) or an Android phone (built-in NFC).

```
app/
├── desktop/          Rust crate `nfc-studio` – portable core (APDU, NDEF) + egui desktop GUI (PC/SC)
└── android/          Android Studio project
    ├── app/          Kotlin UI using Android NFC APIs (reader mode)
    └── rust/         JNI crate `nfc_jni` reusing the desktop crate's core
```

## Desktop app

Place a card on any connected reader and it's read automatically; no buttons needed. The main screen
shows, in plain language:

- **What the card is**: NFC tag (NTAG/Ultralight), MIFARE Classic card, or smart card, plus its card ID.
- **On this card**: its contents as websites, text, phone numbers, email addresses, contacts or Wi-Fi
  networks, with Open/Call/Copy buttons and a bar showing how much space is used.
- **Write to card**: choose Text, Website, Phone or Email, type the value and press *Write to card*.
  Input is checked and size-checked before writing, and replacing or erasing existing content asks
  for confirmation. Blank MIFARE Classic 1K cards can be set up for messages with one click.

Supported for reading and writing: NFC Forum Type 2 tags (NTAG21x, Ultralight), Type 4 tags (NDEF
application, e.g. NTAG 424 / DESFire), NFC-formatted MIFARE Classic and **ISO 15693 / NFC-V RFID
tags** (NXP ICODE SLIX, TI Tag-it, ST LRI; NFC Forum Type 5). Blank MIFARE Classic 1K cards and blank
ISO 15693 tags can be set up with one click. ISO 15693 tags holding another system's data (e.g. library
books) are left untouched. Bank, ID, HID iCLASS and other secure cards are identified but their
protected data isn't shown. TPM virtual smart cards (Windows Hello) are hidden from the reader list.

**125 kHz badges** tab: plug in a USB 125 kHz RFID reader (EM4100 / HID Prox / T5577 readers that type
the card number like a keyboard) and scan badges. The app recognises the reader's fast typing, shows
the number with its hex and 26-bit facility/card forms, and keeps a scan history you can copy.

**Advanced tools** (top right) has the low-level views: raw APDU console, MIFARE Classic block
read/write with custom keys, NTAG page read/write and a command log.

Prerequisites:
- Rust (stable, edition 2024)
- A PC/SC reader (e.g. ACR122U)
- Windows: the *Smart Card* service (built in). Linux: `sudo apt install pcscd libpcsclite-dev`. macOS: built in.

```sh
cd app/desktop
cargo run --release
cargo test
```

## Android app

A Material 3 (Jetpack Compose) card wallet. Tap a card to see what's on it, edit it in the app, then
tap **Save to card** and hold the card to the phone to write it.

- **Store**: passwords (title, username, password with a generator, website, notes), notes, Wi-Fi
  networks (other phones can join by tapping), websites, contacts, phone numbers and email addresses.
- **Protect with a PIN**: passwords and notes can be encrypted on the card (PBKDF2-SHA256 →
  AES-256-GCM). Only the title is visible without the PIN. Unlocked items are hidden again when the app
  goes to the background, and screenshots are blocked while secrets are on screen.
- **Manage**: add, edit, reorder and delete items (with undo); erase a card; copy everything to
  another card; lock a card permanently. Blank cards are set up automatically on the first save, and
  a size meter stops you from writing more than the card holds.
- **Advanced tools**: raw memory dump and APDU commands for smart cards.
- **RFID**: works with 13.56 MHz NFC and RFID tags, including ISO 15693 / NFC-V tags (ICODE, Tag-it).
  These are read, written and set up directly even on phones without built-in NDEF support for them;
  tags holding another system's data are never overwritten. 125 kHz badges can't be read by phones;
  use the desktop app with a 125 kHz USB reader.

Items use standard NDEF records where they exist (text, URI, `application/vnd.wfa.wsc`, `text/vcard`),
so other phones understand them; passwords use `application/vnd.nfcstudio.password` and protected
items `application/vnd.nfcstudio.locked`.

Unit tests (codec, encryption and ISO 15693): `gradle testDebugUnitTest` in `app/android`.

1. Install Android Studio with SDK 34, the NDK, and JDK 17.
2. Build the native library:
   ```sh
   cargo install cargo-ndk
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   cd app/android/rust
   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../app/src/main/jniLibs build --release
   ```
3. Open `app/android` in Android Studio (it generates the Gradle wrapper) and run on an NFC-capable phone.

## Tamper protection (both apps)

- **Tamper seal**: when saving, both apps add a digital signature (ECDSA P-256) over the content and the
  card's unique ID as an extra NDEF record (`nfcstudio.dev:seal`). Reading a sealed card shows
  **Sealed by you**, **Sealed by another device** (with the key's fingerprint) or **Seal broken** if
  the content was changed or copied to another card. Works on every writable card type; it adds 119 bytes.
  Each phone keeps its key in the Android Keystore; the desktop keeps it in `%APPDATA%\NFC Studio\seal-key`
  (`~/.config/nfc-studio/seal-key` elsewhere).
- **Write password** (NTAG213/215/216, MIFARE Ultralight EV1): the chip's own password protection. Anyone
  can still read the card, but changes need the password. The password is turned into the chip's 32-bit
  PWD/PACK with PBKDF2 and the card ID, and the card can freeze itself after 7 wrong attempts to stop
  guessing. Passwords are only kept in memory for the session.
- **Erase completely**: wipes every byte of an NTAG / Ultralight EV1 card and removes its password, so it's like new. Works with passwords set in NFC Studio, NFC Tools (MD5-based) or entered as 8 raw hex digits. A forgotten password or a permanently locked card can't be erased; the chip enforces this.
- **Lock permanently**: makes the card read-only forever (static lock bits, read-only flag, and a random
  unknown password with a one-attempt limit for the rest of the memory).

Write protection stops changes, not reading; keep secrets in PIN-protected items. On the desktop, the
password and lock need a reader that can send raw tag commands (PC/SC transparent session, e.g. OMNIKEY
5022 or ACR1252U, or an ACR122U); the seal works with any reader.

## App icon

The icon's source is `assets/icon.svg` (plus `icon-foreground.svg` / `icon-monochrome.svg` for Android's adaptive and themed icons). After editing them, run `pwsh assets/render-icons.ps1` (needs `cargo install resvg`) to regenerate the desktop window icon and `.exe` icon (`app/desktop/assets`) and the Android launcher icons (`mipmap-*`).

## CI / Releases

`.github/workflows/build.yml` builds and tests both apps on every push to `main`, pull request and manual run. These runs only build: nothing is packaged or published, and the token is read-only. When a GitHub release is **published**, it also attaches the binaries to that release: desktop archives for Windows x64, Linux x64 and macOS (arm64 and x64), plus a debug-signed Android APK.

Android CI explicitly installs platform tools, SDK platform 34 and build tools 34.0.0 instead of the unavailable legacy `tools` package.

Tag releases with a semantic version such as `1.0.0` (a leading `v`, as in `v1.0.0`, is also accepted). The tag version is stamped into the desktop crate and the APK (`versionName` = `1.0.0`, `versionCode` = `10000`), and the assets are named after it, for example `nfc-studio-1.0.0-windows-x64.zip`, `nfc-studio-1.0.0-linux-x64.tar.gz` and `nfc-studio-1.0.0-android.apk`. If the tag isn't in that format, the release build fails.

Release APKs are signed with a permanent key so new versions install as updates over old ones (each release's `versionCode` is higher). The key lives in the repository secrets `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD` and `ANDROID_KEY_ALIAS`; a release build fails if they're missing. Keep a backup of the keystore: if it's lost, existing installs can't be updated. Builds that aren't releases are debug-signed for testing only.
