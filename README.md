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
application, e.g. NTAG 424 / DESFire) and NFC-formatted MIFARE Classic. Bank, ID and other secure
cards are identified but their protected data isn't shown.

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

Features: read NDEF / MIFARE Ultralight / MIFARE Classic dumps, write Text or URI NDEF records,
send APDUs to ISO-DEP cards (separate multiple commands with `;`).

1. Install Android Studio with SDK 34, the NDK, and JDK 17.
2. Build the native library:
   ```sh
   cargo install cargo-ndk
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   cd app/android/rust
   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../app/src/main/jniLibs build --release
   ```
3. Open `app/android` in Android Studio (it generates the Gradle wrapper) and run on an NFC-capable phone.

## CI / Releases

`.github/workflows/build.yml` builds and tests both apps on every push to `main`, pull request and manual run. These runs only build: nothing is packaged or published, and the token is read-only. When a GitHub release is **published**, it also attaches the binaries to that release: desktop archives for Windows x64, Linux x64 and macOS (arm64 and x64), plus a debug-signed Android APK.

Android CI explicitly installs platform tools, SDK platform 34 and build tools 34.0.0 instead of the unavailable legacy `tools` package.

Tag releases with a semantic version such as `1.0.0` (a leading `v`, as in `v1.0.0`, is also accepted). The tag version is stamped into the desktop crate and the APK (`versionName` = `1.0.0`, `versionCode` = `10000`), and the assets are named after it, for example `nfc-studio-1.0.0-windows-x64.zip`, `nfc-studio-1.0.0-linux-x64.tar.gz` and `nfc-studio-1.0.0-android.apk`. If the tag isn't in that format, the release build fails.
