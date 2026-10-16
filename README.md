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

Features: list PC/SC readers, connect to card, show ATR/UID, send raw APDUs, read/write NDEF
(Type 2 tags via PC/SC pseudo-APDUs), MIFARE Classic block read/write.

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

`.github/workflows/build.yml` builds and tests both apps on every push to `main`, pull request and manual run. When a GitHub release is **published**, it also attaches the binaries to that release: desktop archives for Windows x64, Linux x64 and macOS (arm64 and x64), plus a debug-signed Android APK.

Tag releases with a semantic version such as `1.0.0` (a leading `v`, as in `v1.0.0`, is also accepted). The tag version is stamped into the desktop crate and the APK (`versionName` = `1.0.0`, `versionCode` = `10000`), and the assets are named after it, for example `nfc-studio-1.0.0-windows-x64.zip`, `nfc-studio-1.0.0-linux-x64.tar.gz` and `nfc-studio-1.0.0-android.apk`. If the tag isn't in that format, the release build fails.

