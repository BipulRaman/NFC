fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    // Embed the app icon in the .exe so Explorer, the taskbar and shortcuts show it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Couldn't embed the app icon: {e}");
        }
    }
}
