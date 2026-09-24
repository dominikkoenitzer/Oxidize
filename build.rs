//! Embeds `assets/oxidize.ico` into both executables, so Explorer, the
//! taskbar and Alt-Tab show the mark. A failure stops the build: a release
//! without its icon should not ship quietly.

fn main() {
    println!("cargo:rerun-if-changed=assets/oxidize.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/oxidize.ico")
            .compile()
            .expect("embed assets/oxidize.ico");
    }
}
