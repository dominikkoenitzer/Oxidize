//! Build script: embed the Oxidize icon into the Windows executables so they
//! show a proper icon in Explorer, the taskbar, and Alt-Tab.
//!
//! The resource is linked into every binary in the package (both `oxidize-cli`
//! and `oxidize-gui` get the same icon). Embedding is best-effort: if the
//! Windows resource compiler can't be found, we warn but don't fail the build.

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/oxidize.ico");
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/oxidize.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed application icon: {e}");
        }
    }
}
