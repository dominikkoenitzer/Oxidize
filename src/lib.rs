//! Oxidize — engine + CLI exposed as a library so that both the `oxidize`
//! (command-line) and `oxidize-gui` (graphical) binaries can share exactly the
//! same uninstall/scan/backup/safety logic.
//!
//! See `main.rs` (CLI) and `bin/oxidize-gui.rs` (GUI) for the two front-ends.

pub mod backup;
pub mod cli;
pub mod commands;
pub mod hunter;
pub mod model;
pub mod registry;
pub mod safety;
pub mod scanner;
pub mod term;
pub mod uninstall;
pub mod util;
