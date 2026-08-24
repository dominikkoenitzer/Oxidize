//! The Oxidize engine, packaged as a library so the `oxidize` command-line
//! binary and the `oxidize-gui` binary share one copy of the uninstall, scan,
//! backup and safety code.
//!
//! The two front-ends are `main.rs` and `bin/oxidize-gui.rs`.

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
