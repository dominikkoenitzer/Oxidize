//! The Oxidize engine, shared by the `oxidize` command line and `oxidize-gui`.

pub mod backup;
pub mod clean;
pub mod cli;
pub mod commands;
pub mod complete;
pub mod exit;
pub mod hunter;
pub mod lnk;
pub mod mcp;
pub mod model;
pub mod orphans;
pub mod packages;
pub mod registry;
pub mod restore;
pub mod safety;
pub mod scanner;
pub mod system;
pub mod term;
pub mod uninstall;
pub mod util;

#[cfg(test)]
mod tests {
    #[test]
    fn readme_names_this_version_as_the_latest() {
        let readme = include_str!("../README.md");
        let phrase = "The latest version is";
        let mut found = 0;
        for (at, _) in readme.match_indices(phrase) {
            found += 1;
            let rest = readme[at + phrase.len()..].trim_start();
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || ".-+".contains(c)))
                .unwrap_or(rest.len());
            let named = rest[..end].trim_end_matches('.');
            assert_eq!(
                named,
                env!("CARGO_PKG_VERSION"),
                "README.md says \"{phrase} {named}\", but Cargo.toml has version {}",
                env!("CARGO_PKG_VERSION")
            );
        }
        assert!(found > 0, "README.md has no line saying \"{phrase}\"");
    }
}
