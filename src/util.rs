//! Small, pure helpers shared across modules: command-line splitting (Windows
//! `CommandLineToArgvW` rules), environment-variable expansion, name
//! tokenisation for the matcher, and human-friendly formatting.
//!
//! Everything here is dependency-free and unit-tested, because the leftover
//! matcher's correctness (and therefore its safety) hinges on these functions.

/// Generic words that carry no identifying signal and would cause false
/// matches if used as search tokens (e.g. a folder literally named "Software").
const STOPWORDS: &[&str] = &[
    "the", "inc", "llc", "ltd", "corp", "corporation", "company", "limited",
    "software", "technologies", "technology", "systems", "solutions", "group",
    "version", "edition", "x64", "x86", "win32", "win64", "bit", "win",
    "windows", "setup", "installer", "install", "app", "apps", "application",
    "free", "pro", "professional", "plus", "premium", "update", "build",
    "release", "gmbh", "srl", "sas", "incorporated", "and", "for", "com",
    "net", "org", "program", "programs", "common", "files", "data", "tools",
    // High-collision generic words: too common to identify a product on their
    // own, so they never become match tokens (a single coincidental hit on one
    // of these must not flag an unrelated program's files).
    "media", "player", "viewer", "editor", "manager", "helper", "updater",
    "launcher", "driver", "drivers", "runtime", "redistributable", "redist",
    "framework", "toolkit", "utility", "utilities", "assistant", "agent",
    "host", "service", "services", "core", "bin", "lib", "resources", "client",
];

/// True if `token` is a non-identifying stopword.
pub fn is_stopword(token: &str) -> bool {
    STOPWORDS.contains(&token)
}

/// Collapse a string to lower-case alphanumerics only, for substring
/// containment checks (`"Google Chrome" -> "googlechrome"`).
pub fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Split a string into significant lower-cased tokens suitable for matching:
/// at least 3 chars, not a stopword, not purely numeric (drops version noise).
pub fn significant_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in s.split(|c: char| !c.is_alphanumeric()) {
        let t = raw.to_lowercase();
        if t.len() >= 3
            && !is_stopword(&t)
            && !t.chars().all(|c| c.is_ascii_digit())
            && !out.contains(&t)
        {
            out.push(t);
        }
    }
    out
}

/// Expand `%VAR%` references using the current process environment. Unknown
/// variables are left untouched (percent signs preserved), matching the OS's
/// pass-through behaviour closely enough for uninstall/registry strings.
pub fn expand_env_vars(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            // Find the closing '%'.
            if let Some(rel) = chars[i + 1..].iter().position(|&c| c == '%') {
                let name: String = chars[i + 1..i + 1 + rel].iter().collect();
                if name.is_empty() {
                    // "%%" -> literal "%".
                    out.push('%');
                    i += 2;
                    continue;
                }
                match std::env::var(&name) {
                    Ok(val) => out.push_str(&val),
                    // Leave unresolved references verbatim, percents included.
                    Err(_) => {
                        out.push('%');
                        out.push_str(&name);
                        out.push('%');
                    }
                }
                i += 1 + rel + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Split a Windows command line into arguments following the
/// `CommandLineToArgvW` / MSVCRT rules (so a quoted path containing spaces is
/// one argument). `argv[0]` is the executable, the rest are its arguments.
///
/// Rules implemented:
///  * a run of `2n` backslashes before a `"` => `n` backslashes and the quote
///    toggles quoting;
///  * a run of `2n+1` backslashes before a `"` => `n` backslashes and a literal
///    `"`;
///  * backslashes not before a quote are literal;
///  * `""` while inside quotes => a literal `"`;
///  * outside quotes, runs of spaces/tabs separate arguments.
///
/// Note: the real API treats `argv[0]` slightly specially, but program paths in
/// uninstall strings are either quoted or contain no embedded quotes, so the
/// general rules produce the correct result for our inputs.
pub fn split_command_line(cmd: &str) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let n = chars.len();
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut arg_started = false;
    let mut i = 0;

    while i < n {
        match chars[i] {
            '\\' => {
                // Count the run of backslashes.
                let mut slashes = 0;
                while i < n && chars[i] == '\\' {
                    slashes += 1;
                    i += 1;
                }
                if i < n && chars[i] == '"' {
                    // Half of them are literal backslashes...
                    for _ in 0..slashes / 2 {
                        cur.push('\\');
                    }
                    if slashes % 2 == 1 {
                        // ...and an odd one escapes the quote.
                        cur.push('"');
                        i += 1; // consume the quote
                    }
                    // (Even count: leave the quote for the '"' arm next loop.)
                    arg_started = true;
                } else {
                    for _ in 0..slashes {
                        cur.push('\\');
                    }
                    arg_started = true;
                }
            }
            '"' => {
                if in_quotes && i + 1 < n && chars[i + 1] == '"' {
                    // "" inside quotes -> one literal quote.
                    cur.push('"');
                    i += 2;
                } else {
                    in_quotes = !in_quotes;
                    arg_started = true;
                    i += 1;
                }
            }
            ' ' | '\t' if !in_quotes => {
                if arg_started {
                    args.push(std::mem::take(&mut cur));
                    arg_started = false;
                }
                i += 1;
            }
            c => {
                cur.push(c);
                arg_started = true;
                i += 1;
            }
        }
    }
    if arg_started {
        args.push(cur);
    }
    args
}

/// Format a byte count as a short human-readable string.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Normalise a raw `InstallDate` value (`YYYYMMDD`) to `YYYY-MM-DD`. If the
/// value is not a sensible 8-digit date, return it trimmed and unchanged.
pub fn format_install_date(raw: &str) -> String {
    let t = raw.trim();
    if t.len() == 8 && t.chars().all(|c| c.is_ascii_digit()) {
        let (y, rest) = t.split_at(4);
        let (m, d) = rest.split_at(2);
        let mm: u32 = m.parse().unwrap_or(0);
        let dd: u32 = d.parse().unwrap_or(0);
        if (1..=12).contains(&mm) && (1..=31).contains(&dd) {
            return format!("{y}-{m}-{d}");
        }
    }
    t.to_string()
}

/// Lower-cased file name (no directory) of a path-like string. Handles both
/// `\` and `/` separators and trims surrounding quotes/whitespace.
pub fn file_basename_lower(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_matches('"');
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or("").trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_exe_with_args() {
        let v = split_command_line(r#""C:\Program Files\App\unins000.exe" /SILENT /NORESTART"#);
        assert_eq!(
            v,
            vec![
                r"C:\Program Files\App\unins000.exe".to_string(),
                "/SILENT".to_string(),
                "/NORESTART".to_string(),
            ]
        );
    }

    #[test]
    fn splits_msiexec_unquoted() {
        let v = split_command_line("MsiExec.exe /X{2D7E0D49-0001-0000-0000-000000000000}");
        assert_eq!(
            v,
            vec![
                "MsiExec.exe".to_string(),
                "/X{2D7E0D49-0001-0000-0000-000000000000}".to_string(),
            ]
        );
    }

    #[test]
    fn keeps_spaces_inside_quotes() {
        let v = split_command_line(r#""a b" c"#);
        assert_eq!(v, vec!["a b".to_string(), "c".to_string()]);
    }

    #[test]
    fn handles_escaped_quote() {
        // \" is a literal quote, not a delimiter.
        let v = split_command_line(r#"x \"y\" z"#);
        assert_eq!(v, vec!["x".to_string(), "\"y\"".to_string(), "z".to_string()]);
    }

    #[test]
    fn empty_command_line_is_empty() {
        assert!(split_command_line("   ").is_empty());
        assert!(split_command_line("").is_empty());
    }

    #[test]
    fn expands_known_and_leaves_unknown() {
        std::env::set_var("OXIDIZE_TEST_VAR", "C:\\Demo");
        let out = expand_env_vars(r"%OXIDIZE_TEST_VAR%\app.exe %NOPE_OXIDIZE%");
        assert_eq!(out, r"C:\Demo\app.exe %NOPE_OXIDIZE%");
        std::env::remove_var("OXIDIZE_TEST_VAR");
    }

    #[test]
    fn double_percent_is_literal() {
        assert_eq!(expand_env_vars("100%% done"), "100% done");
    }

    #[test]
    fn tokenises_significantly() {
        let toks = significant_tokens("Google Chrome 124.0.1 (x64)");
        assert!(toks.contains(&"google".to_string()));
        assert!(toks.contains(&"chrome".to_string()));
        // Version numbers and "x64" are dropped.
        assert!(!toks.iter().any(|t| t == "x64"));
        assert!(!toks.iter().any(|t| t.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn normalises_to_alnum_lower() {
        assert_eq!(normalize("Google Chrome!"), "googlechrome");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1024 * 1024 * 3), "3.0 MB");
    }

    #[test]
    fn formats_install_date() {
        assert_eq!(format_install_date("20240115"), "2024-01-15");
        assert_eq!(format_install_date("notadate"), "notadate");
        assert_eq!(format_install_date("20249999"), "20249999"); // invalid m/d kept raw
    }

    #[test]
    fn basename_lower_handles_separators() {
        assert_eq!(
            file_basename_lower(r#""C:\Program Files\App\App.EXE""#),
            Some("app.exe".to_string())
        );
        assert_eq!(file_basename_lower("App.exe,0"), Some("app.exe,0".to_string()));
    }
}
