//! The Recycle Bin, read the way Windows keeps it: on every drive a folder
//! `$Recycle.Bin\<user's SID>`, and for each deleted item a pair of entries,
//! `$I<id>` with where it came from and when it was deleted, and `$R<id>`,
//! the item itself. Only complete, readable pairs are ever deleted; anything
//! else in the folder is left alone.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::protect::Protected;
use super::{Kept, KeptReason};

/// One item in the Recycle Bin.
#[derive(Debug, Clone)]
pub struct BinItem {
    /// The `$I` file.
    pub info: PathBuf,
    /// The `$R` file or folder, when it is there.
    pub data: Option<PathBuf>,
    /// Where it was before it was deleted.
    pub original: String,
    pub deleted: SystemTime,
    /// Counted from the item itself.
    pub bytes: u64,
}

/// What an `$I` file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub size: u64,
    pub deleted: SystemTime,
    pub original: String,
}

/// Read an `$I` file: version 1 (Windows Vista to 8.1) holds the path in a
/// fixed 520-byte field, version 2 (Windows 10 and later) gives its length.
pub fn parse_info(bytes: &[u8]) -> Option<Info> {
    let u64_at = |at: usize| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
    };
    let version = u64_at(0)?;
    let size = u64_at(8)?;
    let filetime = u64_at(16)?;
    let name: &[u8] = match version {
        1 => bytes.get(24..24 + 520)?,
        2 => {
            let chars = u32::from_le_bytes(bytes.get(24..28)?.try_into().ok()?) as usize;
            bytes.get(28..28 + chars.checked_mul(2)?)?
        }
        _ => return None,
    };
    let units: Vec<u16> = name
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    let original = String::from_utf16(&units).ok()?;
    if original.is_empty() {
        return None;
    }
    Some(Info {
        size,
        deleted: from_filetime(filetime)?,
        original,
    })
}

/// A FILETIME (100 ns steps since 1601) as a `SystemTime`.
fn from_filetime(ft: u64) -> Option<SystemTime> {
    const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    let since_unix = ft.checked_sub(UNIX_EPOCH_AS_FILETIME)?;
    UNIX_EPOCH.checked_add(Duration::from_nanos(since_unix.checked_mul(100)?))
}

/// The items in one `$Recycle.Bin\<SID>` folder. Entries that do not read as
/// an item are not listed.
pub fn items(bin: &Path) -> Vec<BinItem> {
    let Ok(entries) = fs::read_dir(bin) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(id) = name.strip_prefix("$I") else {
            continue;
        };
        let info_path = entry.path();
        let Some(info) = fs::read(&info_path).ok().and_then(|b| parse_info(&b)) else {
            continue;
        };
        let data = bin.join(format!("$R{id}"));
        let (data, bytes) = match fs::symlink_metadata(&data) {
            Ok(meta) if meta.is_dir() => {
                let bytes = crate::scanner::dir_size(&data);
                (Some(data), bytes)
            }
            Ok(meta) => (Some(data), meta.len()),
            Err(_) => (None, 0),
        };
        out.push(BinItem {
            info: info_path,
            data,
            original: info.original,
            deleted: info.deleted,
            bytes,
        });
    }
    out.sort_by_key(|i| i.deleted);
    out
}

/// Split the items into those deleted at least `min_age` ago and those
/// kept, counting why.
pub fn select(
    items: Vec<BinItem>,
    min_age: Duration,
    protected: &Protected,
    now: SystemTime,
    kept: &mut Vec<Kept>,
) -> Vec<BinItem> {
    let mut out = Vec::new();
    for item in items {
        let age = now.duration_since(item.deleted).unwrap_or_default();
        if protected.covers(&item.info) || protected.covers(Path::new(&item.original)) {
            super::files::add(kept, KeptReason::Protected, 1, item.bytes);
        } else if age < min_age {
            super::files::add(
                kept,
                KeptReason::RecentlyDeleted(min_age.as_secs() / 86_400),
                1,
                item.bytes,
            );
        } else {
            out.push(item);
        }
    }
    out
}

/// Empty the chosen items: the item first, then its `$I` entry, so a failure
/// never leaves an item Windows cannot show. Returns the bytes freed and the
/// number of items that went.
pub fn delete(items: &[BinItem], protected: &Protected, kept: &mut Vec<Kept>) -> (u64, usize) {
    let mut freed = 0;
    let mut gone = 0;
    for item in items {
        if protected.covers(&item.info) || protected.covers(Path::new(&item.original)) {
            super::files::add(kept, KeptReason::Protected, 1, item.bytes);
            continue;
        }
        if let Some(data) = &item.data {
            let result = match fs::symlink_metadata(data) {
                Ok(meta) if meta.is_dir() => fs::remove_dir_all(data),
                Ok(_) => fs::remove_file(data),
                Err(_) => Ok(()),
            };
            if let Err(e) = result {
                let reason = match e.raw_os_error() {
                    Some(32) | Some(33) => KeptReason::InUse,
                    _ => KeptReason::AccessDenied,
                };
                super::files::add(kept, reason, 1, item.bytes);
                continue;
            }
        }
        if fs::remove_file(&item.info).is_ok() || !item.info.exists() {
            freed += item.bytes;
            gone += 1;
        }
    }
    (freed, gone)
}

/// `X:\$Recycle.Bin\<sid>` on every fixed drive that has one.
pub fn bins(sid: &str) -> Vec<PathBuf> {
    fixed_drives()
        .into_iter()
        .map(|d| d.join("$Recycle.Bin").join(sid))
        .filter(|p| p.is_dir())
        .collect()
}

#[cfg(windows)]
fn fixed_drives() -> Vec<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_FIXED: u32 = 3;
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i) as char))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) == DRIVE_FIXED }
        })
        .map(PathBuf::from)
        .collect()
}

#[cfg(not(windows))]
fn fixed_drives() -> Vec<PathBuf> {
    Vec::new()
}

/// The current user's SID as text, `S-1-5-21-...`.
#[cfg(windows)]
pub fn current_sid() -> Option<String> {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let mut buf = vec![0u8; 256];
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        if !ok {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = user.User.Sid;
        if !IsValidSid(sid).as_bool() {
            return None;
        }
        let auth = (*GetSidIdentifierAuthority(sid)).Value;
        let authority = auth.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        let count = *GetSidSubAuthorityCount(sid) as u32;
        let mut text = format!("S-1-{authority}");
        for i in 0..count {
            text.push_str(&format!("-{}", *GetSidSubAuthority(sid, i)));
        }
        Some(text)
    }
}

#[cfg(not(windows))]
pub fn current_sid() -> Option<String> {
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::clean::files::tests::fixture;

    /// The bytes of a version 2 `$I` file.
    pub fn info_v2(size: u64, deleted: SystemTime, original: &str) -> Vec<u8> {
        let ft = deleted.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 / 100
            + 116_444_736_000_000_000;
        let name: Vec<u16> = original.encode_utf16().chain(std::iter::once(0)).collect();
        let mut out = Vec::new();
        out.extend_from_slice(&2u64.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&ft.to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        for u in name {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    /// Put an item into a fixture bin, deleted `days` ago.
    pub fn recycled(bin: &Path, id: &str, len: usize, days: u64, original: &str) {
        let deleted = SystemTime::now() - Duration::from_secs(days * 86_400);
        fs::write(
            bin.join(format!("$I{id}")),
            info_v2(len as u64, deleted, original),
        )
        .unwrap();
        fs::write(bin.join(format!("$R{id}")), vec![b'r'; len]).unwrap();
    }

    #[test]
    fn both_versions_of_the_info_file_read() {
        let when = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let v2 = info_v2(1234, when, r"C:\Users\Example\report.docx");
        let info = parse_info(&v2).unwrap();
        assert_eq!(info.size, 1234);
        assert_eq!(info.original, r"C:\Users\Example\report.docx");
        assert_eq!(info.deleted, when);

        let mut v1 = Vec::new();
        v1.extend_from_slice(&1u64.to_le_bytes());
        v1.extend_from_slice(&v2[8..24]);
        let mut name = vec![0u8; 520];
        for (i, u) in r"D:\old.txt".encode_utf16().enumerate() {
            name[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        v1.extend_from_slice(&name);
        assert_eq!(parse_info(&v1).unwrap().original, r"D:\old.txt");

        for bad in [&v2[..20], &[9u8; 40][..], &[][..]] {
            assert!(parse_info(bad).is_none());
        }
    }

    #[test]
    fn only_items_deleted_long_enough_ago_are_emptied() {
        let bin = fixture("bin");
        recycled(&bin, "AAAAAA.txt", 300, 45, r"C:\Docs\old.txt");
        recycled(&bin, "BBBBBB.txt", 20, 3, r"C:\Docs\new.txt");
        recycled(&bin, "CCCCCC.txt", 50, 90, r"C:\Keep\plan.txt");
        fs::create_dir_all(bin.join("$RDDDDDD")).unwrap();
        fs::write(bin.join("$RDDDDDD").join("inner.bin"), vec![1u8; 70]).unwrap();
        let deleted = SystemTime::now() - Duration::from_secs(40 * 86_400);
        fs::write(
            bin.join("$IDDDDDD"),
            info_v2(70, deleted, r"C:\Docs\folder"),
        )
        .unwrap();
        // Not an item: left alone whatever it is.
        fs::write(bin.join("desktop.ini"), "x").unwrap();
        fs::write(bin.join("$IBROKEN"), "short").unwrap();

        let all = items(&bin);
        assert_eq!(all.len(), 4);
        let protected = Protected::new([r"C:\Keep".to_string()]);
        let mut kept = Vec::new();
        let month = Duration::from_secs(30 * 86_400);
        let chosen = select(all, month, &protected, SystemTime::now(), &mut kept);
        let names: Vec<&str> = chosen.iter().map(|i| i.original.as_str()).collect();
        assert_eq!(names, [r"C:\Docs\old.txt", r"C:\Docs\folder"]);
        assert_eq!(chosen.iter().map(|i| i.bytes).sum::<u64>(), 370);
        let reason = |r: KeptReason| {
            kept.iter()
                .find(|k| k.reason == r)
                .map(|k| (k.count, k.bytes))
        };
        assert_eq!(reason(KeptReason::RecentlyDeleted(30)), Some((1, 20)));
        assert_eq!(reason(KeptReason::Protected), Some((1, 50)));

        let mut kept = Vec::new();
        assert_eq!(delete(&chosen, &protected, &mut kept), (370, 2));
        assert!(!bin.join("$RAAAAAA.txt").exists() && !bin.join("$IAAAAAA.txt").exists());
        assert!(!bin.join("$RDDDDDD").exists());
        for stays in [
            "$RBBBBBB.txt",
            "$IBBBBBB.txt",
            "$RCCCCCC.txt",
            "desktop.ini",
            "$IBROKEN",
        ] {
            assert!(bin.join(stays).exists(), "{stays}");
        }
        let _ = fs::remove_dir_all(&bin);
    }

    #[test]
    fn the_current_user_has_a_sid() {
        let sid = current_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }
}
