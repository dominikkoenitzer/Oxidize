//! Reads where a Windows shortcut file points, without COM.
//!
//! Only the LinkInfo block is used. It holds the local path as plain text, so
//! the shell item list never has to be walked.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Size of the fixed shortcut header, also the value its first field must hold.
const HEADER_LEN: usize = 0x4C;
/// Class id every shortcut file carries right after the header size.
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const HAS_LINK_TARGET_ID_LIST: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x1;
/// Smallest LinkInfo header, without the Unicode offsets.
const INFO_HEADER_MIN: usize = 0x1C;
/// LinkInfo header size from which the Unicode offsets are present.
const INFO_HEADER_UNICODE: usize = 0x24;
/// Shortcut files are small; nothing past this is read.
const MAX_FILE_LEN: u64 = 1024 * 1024;

/// The local path a shortcut file points to, read from its LinkInfo.
/// At most 1 MiB of the file is read. Any read or parse failure gives `None`.
pub fn target_of(path: &Path) -> Option<PathBuf> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_FILE_LEN)
        .read_to_end(&mut bytes)
        .ok()?;
    parse_target(&bytes)
}

/// The same, from the bytes of a shortcut.
/// The Unicode base path wins over the ANSI one, and a common path suffix is
/// appended. Network-only links and malformed input give `None`.
/// `ForceNoLinkInfo`: the location part is to be ignored.
const FORCE_NO_LINK_INFO: u32 = 0x100;

pub fn parse_target(bytes: &[u8]) -> Option<PathBuf> {
    if read_len(bytes, 0)? != HEADER_LEN || bytes.get(4..20)? != LINK_CLSID {
        return None;
    }
    let flags = read_u32(bytes, 20)?;
    // Windows ignores the location part when the link says so; so do we.
    if flags & HAS_LINK_INFO == 0 || flags & FORCE_NO_LINK_INFO != 0 {
        return None;
    }
    let mut start = HEADER_LEN;
    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        let list_len = usize::from(read_u16(bytes, start)?);
        start = start.checked_add(2)?.checked_add(list_len)?;
    }
    let rest = bytes.get(start..)?;
    let info = rest.get(..read_len(rest, 0)?)?;

    let header_size = read_len(info, 4)?;
    if header_size < INFO_HEADER_MIN || read_u32(info, 8)? & VOLUME_ID_AND_LOCAL_BASE_PATH == 0 {
        return None;
    }
    let unicode = header_size >= INFO_HEADER_UNICODE;
    let wide_base = if unicode { read_len(info, 28)? } else { 0 };
    let wide_suffix = if unicode { read_len(info, 32)? } else { 0 };

    let mut target = if wide_base != 0 {
        text_at(info, header_size, wide_base, true)?
    } else {
        text_at(info, header_size, read_len(info, 16)?, false)?
    };
    if target.is_empty() {
        return None;
    }
    let suffix = if wide_suffix != 0 {
        text_at(info, header_size, wide_suffix, true)?
    } else {
        match read_len(info, 24)? {
            0 => String::new(),
            offset => text_at(info, header_size, offset, false)?,
        }
    };
    if !suffix.is_empty() {
        if !target.ends_with('\\') {
            target.push('\\');
        }
        target.push_str(&suffix);
    }
    Some(PathBuf::from(target))
}

/// Reads a NUL-terminated string at an offset into LinkInfo.
/// The offset has to point past the LinkInfo header, and a string without its
/// terminator gives `None`.
fn text_at(info: &[u8], header_size: usize, offset: usize, wide: bool) -> Option<String> {
    if offset < header_size {
        return None;
    }
    let tail = info.get(offset..)?;
    if wide {
        utf16_until_nul(tail)
    } else {
        latin1_until_nul(tail)
    }
}

/// Decodes UTF-16LE up to the first NUL unit. Invalid UTF-16 gives `None`.
fn utf16_until_nul(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for pair in bytes.as_chunks::<2>().0 {
        match u16::from_le_bytes(*pair) {
            0 => return String::from_utf16(&units).ok(),
            unit => units.push(unit),
        }
    }
    None
}

/// Decodes single bytes as Latin-1 up to the first NUL.
/// This is exact for ASCII paths, which is what the ANSI fields hold in practice.
fn latin1_until_nul(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&byte| byte == 0)?;
    let text = bytes.get(..end)?;
    Some(text.iter().map(|&byte| char::from(byte)).collect())
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// Reads a u32 size or offset as a `usize`.
fn read_len(bytes: &[u8], at: usize) -> Option<usize> {
    usize::try_from(read_u32(bytes, at)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAYER: &str = r"C:\Program Files\Example Player\player.exe";

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn ansi(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = text
            .chars()
            .map(|c| u8::try_from(c).expect("latin-1 fixture text"))
            .collect();
        out.push(0);
        out
    }

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// Offset from the start of LinkInfo of the next byte appended to `body`.
    fn next_offset(header_size: u32, body: &[u8]) -> u32 {
        header_size + u32::try_from(body.len()).expect("small fixture")
    }

    /// A local LinkInfo block. The suffix is stored as ANSI, and also as
    /// UTF-16 when a Unicode base path is given.
    fn link_info(ansi_base: &str, unicode_base: Option<&str>, suffix: &str) -> Vec<u8> {
        let header_size: u32 = if unicode_base.is_some() { 0x24 } else { 0x1C };
        let mut body = Vec::new();
        push_u32(&mut body, 0x11);
        push_u32(&mut body, 3);
        push_u32(&mut body, 0x1234_5678);
        push_u32(&mut body, 0x10);
        body.push(0);
        let base_at = next_offset(header_size, &body);
        body.extend(ansi(ansi_base));
        let suffix_at = next_offset(header_size, &body);
        body.extend(ansi(suffix));
        let wide_offsets = unicode_base.map(|base| {
            let wide_base_at = next_offset(header_size, &body);
            body.extend(wide(base));
            let wide_suffix_at = next_offset(header_size, &body);
            body.extend(wide(suffix));
            (wide_base_at, wide_suffix_at)
        });

        let mut info = Vec::new();
        push_u32(&mut info, next_offset(header_size, &body));
        push_u32(&mut info, header_size);
        push_u32(&mut info, VOLUME_ID_AND_LOCAL_BASE_PATH);
        push_u32(&mut info, header_size);
        push_u32(&mut info, base_at);
        push_u32(&mut info, 0);
        push_u32(&mut info, suffix_at);
        if let Some((wide_base_at, wide_suffix_at)) = wide_offsets {
            push_u32(&mut info, wide_base_at);
            push_u32(&mut info, wide_suffix_at);
        }
        info.extend(body);
        info
    }

    /// A whole shortcut: header, an optional item id list, LinkInfo, and the
    /// empty block that ends the extra data.
    fn shortcut(id_list: Option<&[u8]>, info: &[u8]) -> Vec<u8> {
        let mut flags = HAS_LINK_INFO | 0x80;
        if id_list.is_some() {
            flags |= HAS_LINK_TARGET_ID_LIST;
        }
        let mut out = Vec::new();
        push_u32(&mut out, 0x4C);
        out.extend_from_slice(&LINK_CLSID);
        push_u32(&mut out, flags);
        out.resize(HEADER_LEN, 0);
        if let Some(list) = id_list {
            let len = u16::try_from(list.len()).expect("small id list");
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(list);
        }
        out.extend_from_slice(info);
        out.extend_from_slice(&[0; 4]);
        out
    }

    /// One made-up item followed by the terminating empty item.
    const ID_LIST: [u8; 8] = [0x06, 0x00, 0x1F, 0x50, 0xAA, 0xBB, 0x00, 0x00];

    fn expected(path: &str) -> Option<PathBuf> {
        Some(PathBuf::from(path))
    }

    #[test]
    fn a_shortcut_points_to_its_local_base_path() {
        let bytes = shortcut(None, &link_info(PLAYER, None, ""));
        assert_eq!(parse_target(&bytes), expected(PLAYER));
    }

    #[test]
    fn the_unicode_path_wins_over_the_ansi_path() {
        let unicode = r"C:\Program Files\Example Über\player.exe";
        let info = link_info(r"C:\PROGRA~1\EXAMPL~1\player.exe", Some(unicode), "");
        let bytes = shortcut(None, &info);
        assert_eq!(parse_target(&bytes), expected(unicode));
    }

    #[test]
    fn an_item_id_list_before_the_link_info_is_skipped() {
        let bytes = shortcut(Some(&ID_LIST), &link_info(PLAYER, Some(PLAYER), ""));
        assert_eq!(parse_target(&bytes), expected(PLAYER));
    }

    #[test]
    fn a_common_path_suffix_is_appended() {
        let base = r"C:\Program Files\Example Player";
        let bytes = shortcut(None, &link_info(base, None, "player.exe"));
        assert_eq!(parse_target(&bytes), expected(PLAYER));

        let with_slash = r"C:\Program Files\Example Player\";
        let info = link_info(with_slash, Some(with_slash), "player.exe");
        assert_eq!(parse_target(&shortcut(None, &info)), expected(PLAYER));
    }

    #[test]
    fn a_wrong_header_size_gives_nothing() {
        let mut bytes = shortcut(None, &link_info(PLAYER, None, ""));
        bytes[0] = 0x4D;
        assert_eq!(parse_target(&bytes), None);
    }

    #[test]
    fn a_wrong_class_id_gives_nothing() {
        let mut bytes = shortcut(None, &link_info(PLAYER, None, ""));
        bytes[4] = 0x02;
        assert_eq!(parse_target(&bytes), None);
    }

    #[test]
    fn a_shortcut_without_link_info_gives_nothing() {
        let mut bytes = shortcut(Some(&ID_LIST), &link_info(PLAYER, None, ""));
        bytes[20] &= !0x02;
        assert_eq!(parse_target(&bytes), None);
    }

    #[test]
    fn a_network_only_link_gives_nothing() {
        let mut bytes = shortcut(None, &link_info(PLAYER, None, ""));
        bytes[HEADER_LEN + 8..HEADER_LEN + 12].copy_from_slice(&u32::to_le_bytes(0x2));
        assert_eq!(parse_target(&bytes), None);
    }

    #[test]
    fn an_offset_past_the_end_gives_nothing() {
        let mut bytes = shortcut(None, &link_info(PLAYER, None, ""));
        bytes[HEADER_LEN + 16..HEADER_LEN + 20].copy_from_slice(&u32::to_le_bytes(0xFFFF_FFF0));
        assert_eq!(parse_target(&bytes), None);
    }

    #[test]
    fn truncated_bytes_never_panic() {
        let folder = r"C:\Program Files\Example Player";
        let fixtures = [
            shortcut(None, &link_info(PLAYER, None, "")),
            shortcut(Some(&ID_LIST), &link_info(PLAYER, Some(PLAYER), "")),
            shortcut(None, &link_info(folder, None, "player.exe")),
        ];
        for bytes in &fixtures {
            assert_eq!(parse_target(bytes), expected(PLAYER));
            for len in 0..bytes.len() {
                let got = parse_target(&bytes[..len]);
                assert!(got.is_none() || got == expected(PLAYER), "length {len}");
            }
        }
    }

    #[test]
    fn target_of_reads_a_shortcut_file() {
        let name = format!("oxidize-lnk-test-{}.lnk", std::process::id());
        let path = std::env::temp_dir().join(name);
        let bytes = shortcut(None, &link_info(PLAYER, Some(PLAYER), ""));
        std::fs::write(&path, bytes).expect("write fixture");
        let got = target_of(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(got, expected(PLAYER));
        assert_eq!(target_of(&path), None);
    }
}
