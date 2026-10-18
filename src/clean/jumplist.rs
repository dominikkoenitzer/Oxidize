//! Reading how many items a jump list holds and how many of them are pinned.
//!
//! An `.automaticDestinations-ms` file is a compound file. Its `DestList`
//! stream starts with a header that counts the entries and the pinned ones.
//! Only that header is read; nothing is ever written.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// What a jump list holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestList {
    pub entries: u32,
    pub pinned: u32,
}

impl DestList {
    /// The entries that are not pinned: the recent and frequent ones.
    pub fn recent(&self) -> u32 {
        self.entries.saturating_sub(self.pinned)
    }
}

const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const FREE: u32 = 0xFFFF_FFFF;
const DIR_ENTRY: usize = 128;

pub fn read(path: &Path) -> Result<DestList> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&bytes)
}

/// The counts from a jump list's bytes.
pub fn parse(bytes: &[u8]) -> Result<DestList> {
    let file = Compound::new(bytes)?;
    let stream = file
        .stream("DestList")?
        .context("the jump list has no DestList")?;
    if stream.len() < 12 {
        bail!("the DestList is too short");
    }
    Ok(DestList {
        entries: u32_at(&stream, 4),
        pinned: u32_at(&stream, 8),
    })
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Just enough of a compound file to read one stream from it.
struct Compound<'a> {
    bytes: &'a [u8],
    sector: usize,
    mini_sector: usize,
    cutoff: u64,
    fat: Vec<u32>,
    first_mini_fat: u32,
    first_dir: u32,
}

impl<'a> Compound<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 512 || bytes[..8] != SIGNATURE {
            bail!("not a compound file");
        }
        let shift = u16_at(bytes, 0x1E);
        let mini_shift = u16_at(bytes, 0x20);
        if !(7..=16).contains(&shift) || mini_shift >= shift {
            bail!("unknown sector size");
        }
        let mut file = Compound {
            bytes,
            sector: 1 << shift,
            mini_sector: 1 << mini_shift,
            cutoff: u64::from(u32_at(bytes, 0x38)),
            fat: Vec::new(),
            first_mini_fat: u32_at(bytes, 0x3C),
            first_dir: u32_at(bytes, 0x30),
        };
        // The sectors of the allocation table: 109 listed in the header,
        // the rest in a chain of further list sectors.
        let fat_sectors = u32_at(bytes, 0x2C) as usize;
        // The table fits in the file; a header that says otherwise is
        // broken, and believing it would reserve memory for a table of
        // terabytes.
        if fat_sectors > file.sector_count() {
            bail!("the allocation table is larger than the file");
        }
        let mut listed: Vec<u32> = (0..109).map(|i| u32_at(bytes, 0x4C + i * 4)).collect();
        let mut next = u32_at(bytes, 0x44);
        let mut hops = 0;
        while next != END_OF_CHAIN && next != FREE && listed.len() < fat_sectors {
            let s = file.sector_bytes(next)?;
            let per = file.sector / 4 - 1;
            listed.extend((0..per).map(|i| u32_at(s, i * 4)));
            next = u32_at(s, per * 4);
            hops += 1;
            if hops > file.sector_count() {
                bail!("the sector list loops");
            }
        }
        let mut fat = Vec::with_capacity(fat_sectors * file.sector / 4);
        for &n in listed.iter().take(fat_sectors) {
            let s = file.sector_bytes(n)?;
            fat.extend((0..file.sector / 4).map(|i| u32_at(s, i * 4)));
        }
        file.fat = fat;
        Ok(file)
    }

    fn sector_count(&self) -> usize {
        self.bytes.len() / self.sector
    }

    fn sector_bytes(&self, n: u32) -> Result<&'a [u8]> {
        let start = (n as usize + 1)
            .checked_mul(self.sector)
            .context("sector out of range")?;
        self.bytes
            .get(start..start + self.sector)
            .context("sector out of range")
    }

    /// The sectors of a chain, in order.
    fn chain(&self, table: &[u32], first: u32) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut n = first;
        while n != END_OF_CHAIN {
            if out.len() > table.len() {
                bail!("a chain loops");
            }
            out.push(n);
            n = *table.get(n as usize).context("a chain leaves the table")?;
        }
        Ok(out)
    }

    /// The bytes of a chain of full sectors.
    fn read_chain(&self, first: u32) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for n in self.chain(&self.fat, first)? {
            out.extend_from_slice(self.sector_bytes(n)?);
        }
        Ok(out)
    }

    /// The stream of that name, `None` when there is none.
    fn stream(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let dir = self.read_chain(self.first_dir)?;
        let entries: &[[u8; DIR_ENTRY]] = dir.as_chunks::<DIR_ENTRY>().0;
        let Some(root) = entries.first() else {
            bail!("the directory is empty");
        };
        for e in entries {
            if e[0x42] != 2 || entry_name(e) != name {
                continue;
            }
            let start = u32_at(e, 0x74);
            // Version 3 files keep junk in the upper half of the size.
            let size = if self.sector == 512 {
                u64::from(u32_at(e, 0x78))
            } else {
                u64::from(u32_at(e, 0x78)) | (u64::from(u32_at(e, 0x7C)) << 32)
            };
            let mut data = if size < self.cutoff {
                self.read_mini(root, start)?
            } else {
                self.read_chain(start)?
            };
            let size = usize::try_from(size).context("stream too large")?;
            if data.len() < size {
                bail!("the stream is cut short");
            }
            data.truncate(size);
            return Ok(Some(data));
        }
        Ok(None)
    }

    /// A small stream, from the mini stream the root entry holds.
    fn read_mini(&self, root: &[u8], first: u32) -> Result<Vec<u8>> {
        let mini_fat: Vec<u32> = self
            .read_chain(self.first_mini_fat)?
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        let container = self.read_chain(u32_at(root, 0x74))?;
        let mut out = Vec::new();
        for n in self.chain(&mini_fat, first)? {
            let start = n as usize * self.mini_sector;
            out.extend_from_slice(
                container
                    .get(start..start + self.mini_sector)
                    .context("mini sector out of range")?,
            );
        }
        Ok(out)
    }
}

fn entry_name(e: &[u8]) -> String {
    let len = (u16_at(e, 0x40) as usize).min(64);
    let units: Vec<u16> = e[..len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const SECTOR: usize = 512;

    /// A DestList stream: its header, then filler of `len` bytes in all.
    pub fn dest_list(entries: u32, pinned: u32, len: usize) -> Vec<u8> {
        let mut s = vec![0u8; len.max(32)];
        s[0..4].copy_from_slice(&4u32.to_le_bytes());
        s[4..8].copy_from_slice(&entries.to_le_bytes());
        s[8..12].copy_from_slice(&pinned.to_le_bytes());
        s
    }

    /// A version 3 compound file holding the given streams. Streams under
    /// 4096 bytes go into the mini stream, as Windows writes them.
    pub fn compound(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut sectors: Vec<Vec<u8>> = Vec::new();
        let mut fat: Vec<u32> = Vec::new();
        // Lay a chain of sectors, returning its first sector.
        let lay = |sectors: &mut Vec<Vec<u8>>, fat: &mut Vec<u32>, data: &[u8]| -> u32 {
            let first = sectors.len() as u32;
            let chunks: Vec<&[u8]> = data.chunks(SECTOR).collect();
            for (i, c) in chunks.iter().enumerate() {
                let mut s = c.to_vec();
                s.resize(SECTOR, 0);
                sectors.push(s);
                fat.push(if i + 1 == chunks.len() {
                    END_OF_CHAIN
                } else {
                    first + i as u32 + 1
                });
            }
            first
        };
        // Sector 0 is the allocation table itself.
        sectors.push(vec![0; SECTOR]);
        fat.push(0xFFFF_FFFD);

        let mut mini = Vec::new();
        let mut mini_fat: Vec<u32> = Vec::new();
        let mut placed = Vec::new();
        for (name, data) in streams {
            if data.len() < 4096 {
                let first = (mini.len() / 64) as u32;
                let n = data.len().div_ceil(64).max(1);
                for i in 0..n {
                    mini_fat.push(if i + 1 == n {
                        END_OF_CHAIN
                    } else {
                        first + i as u32 + 1
                    });
                }
                let mut d = data.clone();
                d.resize(n * 64, 0);
                mini.extend(d);
                placed.push((name.to_string(), first, data.len()));
            } else {
                let first = lay(&mut sectors, &mut fat, data);
                placed.push((name.to_string(), first, data.len()));
            }
        }
        let (mini_start, mini_fat_start) = if mini.is_empty() {
            (END_OF_CHAIN, END_OF_CHAIN)
        } else {
            let bytes: Vec<u8> = mini_fat.iter().flat_map(|v| v.to_le_bytes()).collect();
            let mf = lay(&mut sectors, &mut fat, &bytes);
            (lay(&mut sectors, &mut fat, &mini), mf)
        };

        let mut dir = Vec::new();
        let entry = |name: &str, kind: u8, start: u32, size: usize, child: u32| {
            let mut e = vec![0u8; DIR_ENTRY];
            let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
            for (i, u) in units.iter().enumerate() {
                e[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
            }
            e[0x40..0x42].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
            e[0x42] = kind;
            e[0x44..0x48].copy_from_slice(&FREE.to_le_bytes());
            e[0x48..0x4C].copy_from_slice(&FREE.to_le_bytes());
            e[0x4C..0x50].copy_from_slice(&child.to_le_bytes());
            e[0x74..0x78].copy_from_slice(&start.to_le_bytes());
            e[0x78..0x7C].copy_from_slice(&(size as u32).to_le_bytes());
            e
        };
        dir.extend(entry("Root Entry", 5, mini_start, mini.len(), 1));
        for (name, first, len) in &placed {
            dir.extend(entry(name, 2, *first, *len, FREE));
        }
        let dir_start = lay(&mut sectors, &mut fat, &dir);

        assert!(
            fat.len() <= SECTOR / 4,
            "the test file needs one table sector"
        );
        let mut table: Vec<u8> = fat.iter().flat_map(|v| v.to_le_bytes()).collect();
        table.resize(SECTOR, 0xFF);
        sectors[0] = table;

        let mut header = vec![0u8; SECTOR];
        header[..8].copy_from_slice(&SIGNATURE);
        header[0x18..0x1A].copy_from_slice(&0x3Eu16.to_le_bytes());
        header[0x1A..0x1C].copy_from_slice(&3u16.to_le_bytes());
        header[0x1C..0x1E].copy_from_slice(&0xFFFEu16.to_le_bytes());
        header[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes());
        header[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
        header[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        header[0x30..0x34].copy_from_slice(&dir_start.to_le_bytes());
        header[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes());
        header[0x3C..0x40].copy_from_slice(&mini_fat_start.to_le_bytes());
        header[0x40..0x44].copy_from_slice(&u32::from(!mini.is_empty()).to_le_bytes());
        header[0x44..0x48].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for i in 0..109 {
            let v: u32 = if i == 0 { 0 } else { FREE };
            header[0x4C + i * 4..0x50 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        let mut out = header;
        for s in sectors {
            out.extend(s);
        }
        out
    }

    /// A jump list with that many entries, `pinned` of them pinned.
    pub fn jump_list(entries: u32, pinned: u32) -> Vec<u8> {
        compound(&[
            ("1", vec![7; 300]),
            (
                "DestList",
                dest_list(entries, pinned, 130 * entries as usize),
            ),
        ])
    }

    #[test]
    fn reads_the_counts_from_the_mini_stream() {
        let d = parse(&jump_list(12, 3)).unwrap();
        assert_eq!(
            d,
            DestList {
                entries: 12,
                pinned: 3
            }
        );
        assert_eq!(d.recent(), 9);
    }

    #[test]
    fn reads_the_counts_from_a_large_destlist() {
        // Over 4096 bytes, so the stream lies in ordinary sectors.
        let file = compound(&[("DestList", dest_list(40, 0, 5200)), ("2", vec![1; 64])]);
        assert_eq!(
            parse(&file).unwrap(),
            DestList {
                entries: 40,
                pinned: 0
            }
        );
    }

    #[test]
    fn refuses_what_is_not_a_jump_list() {
        assert!(parse(b"not a compound file").is_err());
        assert!(parse(&[0u8; 1024]).is_err());
        let no_list = compound(&[("1", vec![0; 100])]);
        assert!(parse(&no_list).is_err());
        // Cut off in the middle.
        let file = jump_list(5, 0);
        assert!(parse(&file[..file.len() - 600]).is_err());
    }

    #[test]
    fn a_looping_chain_is_an_error_not_a_hang() {
        let mut file = compound(&[("DestList", dest_list(40, 0, 5200))]);
        // Point the stream's last sector back at its first.
        let table = &mut file[512..1024];
        let last = (1..128)
            .find(|i| u32_at(table, i * 4) == END_OF_CHAIN)
            .unwrap();
        table[last * 4..last * 4 + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse(&file).is_err());
    }
}
