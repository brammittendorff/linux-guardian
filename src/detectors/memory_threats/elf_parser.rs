use super::utils::parse_address_range;
use anyhow::Result;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use sha2::{Digest, Sha256};

/// Info about the .text section parsed from an ELF binary
pub(super) struct TextSectionInfo {
    /// File offset of .text section
    pub(super) file_offset: u64,
    /// Size of .text section in bytes
    pub(super) size: u64,
    /// Whether the binary has DT_TEXTREL (text relocations)
    pub(super) has_textrel: bool,
}

/// Info about a memory mapping from /proc/PID/maps
pub(super) struct MappingInfo {
    /// Start address
    pub(super) start: u64,
    /// File offset this mapping corresponds to
    pub(super) file_offset: u64,
}

/// Parse an ELF binary to find the .text section offset and size.
/// Returns None if the file isn't a valid ELF or has no .text section.
pub(super) fn parse_elf_text_section(path: &std::path::Path) -> Option<TextSectionInfo> {
    let data = fs::read(path).ok()?;

    // Verify ELF magic
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return None;
    }

    // We only handle 64-bit ELF (class 2)
    if data[4] != 2 {
        return None;
    }

    // Little-endian (data encoding 1) — x86_64
    let le = data[5] == 1;
    if !le {
        return None;
    }

    let read_u16 = |off: usize| -> u16 { u16::from_le_bytes([data[off], data[off + 1]]) };
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    };
    let read_u64 = |off: usize| -> u64 {
        u64::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ])
    };

    // ELF64 header fields
    let e_shoff = read_u64(40) as usize; // Section header table offset
    let e_shentsize = read_u16(58) as usize; // Section header entry size
    let e_shnum = read_u16(60) as usize; // Number of section headers
    let e_shstrndx = read_u16(62) as usize; // Section name string table index

    if e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return None;
    }

    // Bounds check for section header table
    let sh_table_end = e_shoff + e_shnum * e_shentsize;
    if sh_table_end > data.len() {
        return None;
    }

    // Read section name string table
    let shstrtab_off = e_shoff + e_shstrndx * e_shentsize;
    if shstrtab_off + e_shentsize > data.len() {
        return None;
    }
    let strtab_offset = read_u64(shstrtab_off + 24) as usize;
    let strtab_size = read_u64(shstrtab_off + 32) as usize;

    if strtab_offset + strtab_size > data.len() {
        return None;
    }

    // Check for DT_TEXTREL in .dynamic section and find .text
    let mut has_textrel = false;
    let mut text_offset: Option<u64> = None;
    let mut text_size: Option<u64> = None;

    for i in 0..e_shnum {
        let sh_off = e_shoff + i * e_shentsize;
        if sh_off + e_shentsize > data.len() {
            break;
        }

        let sh_name_idx = read_u32(sh_off) as usize;
        let sh_type = read_u32(sh_off + 4);

        // Get section name
        if sh_name_idx < strtab_size {
            let name_start = strtab_offset + sh_name_idx;
            let name_end = data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| name_start + p)
                .unwrap_or(name_start);
            let name = std::str::from_utf8(&data[name_start..name_end]).unwrap_or("");

            if name == ".text" {
                text_offset = Some(read_u64(sh_off + 24)); // sh_offset
                text_size = Some(read_u64(sh_off + 32)); // sh_size
            }
        }

        // SHT_DYNAMIC = 6 — check for DT_TEXTREL entries
        if sh_type == 6 {
            let dyn_off = read_u64(sh_off + 24) as usize;
            let dyn_size = read_u64(sh_off + 32) as usize;
            if dyn_off + dyn_size <= data.len() {
                // Each dynamic entry is 16 bytes (d_tag u64, d_val u64)
                let mut pos = dyn_off;
                while pos + 16 <= dyn_off + dyn_size {
                    let d_tag = read_u64(pos);
                    if d_tag == 22 {
                        // DT_TEXTREL = 22
                        has_textrel = true;
                        break;
                    }
                    if d_tag == 0x6ffffffb {
                        // DT_FLAGS_1: check for DF_1_TEXTREL (bit 0)
                        // DT_FLAGS = 30: check for DF_TEXTREL (bit 2)
                    }
                    if d_tag == 30 {
                        // DT_FLAGS
                        let d_val = read_u64(pos + 8);
                        if d_val & 4 != 0 {
                            // DF_TEXTREL = 0x4
                            has_textrel = true;
                            break;
                        }
                    }
                    if d_tag == 0 {
                        break; // DT_NULL
                    }
                    pos += 16;
                }
            }
        }
    }

    let offset = text_offset?;
    let size = text_size?;

    // Sanity check: .text should be reasonable
    if size == 0 || offset + size > data.len() as u64 {
        return None;
    }

    Some(TextSectionInfo {
        file_offset: offset,
        size,
        has_textrel,
    })
}

/// Find the r-xp file-backed mapping that contains the .text section.
///
/// Each `r-xp` entry in `/proc/PID/maps` covers a contiguous range of the
/// binary file starting at `file_offset` and spanning exactly `end - start`
/// bytes. The .text section's file offset must fall within that range.
///
/// The `?` operator is intentionally NOT used on per-line parsing so that a
/// malformed line does not abort the entire search.
pub(super) fn find_text_mapping(maps: &str, exe_path: &str, text_file_offset: u64) -> Option<MappingInfo> {
    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        // Must be r-xp (read + execute, private)
        if !parts[1].starts_with("r-x") {
            continue;
        }

        // Must be mapped from the same executable.
        // /proc/PID/maps always shows the path as seen inside the process's
        // namespace, which matches the value returned by readlink(/proc/PID/exe).
        let mapped_path = parts[5..].join(" ");
        if !mapped_path.contains(exe_path) {
            continue;
        }

        // Parse start/end addresses and file offset; skip malformed lines
        // without aborting the search for subsequent valid lines.
        let (start, end) = match parse_address_range(parts[0]) {
            Some(r) => r,
            None => continue,
        };
        let file_offset = match u64::from_str_radix(parts[2], 16) {
            Ok(o) => o,
            Err(_) => continue,
        };

        // The mapping covers file bytes [file_offset, file_offset + mapping_size).
        // The virtual size of an r-xp segment equals its file coverage (no BSS
        // zero-fill in executable segments), so mapping_size is the correct span.
        let mapping_size = end - start;
        if text_file_offset >= file_offset
            && text_file_offset < file_offset + mapping_size
        {
            return Some(MappingInfo {
                start,
                file_offset,
            });
        }
    }

    None
}

/// Read a range of bytes from a file
pub(super) fn read_file_range(
    path: &std::path::Path,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size];
    let bytes_read = file.read(&mut buf)?;
    buf.truncate(bytes_read);
    Ok(buf)
}

/// Calculate SHA256 hash of data
pub(super) fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
