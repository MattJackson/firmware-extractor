//! pe_overlay() + pe_resources().
//!
//! Any malformed input (a read past the end of the buffer, a bad signature, etc.)
//! yields an empty result rather than an error.

/// Read a little-endian u32 at `off`, or `None` if it would run past the end.
fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let b = d.get(off..end)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian u16 at `off`, or `None` if it would run past the end.
fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let b = d.get(off..end)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Find the start of the PE image, tolerating a little leading junk before the
/// `MZ` magic. Some vendor download endpoints (e.g. the HLDS/LG PHP that serves
/// `DVDRAM_*` firmware) prepend a stray byte — typically a `0x20` space — ahead
/// of `MZ`, which would otherwise defeat a strict `d[..2] == "MZ"` check and make
/// the whole EXE look like one opaque blob. We scan the first 16 bytes for an
/// `MZ` whose `e_lfanew` points at a valid `PE\0\0`, and rebase from there.
fn pe_start(d: &[u8]) -> Option<usize> {
    for off in 0..d.len().min(16) {
        if d.get(off..off + 2) != Some(b"MZ") {
            continue;
        }
        let e = off + rd_u32(d, off + 0x3c)? as usize;
        if d.get(e..e.saturating_add(4)) == Some(b"PE\0\0") {
            return Some(off);
        }
    }
    None
}

/// Return bytes appended after the PE image (the overlay), or empty.
pub fn pe_overlay(d: &[u8]) -> Vec<u8> {
    pe_overlay_inner(d).unwrap_or_default()
}

fn pe_overlay_inner(d: &[u8]) -> Option<Vec<u8>> {
    // Rebase past any leading junk before MZ; no PE -> no overlay.
    let d = match pe_start(d) {
        Some(s) => &d[s..],
        None => return Some(Vec::new()),
    };
    let e = rd_u32(d, 0x3c)? as usize;
    // No PE signature at e_lfanew: no overlay.
    if d.get(e..e.saturating_add(4)) != Some(b"PE\0\0") {
        return Some(Vec::new());
    }
    let nsec = rd_u16(d, e + 6)? as usize;
    let optsz = rd_u16(d, e + 20)? as usize;
    let st = e + 24 + optsz;
    // Use u64 for the running maximum: PointerToRawData + SizeOfRawData can
    // exceed u32.
    let mut end: u64 = 0;
    for i in 0..nsec {
        let o = st + i * 40;
        let raw_ptr = rd_u32(d, o + 20)? as u64;
        let raw_sz = rd_u32(d, o + 16)? as u64;
        end = end.max(raw_ptr + raw_sz);
    }
    let len = d.len() as u64;
    if end > 0 && end < len {
        Some(d[end as usize..].to_vec())
    } else {
        Some(Vec::new())
    }
}

/// Return `(name, blob)` for every PE resource data entry.
pub fn pe_resources(d: &[u8]) -> Vec<(String, Vec<u8>)> {
    pe_resources_inner(d).unwrap_or_default()
}

fn pe_resources_inner(d: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    // Rebase past any leading junk before MZ (see pe_start).
    let d = match pe_start(d) {
        Some(s) => &d[s..],
        None => return Some(Vec::new()),
    };
    let e = rd_u32(d, 0x3c)? as usize;
    if d.get(e..e.saturating_add(4)) != Some(b"PE\0\0") {
        return Some(Vec::new());
    }
    let nsec = rd_u16(d, e + 6)? as usize;
    let optsz = rd_u16(d, e + 20)? as usize;
    let opt = e + 24;
    let magic = rd_u16(d, opt)?;
    let ddir = opt + if magic == 0x20b { 112 } else { 96 };
    let rsrc_rva = rd_u32(d, ddir + 2 * 8)? as usize; // entry 2 = resources
    if rsrc_rva == 0 {
        return Some(Vec::new());
    }
    let sect = opt + optsz;
    // Section table: (VirtualAddress, PointerToRawData, VirtualSize)
    let mut secs: Vec<(usize, usize, usize)> = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let o = sect + i * 40;
        let va = rd_u32(d, o + 12)? as usize;
        let rawoff = rd_u32(d, o + 20)? as usize;
        let vsz = rd_u32(d, o + 8)? as usize;
        secs.push((va, rawoff, vsz));
    }

    let base = rva2off(&secs, rsrc_rva)?;
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    walk(d, &secs, base, base, 0, &mut out);
    Some(out)
}

/// Map an RVA to a file offset. Section SELECTION is exact — the section with the
/// greatest `va <= rva`, i.e. the one that actually contains the RVA. (An earlier
/// bug selected by a slack window, which overlapped the next contiguous section and
/// mis-mapped e.g. an `.rsrc` RVA into `.data`; selecting the greatest `va <= rva`
/// fixes that.) The `+ 0x2000` below is NOT slack in selection — it is a tolerance
/// on the UPPER bound within the already-chosen section: `VirtualSize` is often
/// smaller than the section's real on-disk data (alignment/rounding), so an RVA up
/// to 0x2000 past `VirtualSize` is still mapped rather than rejected. Reads through
/// the returned offset remain bounds-checked by the caller.
fn rva2off(secs: &[(usize, usize, usize)], rva: usize) -> Option<usize> {
    let mut best: Option<(usize, usize, usize)> = None;
    for &(va, ro, vs) in secs {
        if rva >= va && best.is_none_or(|b| va > b.0) {
            best = Some((va, ro, vs));
        }
    }
    let (va, ro, vs) = best?;
    if rva - va >= vs.max(1) + 0x2000 {
        return None;
    }
    Some(ro + (rva - va))
}

fn walk(
    d: &[u8],
    secs: &[(usize, usize, usize)],
    base: usize,
    off: usize,
    depth: u32,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    if depth > 3 || off + 16 > d.len() {
        return;
    }
    // NumberOfNamedEntries / NumberOfIdEntries.
    let nnamed = match rd_u16(d, off + 12) {
        Some(v) => v as usize,
        None => return,
    };
    let nid = match rd_u16(d, off + 14) {
        Some(v) => v as usize,
        None => return,
    };
    let ent = off + 16;
    for i in 0..(nnamed + nid) {
        let eo = ent + i * 8;
        if eo + 8 > d.len() {
            return;
        }
        let off_to = match rd_u32(d, eo + 4) {
            Some(v) => v,
            None => return,
        };
        if off_to & 0x8000_0000 != 0 {
            // subdirectory
            let next = base.saturating_add((off_to & 0x7fff_ffff) as usize);
            walk(d, secs, base, next, depth + 1, out);
        } else {
            // data entry
            let de = base.saturating_add(off_to as usize);
            if de + 16 > d.len() {
                continue;
            }
            let data_rva = match rd_u32(d, de) {
                Some(v) => v as usize,
                None => continue,
            };
            let size = match rd_u32(d, de + 4) {
                Some(v) => v as usize,
                None => continue,
            };
            if let Some(do_) = rva2off(secs, data_rva) {
                if (256..=64 * 1024 * 1024).contains(&size) && do_ + size <= d.len() {
                    out.push(("rsrc".to_string(), d[do_..do_ + size].to_vec()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_mz_input_yields_empty() {
        let d = b"not a pe file at all, definitely no MZ magic here";
        assert!(pe_overlay(d).is_empty());
        assert!(pe_resources(d).is_empty());
    }

    #[test]
    fn empty_input_yields_empty() {
        assert!(pe_overlay(&[]).is_empty());
        assert!(pe_resources(&[]).is_empty());
    }

    #[test]
    fn pe_start_tolerates_leading_junk() {
        // Minimal MZ with e_lfanew=0x40 pointing at "PE\0\0".
        let mut img = vec![0u8; 0x48];
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        img[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(pe_start(&img), Some(0));
        // A stray leading byte (the HLDS/LG PHP case) before MZ is tolerated.
        let mut junked = vec![0x20u8];
        junked.extend_from_slice(&img);
        // e_lfanew is relative to MZ, so it still resolves via the +off rebase.
        assert_eq!(pe_start(&junked), Some(1));
        // Pure garbage with no PE has no start.
        assert_eq!(pe_start(b"not a pe at all, no magic"), None);
    }

    /// Build a minimal MZ+PE image with e_lfanew = 0x40, optionally prefixed by
    /// `lead` junk bytes.
    fn mz_pe(lead: usize) -> Vec<u8> {
        let mut img = vec![0u8; 0x48];
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        img[0x40..0x44].copy_from_slice(b"PE\0\0");
        let mut out = vec![0xabu8; lead];
        out.extend_from_slice(&img);
        out
    }

    #[test]
    fn pe_start_rejects_mz_beyond_scan_window() {
        // MZ located at offset 16 is past the first-16-bytes scan window -> None
        // (pe_start only tolerates a little leading junk, not arbitrary offsets).
        assert_eq!(pe_start(&mz_pe(16)), None);
        // At offset 15 it is still within the window.
        assert_eq!(pe_start(&mz_pe(15)), Some(15));
    }

    #[test]
    fn pe_start_rejects_mz_without_valid_pe_sig() {
        // MZ present, e_lfanew points somewhere that is not "PE\0\0" -> None.
        let mut img = vec![0u8; 0x48];
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // leave 0x40.. as zeros (not "PE\0\0")
        assert_eq!(pe_start(&img), None);
    }

    #[test]
    fn pe_start_no_panic_on_truncated_e_lfanew() {
        // MZ but too short to hold e_lfanew at 0x3c -> None, no panic.
        assert_eq!(pe_start(b"MZ"), None);
        assert_eq!(pe_start(b"MZ\x00\x00\x00\x00"), None);
    }
}
