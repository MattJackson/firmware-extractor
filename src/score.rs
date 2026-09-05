//! score_fw() + JUNK/RAW ext + PE_SECTION + MAGICS. Higher = more likely THE
//! firmware. MZ/container wrappers must never win (see extract).
//!
//! `score_fw(name, blob)` applies additive weights, size/entropy thresholds, and
//! regex matches. The string searches (MTK/EXACT/BANNER) run over
//! `strings_blob(blob[:1<<20])` — the concatenation of printable runs of length
//! >= 4 joined by `\n`.

use regex::bytes::Regex;
use std::sync::OnceLock;

// ── extension sets (JUNK_EXT / RAW_EXT) ──
const RAW_EXT: &[&str] = &[
    ".bin", ".frm", ".rom", ".fw", ".img", ".afs", ".bix", ".ric", ".rvm", ".rff", ".lfl", ".hex",
    ".dat",
];
const JUNK_EXT: &[&str] = &[
    ".txt", ".pdf", ".rtf", ".doc", ".htm", ".html", ".url", ".nfo", ".ini", ".inf", ".cat",
    ".dll", ".sys", ".vxd", ".chm", ".gif", ".jpg", ".png", ".bmp", ".ico", ".xml", ".log", ".cfg",
    ".reg",
];

// ── vendor firmware header magics (searched in blob[:64]); labels unused for scoring ──
const MAGICS: &[&[u8]] = &[b"ASUS FILE SYSTEM", b"****", b"MATSHITA", b"<iii"];

// ── EXACT_PARTS regex sources (labels irrelevant to the score, only presence matters) ──
const EXACT_PARTS_SRC: &[&str] = &[
    r"MMP[0-9]{3}",
    r"SH7[0-9]{3}",
    r"HD64F30[0-9]{2}|\b30[0-9]{2}F\b",
    r"Renesas",
    r"Nexperia|PNX[0-9]{3,}",
];

fn mtk_part() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"MT1[389][0-9]{2}[A-Z]?").unwrap())
}
fn mtk_ctx() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)MEDIATEK|SRVMTK|MTKDW|MTKFLASH|MTEKMT|Mtk\.SYS|\bMTK[0-9]").unwrap()
    })
}
fn banner() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"Boot[ _][A-Z0-9]{2,8}").unwrap())
}
fn exact_parts() -> &'static Vec<Regex> {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        EXACT_PARTS_SRC
            .iter()
            .map(|s| Regex::new(s).unwrap())
            .collect()
    })
}
fn pe_section() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // Anchored at both ends (`^...$`), case-insensitive (`(?i)`).
    R.get_or_init(|| {
        Regex::new(
            r"(?i)^[0-9A-Fa-f]*\.?(text|rdata|data|rsrc|reloc|idata|edata|pdata|bss|tls|xdata|didat|crt|gfids|debug)$",
        )
        .unwrap()
    })
}
fn readme_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(readme|license|setup|uninst|redist|vcredist|autorun)").unwrap())
}

/// Basename of `name` — everything after the last `/`.
fn basename(name: &str) -> &str {
    match name.rfind('/') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// The file extension of `name` including the leading dot, or "" if there is
/// none. Leading dots of the basename (dotfiles) are not an extension.
fn ext_of(name: &str) -> &str {
    let sep = name.rfind('/').map(|i| i as isize).unwrap_or(-1);
    let dot = match name.rfind('.') {
        Some(d) => d as isize,
        None => return "",
    };
    if dot > sep {
        // skip leading dots of the filename component
        let mut fi = sep + 1;
        while fi < dot {
            if name.as_bytes()[fi as usize] != b'.' {
                return &name[dot as usize..];
            }
            fi += 1;
        }
    }
    ""
}

/// Join every maximal run of printable bytes (`[\x20-\x7e]{4,}`) with a single
/// `\n` (0x0a).
fn strings_blob(b: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut run_start = 0usize;
    let mut in_run = false;
    let mut first = true;
    let flush = |out: &mut Vec<u8>, first: &mut bool, slice: &[u8]| {
        if slice.len() >= 4 {
            if !*first {
                out.push(b'\n');
            }
            out.extend_from_slice(slice);
            *first = false;
        }
    };
    for (i, &x) in b.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(&x);
        if printable && !in_run {
            in_run = true;
            run_start = i;
        } else if !printable && in_run {
            flush(&mut out, &mut first, &b[run_start..i]);
            in_run = false;
        }
    }
    if in_run {
        flush(&mut out, &mut first, &b[run_start..]);
    }
    out
}

/// Score a firmware candidate. Higher = more likely THE firmware image; `<= 0`
/// should be rejected by the caller.
pub fn score_fw(name: &str, blob: &[u8]) -> i64 {
    let n = name.to_lowercase();
    let ext = ext_of(&n);
    let size = blob.len();

    if size < 4096 {
        return -1;
    }
    if JUNK_EXT.contains(&ext) || pe_section().is_match(basename(&n).as_bytes()) {
        return -1;
    }
    if readme_re().is_match(n.as_bytes()) {
        return -1;
    }

    let mut s: i64 = 0;

    if RAW_EXT.contains(&ext) {
        s += 60;
    }

    // vendor firmware header magic in the first 64 bytes
    let head64 = &blob[..blob.len().min(64)];
    for mag in MAGICS {
        if find_sub(head64, mag).is_some() {
            s += 80;
        }
    }

    // strings of blob[:1MB]
    let st = strings_blob(&blob[..blob.len().min(1 << 20)]);
    if mtk_part().is_match(&st) && mtk_ctx().is_match(&st) {
        s += 70;
    }
    for pat in exact_parts() {
        if pat.is_match(&st) {
            s += 60;
        }
    }
    if banner().is_match(&st) {
        s += 40;
    }

    // entropy of blob[len/8 .. len/8 + 1MB] (fall back to whole blob if empty)
    let lo = blob.len() / 8;
    let hi = (lo + (1 << 20)).min(blob.len());
    let body = if lo < hi { &blob[lo..hi] } else { blob };
    let h = crate::entropy(body);
    if (4.0..=7.3).contains(&h) {
        s += 25;
    } else if h >= 7.9 {
        s += 5;
    }

    // a PE candidate is usually the flasher, not the image
    if blob.len() >= 2 && &blob[..2] == b"MZ" {
        s -= 30;
    }

    if (32 * 1024..=16 * 1024 * 1024).contains(&size) {
        s += 20;
    }

    s += std::cmp::min((size / (256 * 1024)) as i64, 15);
    s
}

/// First index of `needle` within `haystack`, or None.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A blob big enough to pass the size gate, low-entropy zeros.
    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    #[test]
    fn too_small_rejected() {
        assert_eq!(score_fw("a.bin", &zeros(100)), -1);
    }

    #[test]
    fn junk_ext_rejected() {
        assert_eq!(score_fw("readme.txt", &zeros(100_000)), -1);
        assert_eq!(score_fw("driver.dll", &zeros(100_000)), -1);
    }

    #[test]
    fn pe_section_name_rejected() {
        assert_eq!(score_fw(".rsrc", &zeros(100_000)), -1);
        assert_eq!(score_fw("00abcd.text", &zeros(100_000)), -1);
    }

    #[test]
    fn readme_name_rejected() {
        // .bin ext dodges JUNK_EXT but the name keyword still rejects.
        assert_eq!(score_fw("vcredist_x86.bin", &zeros(100_000)), -1);
        assert_eq!(score_fw("SETUP.bin", &zeros(100_000)), -1);
    }

    #[test]
    fn raw_ext_bonus_and_size_band() {
        // 100_000 bytes, zeros: raw ext +60, entropy 0 (no band), not MZ,
        // 32KiB<=size<=16MiB +20, size//256KiB = 0.
        assert_eq!(score_fw("fw.bin", &zeros(100_000)), 80);
        // .unknownext: no raw bonus -> 20.
        assert_eq!(score_fw("fw.xyz", &zeros(100_000)), 20);
    }

    #[test]
    fn mz_penalty() {
        // Start from a raw-ext zero blob (80) then flip first two bytes to MZ: -30.
        let mut b = zeros(100_000);
        b[0] = b'M';
        b[1] = b'Z';
        // MZ printable run is only 2 bytes (<4) so no strings hit; entropy still ~0.
        assert_eq!(score_fw("fw.bin", &b), 80 - 30);
    }

    #[test]
    fn size_component_and_large_band() {
        // 1 MiB of zeros, raw ext: +60, +20 (band), size//256KiB = 4.
        let b = zeros(1024 * 1024);
        assert_eq!(score_fw("fw.bin", &b), 60 + 20 + 4);
        // Clamp at 15: 8 MiB -> size//256KiB = 32 -> min 15.
        let big = zeros(8 * 1024 * 1024);
        assert_eq!(score_fw("fw.bin", &big), 60 + 20 + 15);
    }

    #[test]
    fn below_size_band_no_bonus() {
        // 20_000 bytes (>=4096 but <32KiB): raw ext +60, no size-band +20,
        // size//256KiB = 0, entropy 0.
        assert_eq!(score_fw("fw.bin", &zeros(20_000)), 60);
    }

    #[test]
    fn magic_header_bonus() {
        // MATSHITA magic in first 64 bytes -> +80, plus raw ext 60, band 20.
        let mut b = zeros(100_000);
        b[..8].copy_from_slice(b"MATSHITA");
        assert_eq!(score_fw("fw.bin", &b), 60 + 80 + 20);
    }

    #[test]
    fn banner_and_mtk_strings() {
        // Build a blob whose strings contain a boot banner + MTK part/context.
        let mut b = Vec::new();
        b.extend_from_slice(b"Boot MT1359 MEDIATEK flasher build\x00");
        b.extend_from_slice(&vec![0u8; 100_000]);
        // raw ext 60, MTK part+ctx 70, banner 40, size band 20. entropy ~0.
        assert_eq!(score_fw("fw.bin", &b), 60 + 70 + 40 + 20);
    }
}
