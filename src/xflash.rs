//! XFlash plaintext-firmware carving.
//!
//! MediaTek XFlash flashers (LiteOn/Sony/Plextor/TDK/Optiarc/…) embed the raw
//! optical-drive firmware image **plaintext** inside the unpacked flasher — never
//! encrypted. This module carves it by SIGNATURE (no hardcoded offsets). Each
//! optical-drive MCU is an 8051 whose image begins with a vector table, so every
//! family's image starts with an `LJMP` (`0x02`) or `CLR bit` (`0xC2`) opcode; the
//! families differ only in the exact start signature and the anchor/end rule.
//!
//! `carve()` tries the family strategies in order and returns the first image that
//! passes (right 8051 head, plausible NOR size, plaintext entropy), tagged with the
//! family it matched — the identify→dispatch contract.

/// Try every family strategy; return `(firmware, family_tag)` for the first hit.
pub fn carve(blob: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    if let Some(fw) = carve_verbatim(blob) {
        return Some((fw, "xflash-verbatim")); // full distribution image (LiteOn BL0X)
    }
    if let Some(fw) = carve_resetvec(blob) {
        return Some((fw, "xflash-8051-resetvec")); // LiteOn + Plextor
    }
    if let Some(fw) = carve_vec_c295(blob) {
        return Some((fw, "xflash-8051-vectable")); // TDK + Sony family A
    }
    if let Some(fw) = carve_benq(blob) {
        return Some((fw, "xflash-benq-vector")); // BenQ CD-RW/DVD
    }
    if let Some(fw) = carve_sony(blob) {
        return Some((fw, "xflash-sony")); // Sony families B/C/D
    }
    if let Some(fw) = carve_atapi(blob) {
        return Some((fw, "xflash-atapi")); // LiteOn banner-anchored variants
    }
    if let Some(fw) = carve_plextor_vectable(blob) {
        return Some((fw, "xflash-plextor-vectable")); // Plextor PX-130A class
    }
    if let Some(fw) = carve_mtkdw(blob) {
        return Some((fw, "xflash-mtkdw")); // Pioneer MT1868 (uncompressed in PE .data)
    }
    None
}

const MIN: usize = 0x1_0000; // 64 KiB (CD-era Sony images are small)
const MAX: usize = 0x40_0000; // 4 MiB

/// Firmware images are erase-sector aligned; both the zero/fill end-rules scan in
/// 4 KiB blocks and stop after this many sustained all-fill blocks (32 KiB).
const BLOCK: usize = 0x1000;
const FILL_BLOCKS_END: usize = 8;
/// Bytes to skip past a signature before scanning for the trailing zero run, so an
/// internal zero gap right after the header is not mistaken for the image end.
const HEAD_SKIP: usize = 0x1000;
/// A trailing run of this many zero bytes marks the end of an image with no
/// internal gaps (allocation padding).
const ZERO_RUN_END: usize = 4096;

/// Shannon entropy over a window; used for the entropy-wall end rule.
fn ent(b: &[u8]) -> f64 {
    crate::entropy(b)
}

/// Accept a carved slice only if it is a plausible NOR-image size and plaintext
/// (a transformed/compressed blob reads ~7.9).
fn accept(fw: &[u8]) -> bool {
    (MIN..=MAX).contains(&fw.len()) && ent(fw) < 7.6
}

/// Forward from `from`: first offset that starts a run of `>= n` zero bytes, else
/// `blob.len()`.
fn zero_run_fwd(blob: &[u8], from: usize, n: usize) -> usize {
    let mut run = 0usize;
    for (i, &b) in blob.iter().enumerate().skip(from) {
        if b == 0 {
            run += 1;
            if run >= n {
                return i - run + 1;
            }
        } else {
            run = 0;
        }
    }
    blob.len()
}

/// Backward from `off`: end offset of the nearest preceding run of `>= minrun`
/// zero bytes (i.e. the first code byte after that padding), else 0.
fn code_start_before(blob: &[u8], off: usize, minrun: usize) -> usize {
    let mut run = 0usize;
    let mut i = off;
    while i > 0 {
        if blob[i] == 0 {
            run += 1;
            if run >= minrun {
                return i + run;
            }
        } else {
            run = 0;
        }
        i -= 1;
    }
    0
}

/// First 16 KiB window at/after `start` where this window AND the next both exceed
/// 7.6 entropy (a compressed/encrypted blob following the plaintext code). Two
/// consecutive windows are required to reject one-off high-entropy tables.
fn entropy_wall(blob: &[u8], start: usize) -> Option<usize> {
    const W: usize = 0x4000;
    // A valid image never exceeds MAX, so cap the scan at start + MAX (plus one
    // window of slack to find the wall itself). This bounds the cost on a large
    // input that merely contains a false-positive signature near its start.
    let limit = blob.len().min(start.saturating_add(MAX).saturating_add(W));
    let mut i = start + W; // never wall the code head itself
                           // Reuse the second window's entropy as the next iteration's first window.
    let mut cur = if i + W <= limit {
        Some(ent(&blob[i..i + W]))
    } else {
        None
    };
    while i + 2 * W <= limit {
        let next = ent(&blob[i + W..i + 2 * W]);
        if cur.unwrap_or(0.0) > 7.6 && next > 7.6 {
            return Some(i);
        }
        cur = Some(next);
        i += W;
    }
    None
}

/// VERBATIM distribution image: some flashers store the full distribution image
/// (not just the raw code body) headed by `[\x1a\x1b]<4 printable ver>\xff{7}`
/// (LiteOn iHAS124/BL0X class). Carve byte-exact from that header to its trailing
/// zero padding. The min size is larger than the plaintext families' because this
/// includes the distribution wrapper, so gate at `VERBATIM_MIN` rather than `MIN`.
const VERBATIM_MIN: usize = 0x40000;
fn carve_verbatim(blob: &[u8]) -> Option<Vec<u8>> {
    use regex::bytes::Regex;
    use std::sync::OnceLock;
    static SIG: OnceLock<Regex> = OnceLock::new();
    let sig = SIG.get_or_init(|| Regex::new(r"(?-u)[\x1a\x1b][\x20-\x7e]{4}\xff{7}").unwrap());
    let start = sig.find(blob)?.start();
    let end = zero_run_fwd(blob, start + HEAD_SKIP, ZERO_RUN_END);
    let fw = blob.get(start..end)?;
    if fw.len() < VERBATIM_MIN || fw.len() > MAX || ent(fw) >= 7.6 {
        return None;
    }
    Some(fw.to_vec())
}

/// LiteOn + Plextor: image begins with the exact 8051 reset stub
/// `02 30 03 C2 AF 02 30 40` (`LJMP 0x3003 ; CLR EA ; LJMP 0x3040`). End at the
/// smaller of the first 4 KiB zero run and the first entropy wall (some Plextor
/// images are followed by a high-entropy secondary resource).
fn carve_resetvec(blob: &[u8]) -> Option<Vec<u8>> {
    const SIG: &[u8] = &[0x02, 0x30, 0x03, 0xc2, 0xaf, 0x02, 0x30, 0x40];
    let start = find(blob, SIG)?;
    let hard = zero_run_fwd(blob, start + HEAD_SKIP, ZERO_RUN_END);
    let end = match entropy_wall(blob, start) {
        Some(w) => hard.min(w),
        None => hard,
    };
    let fw = blob.get(start..end)?;
    accept(fw).then(|| fw.to_vec())
}

/// TDK family A + Sony family A: image begins with the mirrored 8051 vector-table
/// record `C2 95 C2 96 02 .. .. 22`. TDK images have internal 4 KiB zero gaps, so
/// the end is the last non-empty 4 KiB block before a sustained (>=8-block / 32 KiB)
/// zero run — a plain "first 4 KiB zero run" would truncate them ~8x short.
fn carve_vec_c295(blob: &[u8]) -> Option<Vec<u8>> {
    const SIG: &[u8] = &[0xc2, 0x95, 0xc2, 0x96, 0x02];
    let start = find(blob, SIG)?;
    // Head must be the full mirrored record (…02 xx xx 22), not a chance match.
    if blob.get(start + 7) != Some(&0x22) {
        return None;
    }
    let end = end_by_blocks(blob, start, false);
    let fw = blob.get(start..end)?;
    accept(fw).then(|| fw.to_vec())
}

/// End rule for images with internal fill gaps (TDK/BenQ/Plextor): the end of the
/// last non-fill 4 KiB block before a sustained run of `>= FILL_BLOCKS_END` all-fill
/// blocks (32 KiB). A plain "first 4 KiB zero run" truncates these images at an
/// internal padding gap. A block is "fill" if it is entirely `0x00`, or — when
/// `allow_ff` — entirely `0xFF` (NOR erase state, used by Plextor).
fn end_by_blocks(blob: &[u8], start: usize, allow_ff: bool) -> usize {
    let mut last_nonfill_end = start;
    let mut fill_blocks = 0usize;
    let mut i = start;
    while i < blob.len() {
        let end = (i + BLOCK).min(blob.len());
        let blk = &blob[i..end];
        let is_fill = blk.iter().all(|&b| b == 0) || (allow_ff && blk.iter().all(|&b| b == 0xff));
        if is_fill {
            fill_blocks += 1;
            if fill_blocks >= FILL_BLOCKS_END {
                break;
            }
        } else {
            fill_blocks = 0;
            last_nonfill_end = end;
        }
        i += BLOCK;
    }
    last_nonfill_end
}

/// BenQ CD-RW/DVD: image begins with a fixed 24-byte BenQ boot-vector header
/// (`60 F4 67 76 80 0A 68 76 …`), byte-identical across models. 8051 plaintext with
/// internal zero gaps, so use the sustained-zero-block end rule.
fn carve_benq(blob: &[u8]) -> Option<Vec<u8>> {
    const SIG: &[u8] = &[
        0x60, 0xf4, 0x67, 0x76, 0x80, 0x0a, 0x68, 0x76, 0x70, 0xf3, 0x67, 0x76, 0x10, 0x48, 0x68,
        0x76, 0x70, 0x04, 0x68, 0x76, 0x60, 0xf5, 0x67, 0x76,
    ];
    let start = find(blob, SIG)?;
    let end = end_by_blocks(blob, start, false);
    let fw = blob.get(start..end)?;
    accept(fw).then(|| fw.to_vec())
}

/// Sony: anchored by the T10 INQUIRY banner `SONY    <product/model/rev/date>`.
/// Walk back to candidate zero-run boundaries (nearest first) and accept the first
/// whose head is a valid 8051 vector lead; end at the first 4 KiB zero run.
fn carve_sony(blob: &[u8]) -> Option<Vec<u8>> {
    use regex::bytes::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?-u)SONY {4}[\x20-\x7e]{16,60}").unwrap());
    for m in re.find_iter(blob) {
        let anchor = m.start();
        // Candidate starts: nearest preceding zero runs of decreasing strictness.
        for minrun in [4096usize, 1024, 256, 128] {
            let start = code_start_before(blob, anchor, minrun);
            if start == 0 || start >= anchor {
                continue;
            }
            if !sony_head_ok(&blob[start..]) {
                continue;
            }
            let end = zero_run_fwd(blob, anchor.max(start + HEAD_SKIP), ZERO_RUN_END);
            let fw = match blob.get(start..end) {
                Some(f) => f,
                None => continue,
            };
            if accept(fw) {
                return Some(fw.to_vec());
            }
        }
    }
    None
}

/// A valid Sony 8051 image head: family A `C2 95 C2 96 02`, family B
/// `02 xx xx C2 AF 02`, or a raw vector table `02 xx xx 02 xx xx` — but not a
/// degenerate run of a single repeated byte (erased flash).
fn sony_head_ok(h: &[u8]) -> bool {
    if h.len() < 8 {
        return false;
    }
    if h[..8]
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        <= 2
    {
        return false; // degenerate/erased
    }
    let fam_a = h[0] == 0xc2 && h[1] == 0x95 && h[2] == 0xc2 && h[3] == 0x96 && h[4] == 0x02;
    let fam_b = h[0] == 0x02 && h[3] == 0xc2 && h[4] == 0xaf && h[5] == 0x02;
    let fam_c = h[0] == 0x02 && h[3] == 0x02; // two LJMPs = interrupt vector table
    fam_a || fam_b || fam_c
}

/// LiteOn variants not covered by the exact reset-vector signature: anchor on the
/// `ATAPI   <model>` banner, back to the preceding zero run, require an `LJMP`
/// (`0x02`) head, end at the first 4 KiB zero run.
fn carve_atapi(blob: &[u8]) -> Option<Vec<u8>> {
    use regex::bytes::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?-u)ATAPI   [\x20-\x7e]{4,40}").unwrap());
    let anchor = re.find(blob)?.start();
    let start = code_start_before(blob, anchor, 256);
    if start >= anchor || blob.get(start) != Some(&0x02) {
        return None;
    }
    let end = zero_run_fwd(blob, anchor.max(start + HEAD_SKIP), ZERO_RUN_END);
    let fw = blob.get(start..end)?;
    accept(fw).then(|| fw.to_vec())
}

/// Plextor PX-130A class: a small MZ flasher embedding an 8051 image in its PE
/// `.data` — the image opens with an interrupt-vector table (`02 xx xx 02 xx xx`,
/// LJMPs at a 3-byte stride, gaps 0xFF-filled) and carries a `PLEXTOR` banner near
/// the tail, followed by 0xFF erase-fill. Gated on the PLEXTOR banner to keep the
/// generic vector pattern from false-matching.
fn carve_plextor_vectable(blob: &[u8]) -> Option<Vec<u8>> {
    find(blob, b"PLEXTOR")?;
    // Candidate start: an LJMP-vector pair preceded by >= 8 zero bytes.
    let mut i = 8;
    while i + 6 < blob.len() {
        let is_vec = blob[i] == 0x02 && blob[i + 3] == 0x02;
        let zero_before = blob[i - 8..i].iter().all(|&b| b == 0);
        if is_vec && zero_before {
            // Image has internal 0xFF erase-fill gaps, so end at the last non-fill
            // 4 KiB block before a sustained (>=8-block) run of all-0x00/all-0xFF fill.
            let end = end_by_blocks(blob, i, true);
            let fw = &blob[i..end];
            // Must contain the PLEXTOR banner within the carved image, and pass gates.
            if find(fw, b"PLEXTOR").is_some() && accept(fw) {
                return Some(fw.to_vec());
            }
        }
        i += 1;
    }
    None
}

/// Pioneer MT1868-class: the flasher stores the firmware UNCOMPRESSED in its PE
/// `.data`. The image begins right after a large NOR-erase pad (`0xFF` run) with an
/// 8051 entry — either the `D2 90 00 00 00 00 02` stub (`SETB P1.0; NOP; NOP; LJMP`)
/// or a bare `02` (`LJMP`) — and ends at the trailing zero padding. Scanned over the
/// whole blob (the image sits in `.data` of the outer PE, so no PE parse is needed);
/// gated on a MediaTek flash-driver marker (`ATAPIWrite`/`MTKDW`) inside the carved
/// image so the generic `02` entry cannot false-match.
fn carve_mtkdw(blob: &[u8]) -> Option<Vec<u8>> {
    const A: &[u8] = &[0xd2, 0x90, 0x00, 0x00, 0x00, 0x00, 0x02];
    let mut i = 0usize;
    while i < blob.len() {
        if blob[i] != 0xff {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < blob.len() && blob[i] == 0xff {
            i += 1;
        }
        if i - run_start < 0x2000 {
            continue;
        }
        // `i` is the first non-0xFF byte after a >= 8 KiB erase pad.
        let entry = blob.get(i..i + 7) == Some(A) || blob.get(i) == Some(&0x02);
        if !entry {
            continue;
        }
        let end = zero_run_fwd(blob, i + HEAD_SKIP, 0x4000);
        let fw = match blob.get(i..end) {
            Some(f) => f,
            None => continue,
        };
        if accept(fw) && (find(fw, b"ATAPIWrite").is_some() || find(fw, b"MTKDW").is_some()) {
            return Some(fw.to_vec());
        }
    }
    None
}

/// First index of `needle` in `hay`, or `None`. Uses memchr to skip to candidate
/// first-byte positions rather than comparing at every offset — the signature
/// scans run over multi-MB flasher dumps, so a naive byte-by-byte window compare
/// is the hot path.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut base = 0usize;
    while let Some(rel) = memchr::memchr(first, &hay[base..]) {
        let at = base + rel;
        if at + needle.len() > hay.len() {
            return None;
        }
        if &hay[at..at + needle.len()] == needle {
            return Some(at);
        }
        base = at + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_gates() {
        assert!(sony_head_ok(&[
            0x02, 0x10, 0x03, 0xc2, 0xaf, 0x02, 0x10, 0x30
        ]));
        assert!(sony_head_ok(&[
            0xc2, 0x95, 0xc2, 0x96, 0x02, 0x28, 0x00, 0x22
        ]));
        assert!(sony_head_ok(&[
            0x02, 0x40, 0x00, 0x02, 0x40, 0x03, 0x12, 0x55
        ]));
        assert!(!sony_head_ok(&[
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
        ]));
        assert!(!sony_head_ok(&[0x00, 0x00]));
    }

    #[test]
    fn find_needle() {
        assert_eq!(find(b"xxABCyy", b"ABC"), Some(2));
        assert_eq!(find(b"xxxx", b"ABC"), None);
    }

    #[test]
    fn zero_run_and_accept() {
        let mut b = vec![1u8; 0x2000];
        b.extend(std::iter::repeat_n(0u8, 5000));
        assert_eq!(zero_run_fwd(&b, 0, 4096), 0x2000);
        // too small to accept
        assert!(!accept(&b[..0x2000]));
    }

    // ── helpers to synthesize a plausible plaintext 8051 image ──

    /// A low-entropy body of `len` bytes starting with `head`, padded with a short
    /// repeating pattern (small alphabet) so Shannon entropy stays well under 7.6 —
    /// like real 8051 code — and it is neither an all-0x00 nor all-0xFF run.
    fn body(head: &[u8], len: usize) -> Vec<u8> {
        // A 4-symbol pattern gives entropy ~2 bits/byte, far below the 7.6 gate.
        const PAT: [u8; 4] = [0x12, 0x34, 0x02, 0x90];
        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(head);
        while v.len() < len {
            v.push(PAT[v.len() % PAT.len()]);
        }
        v.truncate(len);
        v
    }

    /// Wrap `img` with `lead` zero bytes before and `trail` zero bytes after.
    fn wrap(lead: usize, img: &[u8], trail: usize) -> Vec<u8> {
        let mut v = vec![0u8; lead];
        v.extend_from_slice(img);
        v.extend(std::iter::repeat_n(0u8, trail));
        v
    }

    const RESETVEC: [u8; 8] = [0x02, 0x30, 0x03, 0xc2, 0xaf, 0x02, 0x30, 0x40];

    #[test]
    fn find_uses_first_byte_and_matches_at_end() {
        // needle exactly at the end of the haystack must still be found.
        let mut h = vec![9u8; 100];
        h.extend_from_slice(b"SIG");
        assert_eq!(find(&h, b"SIG"), Some(100));
        // a first-byte match that does not extend far enough returns None safely.
        assert_eq!(find(b"abcS", b"SIG"), None);
        // empty needle / oversize needle
        assert_eq!(find(b"abc", b""), None);
        assert_eq!(find(b"ab", b"abcd"), None);
    }

    #[test]
    fn accept_rejects_oversize_and_high_entropy() {
        // too big
        assert!(!accept(&vec![1u8; MAX + 1]));
        // in-size but high entropy (random-ish) must be rejected
        let mut hi = Vec::with_capacity(MIN);
        let mut x = 0u32;
        for _ in 0..MIN {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            hi.push((x >> 24) as u8);
        }
        assert!(ent(&hi) >= 7.6);
        assert!(!accept(&hi));
        // in-size, low entropy accepted
        assert!(accept(&body(&RESETVEC, MIN)));
    }

    #[test]
    fn code_start_before_lands_after_padding() {
        // [nonzero..][>=minrun zeros][code..]; must return start of code.
        let mut b = vec![7u8; 10];
        b.extend(std::iter::repeat_n(0u8, 300));
        let code_at = b.len();
        b.extend_from_slice(b"CODEHERE");
        // banner anchor a bit past the code start
        let anchor = code_at + 4;
        assert_eq!(code_start_before(&b, anchor, 256), code_at);
        // no qualifying run -> 0
        let b2 = vec![7u8; 500];
        assert_eq!(code_start_before(&b2, 400, 256), 0);
    }

    #[test]
    fn entropy_wall_stops_before_high_entropy_tail() {
        // low-entropy code, then a high-entropy blob.
        let mut b = body(&RESETVEC, 0x30000);
        let mut x = 1u32;
        for _ in 0..0x30000 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            b.push((x >> 24) as u8);
        }
        let wall = entropy_wall(&b, 0).expect("wall found");
        assert!((0x30000 - 0x8000..=0x30000 + 0x8000).contains(&wall));
        // pure low-entropy: no wall.
        assert_eq!(entropy_wall(&body(&RESETVEC, 0x40000), 0), None);
    }

    #[test]
    fn end_by_blocks_spans_internal_gaps() {
        // content block, a 1-block internal zero gap, more content, then a >=8-block
        // sustained zero run: end must be after the SECOND content block.
        let mut b = body(&RESETVEC, BLOCK); // block 0 content
        b.extend(std::iter::repeat_n(0u8, BLOCK)); // internal gap (1 block)
        b.extend(body(&[1, 2, 3, 4], BLOCK)); // block 2 content
        let content_end = b.len();
        b.extend(std::iter::repeat_n(0u8, BLOCK * FILL_BLOCKS_END)); // sustained fill
        assert_eq!(end_by_blocks(&b, 0, false), content_end);
        // 0xFF gap only counts as fill when allow_ff.
        let mut c = body(&RESETVEC, BLOCK);
        c.extend(std::iter::repeat_n(0xffu8, BLOCK * FILL_BLOCKS_END));
        assert_eq!(end_by_blocks(&c, 0, true), BLOCK);
        // without allow_ff the 0xFF run is treated as content, not an end.
        assert!(end_by_blocks(&c, 0, false) > BLOCK);
    }

    #[test]
    fn carve_resetvec_success_and_truncation() {
        let img = body(&RESETVEC, 0x80000);
        let blob = wrap(0x1000, &img, 0x2000);
        let (fw, tag) = carve(&blob).expect("carved");
        assert_eq!(tag, "xflash-8051-resetvec");
        assert_eq!(&fw[..8], &RESETVEC);
        assert_eq!(fw.len(), img.len());
    }

    #[test]
    fn carve_vec_c295_requires_full_record() {
        // full mirrored record: byte[start+7] == 0x22 -> carve.
        let head = [0xc2, 0x95, 0xc2, 0x96, 0x02, 0x28, 0x00, 0x22];
        let img = body(&head, 0x80000);
        let blob = wrap(0x1000, &img, BLOCK * FILL_BLOCKS_END);
        let (fw, tag) = carve(&blob).expect("carved");
        assert_eq!(tag, "xflash-8051-vectable");
        assert_eq!(&fw[..5], &head[..5]);
        // same signature but byte[start+7] != 0x22 -> this family must NOT match.
        let bad_head = [0xc2, 0x95, 0xc2, 0x96, 0x02, 0x28, 0x00, 0x00];
        let bad = wrap(0x1000, &body(&bad_head, 0x80000), BLOCK * FILL_BLOCKS_END);
        assert!(carve(&bad).map(|(_, t)| t) != Some("xflash-8051-vectable"));
    }

    #[test]
    fn carve_benq_signature() {
        const BENQ: [u8; 24] = [
            0x60, 0xf4, 0x67, 0x76, 0x80, 0x0a, 0x68, 0x76, 0x70, 0xf3, 0x67, 0x76, 0x10, 0x48,
            0x68, 0x76, 0x70, 0x04, 0x68, 0x76, 0x60, 0xf5, 0x67, 0x76,
        ];
        let img = body(&BENQ, 0x43000);
        let blob = wrap(0x8000, &img, BLOCK * FILL_BLOCKS_END);
        let (fw, tag) = carve(&blob).expect("carved");
        assert_eq!(tag, "xflash-benq-vector");
        assert_eq!(&fw[..24], &BENQ);
    }

    #[test]
    fn carve_sony_banner_anchored() {
        // [pad zeros][8051 head + banner body][pad]
        let mut img = body(&[0x02, 0x10, 0x03, 0xc2, 0xaf, 0x02, 0x10, 0x30], 0x1000);
        img.extend_from_slice(b"SONY    DVD RW DRU-710A BY01 Aug06 ,2004");
        img.extend(body(&[5, 6, 7, 8], 0x40000));
        let blob = wrap(0x2000, &img, 0x2000);
        let (fw, tag) = carve(&blob).expect("carved");
        assert_eq!(tag, "xflash-sony");
        assert_eq!(fw[0], 0x02);
    }

    #[test]
    fn carve_plextor_requires_banner() {
        // vector-table head + PLEXTOR banner in the image -> carve.
        let mut img = body(&[0x02, 0x0f, 0x47, 0x02, 0x09, 0x4c], 0x20000);
        img.extend_from_slice(b"PLEXTOR DVD-ROM PX-130A 1.02");
        img.extend(body(&[3, 4, 5, 6], 0x2000));
        let blob = wrap(0x100, &img, BLOCK * FILL_BLOCKS_END);
        let (_fw, tag) = carve(&blob).expect("carved");
        assert_eq!(tag, "xflash-plextor-vectable");
        // identical vector layout WITHOUT the PLEXTOR banner must NOT be carved by
        // this family (the banner gate prevents generic false-matches).
        let noban = wrap(
            0x100,
            &body(&[0x02, 0x0f, 0x47, 0x02, 0x09, 0x4c], 0x20000),
            BLOCK,
        );
        assert!(carve(&noban).map(|(_, t)| t) != Some("xflash-plextor-vectable"));
    }

    #[test]
    fn carve_none_on_empty_or_garbage() {
        assert!(carve(&[]).is_none());
        assert!(carve(&[0u8; 16]).is_none());
        assert!(carve(&vec![0x99u8; 0x50000]).is_none());
        // signature present but resulting image too small to accept -> None.
        let tiny = wrap(0x10, &body(&RESETVEC, 0x1000), 0x2000);
        assert!(carve(&tiny).is_none());
    }
}
