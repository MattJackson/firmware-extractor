//! `extract()` + `label()`: the orchestration that decides which firmware image to
//! carve from an input and how to label it.
//!
//! The pipeline, in order:
//!   1. sibling `.unpacked.bin` (runtime/dynamic unpack artifact) -> label from it.
//!   2. first 64 KiB is a MediaTek XFlash `af7df9fd` packer -> needs the oracle.
//!   3. MZ-but-not-PE (16-bit DOS flasher) -> firmware embedded, no clean carve.
//!   4. collect candidates, score, drop score<=0, sort descending (stable).
//!   5. prefer non-wrapper (MZ/PK/KP) candidates; else keep all.
//!   6. nothing left -> no-firmware-found.
//!   7. label the top candidate.
//!   8. packed-wrapper or MZ best -> needs live unpack; else emit the bytes.
//!
//! The extracted firmware bytes (identified by sha256) are the primary output.
//! The `Label` struct carries only the fields that describe those bytes; other
//! descriptive metadata is intentionally omitted as it does not affect the
//! extracted image.

use crate::Label;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The basename of `path` — the component after the final path separator.
fn basename(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The path with its final extension removed.
///
/// The last dot in the final path component is the split point, but leading dots
/// (dotfiles) are not treated as extensions.
fn splitext_root(path: &Path) -> String {
    let s = path.to_string_lossy().into_owned();
    let sep = s.rfind('/');
    let base_start = sep.map(|i| i + 1).unwrap_or(0);
    if let Some(dot_rel) = s[base_start..].rfind('.') {
        let dot_abs = base_start + dot_rel;
        // Only an extension if some char before the dot (within the basename)
        // is not itself a dot — i.e. skip pure leading-dot names.
        if s[base_start..dot_abs].chars().any(|c| c != '.') {
            return s[..dot_abs].to_string();
        }
    }
    s
}

/// Return an already-unpacked flasher artifact sitting next to `path`, if one
/// exists.
fn sibling_unpacked(path: &Path) -> Option<PathBuf> {
    let stem = splitext_root(path);
    let cand1 = PathBuf::from(format!("{stem}.unpacked.bin"));
    let cand2 = PathBuf::from(format!("{}.unpacked.bin", path.to_string_lossy()));
    [cand1, cand2].into_iter().find(|c| c.is_file())
}

/// Read up to `n` bytes from the head of `path`. An unreadable file yields an
/// empty buffer.
fn read_head(path: &Path, n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        // `take` reads at most `n` bytes.
        let _ = f.take(n as u64).read_to_end(&mut buf);
    }
    buf
}

/// Build the `Label` for firmware `blob` named `name`.
///
/// Only the fields present on `crate::Label` are populated. Purely descriptive
/// metadata (a vendor-container string dump, and the cosmetic `BRAND_RECIPE`
/// lookup's `flash_write_opcode` / `controller_family` when a brand is known) has
/// no field on the struct and is skipped — none of it affects the extracted
/// firmware bytes.
fn label(name: &str, blob: &[u8], brand: Option<&str>, model: Option<&str>) -> Label {
    let (chip, conf, ev, banner) = crate::chipset::detect_chipset(blob);
    let (encrypted, entropy, payload_form) = crate::encryption::classify_encryption(blob);

    let mut lab = Label {
        name: Some(name.to_string()),
        size: Some(blob.len()),
        sha256: Some(crate::sha(blob)),
        chipset: chip,
        // Fall back to "live-only" when no static confidence is known.
        chipset_confidence: Some(conf.unwrap_or_else(|| "live-only".to_string())),
        chipset_evidence: ev,
        boot_banner: banner,
        encrypted,
        entropy: Some(entropy),
        payload_form: Some(payload_form),
        ..Default::default()
    };

    if let Some(recipe) = crate::recipe::detect_flash_recipe(blob) {
        lab.flash_recipe = Some(recipe);
    }
    if let Some(brand) = brand {
        lab.brand = Some(brand.to_string());
        // BRAND_RECIPE -> flash_write_opcode / controller_family: no Label fields, skipped.
    }
    if let Some(model) = model {
        lab.model = Some(model.to_string());
    }
    lab
}

/// Full pipeline: return `(best_fw_bytes or None, label)`.
pub fn extract(path: &Path, brand: Option<&str>, model: Option<&str>) -> (Option<Vec<u8>>, Label) {
    let original = basename(path);

    // 1) An unpacked flasher sibling (.unpacked.bin) exists. Some flashers store the
    //    firmware plaintext inside, headed by the signature `[\x1a\x1b]<4-char ver>
    //    \xff{7}` (LiteOn/MediaTek); carve it by that signature (never by offset).
    //    If found, that IS the final firmware. Otherwise the image is transformed
    //    inside the flasher — label from the flasher and flag unconfirmed.
    if let Some(sib) = sibling_unpacked(path) {
        let blob = std::fs::read(&sib).unwrap_or_default();
        // 1a) The flasher stores the firmware inside. crate::xflash::carve dispatches
        //     by family SIGNATURE (verbatim distribution-image header, or the raw
        //     plaintext 8051 body: LiteOn/Plextor reset-vector, TDK/Sony vector-table,
        //     BenQ vector, Sony/ATAPI banner) — all signature-based, no offsets. The
        //     matched family tag is recorded in the note.
        if let Some((fw, note)) = carve_or_unpack(&blob) {
            let mut lab = label("flasher-firmware", &fw, brand, model);
            lab.status = Some("extracted".to_string());
            lab.confidence = Some(assess_confidence(&lab).to_string());
            lab.note = Some(note);
            lab.unpacked_path = Some(sib.to_string_lossy().into_owned());
            lab.original = Some(original);
            return (Some(fw), lab);
        }
        // 1b) OPAQUE type: firmware present but no offline-recognized boundary yet
        //     (a newer/compressed sub-family). Label from the flasher and flag for
        //     per-family signature work.
        let mut lab = label(&basename(&sib), &blob, brand, model);
        lab.status = Some("xflash-unpacked".to_string());
        lab.confidence = Some("unconfirmed".to_string());
        lab.note = Some(
            "xflash-opaque: plaintext firmware embedded but no offline carve signature for this family yet".to_string(),
        );
        lab.unpacked_path = Some(sib.to_string_lossy().into_owned());
        lab.original = Some(original);
        return (None, lab);
    }

    // 2) MediaTek XFlash self-extractor (af7df9fd packer within the first 64 KiB):
    //    unpack it OFFLINE (af7::unpack) and carve the firmware from the result. Only
    //    if the offline unpack fails does it fall through to the oracle flag below.
    let raw0 = read_head(path, 1 << 16);
    if crate::identify::is_xflash_packed(&raw0) {
        let full = std::fs::read(path).unwrap_or_default();
        if let Some((fw, note)) = carve_or_unpack(&full) {
            let mut lab = label("flasher-firmware", &fw, brand, model);
            lab.status = Some("extracted".to_string());
            lab.confidence = Some(assess_confidence(&lab).to_string());
            lab.note = Some(note);
            lab.original = Some(original);
            return (Some(fw), lab);
        }
        return (
            None,
            Label {
                status: Some("xflash-packed-needs-oracle".to_string()),
                confidence: Some("none".to_string()),
                note: Some(
                    "MediaTek XFlash af7df9fd packer; offline unpack did not yield a carveable image"
                        .to_string(),
                ),
                original: Some(original),
                ..Default::default()
            },
        );
    }

    // 3) 16-bit DOS flasher (MZ but no PE header): firmware is embedded in a
    //    real-mode binary with no clean carve boundary. Deterministically flag.
    let rawf = std::fs::read(path).unwrap_or_default();
    if rawf.len() >= 2 && &rawf[..2] == b"MZ" {
        let e = if rawf.len() >= 0x40 {
            u32::from_le_bytes([rawf[0x3c], rawf[0x3d], rawf[0x3e], rawf[0x3f]]) as usize
        } else {
            0
        };
        // is_pe: e_lfanew points at the PE signature. `rawf.get(e..e+4)` is
        // self-bounding (returns None past EOF), so a PE whose signature sits
        // exactly at end-of-file is still recognized (no off-by-one on the bound).
        let is_pe = e > 0 && rawf.get(e..e + 4) == Some(b"PE\0\0");
        if !is_pe {
            return (
                None,
                Label {
                    status: Some("legacy-dos-flasher-embedded".to_string()),
                    confidence: Some("none".to_string()),
                    note: Some(
                        "16-bit DOS flasher; firmware embedded in raw (no clean carve)".to_string(),
                    ),
                    original: Some(original),
                    ..Default::default()
                },
            );
        }
    }

    // 4) Gather candidates, score, drop score<=0. Deterministic TOTAL order so ties
    //    resolve identically regardless of archive walk order (FS order is
    //    nondeterministic): score desc, then size desc, then name asc. This total
    //    order makes multi-candidate installers resolve identically every run.
    // Move the already-read top-level bytes into collect so the input file is not
    // read (or held) twice; collect emits `rawf` back as candidate 0.
    let cands = crate::collect::collect_candidates(path, Some(rawf));

    // 4a) XFlash plaintext carve over every candidate. A packed download (zip/UPX)
    //     unwraps — via collect's 7z/upx pass — to an XFlash flasher whose firmware
    //     is plaintext once unpacked; carve it by the same family signatures used
    //     for the .unpacked.bin siblings. Candidate 0 is the raw file itself, so
    //     this also covers an XFlash image sitting directly in the download. This is
    //     what makes packed XFlash downloads resolve offline (no oracle unpack).
    for blob in cands.iter().map(|c| &c.data) {
        if let Some((fw, note)) = carve_or_unpack(blob) {
            let mut lab = label("flasher-firmware", &fw, brand, model);
            lab.status = Some("extracted".to_string());
            lab.confidence = Some(assess_confidence(&lab).to_string());
            lab.note = Some(note);
            lab.original = Some(original);
            return (Some(fw), lab);
        }
    }

    let mut scored: Vec<(i64, String, Vec<u8>)> = cands
        .into_iter()
        .map(|c| (crate::score::score_fw(&c.name, &c.data), c.name, c.data))
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.2.len().cmp(&a.2.len()))
            .then_with(|| a.1.cmp(&b.1))
    });
    scored.retain(|t| t.0 > 0);

    // 5) An optical-drive firmware image is never a Windows PE. A still-MZ (or
    //    undecoded container) candidate is a flasher/wrapper, not the image.
    //    Prefer real images; fall back to the wrapper only to drive the
    //    packed/legacy classification below. Partition by MOVE (no clone) — the
    //    surviving blobs can be multi-MB each.
    let (real, wrappers): (Vec<_>, Vec<_>) = scored.into_iter().partition(|t| !is_wrapper(&t.2));
    let scored = if !real.is_empty() { real } else { wrappers };

    // 6) Nothing survived: opaque/packed installer.
    if scored.is_empty() {
        return (
            None,
            Label {
                status: Some("no-firmware-found".to_string()),
                confidence: Some("none".to_string()),
                note: Some("installer opaque/packed; needs live unpack".to_string()),
                original: Some(original),
                ..Default::default()
            },
        );
    }

    // 7) Label the top candidate. Move the winning tuple out of `scored` so the
    //    firmware bytes are never cloned.
    let mut scored = scored;
    let (_best_score, best_name, best_blob) = scored.swap_remove(0);
    let mut lab = label(&best_name, &best_blob, brand, model);
    lab.original = Some(original);

    // 8) A self-extracting/packed flasher (XFlash aPLib, MZ, etc.) is NOT a firmware
    //    image — the real image only decompresses at runtime. Also reject any
    //    remaining wrapper (an MZ/PE, or a PK/KP zip that decode_container could not
    //    decode — e.g. an AES-encrypted or unsupported-method entry): step 5 filters
    //    wrappers out only when a non-wrapper candidate exists, so a sole undecodable
    //    wrapper reaches here and must be flagged, never emitted as "confident".
    if lab.payload_form.as_deref() == Some("packed-wrapper") || is_wrapper(&best_blob) {
        lab.status = Some("packed-flasher-needs-live-unpack".to_string());
        lab.confidence = Some("none".to_string());
        return (None, lab);
    }
    lab.status = Some("extracted".to_string());
    lab.confidence = Some(assess_confidence(&lab).to_string());
    (Some(best_blob), lab)
}

/// Extract firmware from a flasher blob, transparently handling the af7df9fd
/// packer. First try a direct XFlash carve (already-unpacked flasher / plaintext
/// image); if that fails and the blob is af7df9fd-packed, decompress it offline
/// (`af7::unpack`) and carve the result. Returns `(firmware, note)` describing the
/// path taken, or `None` if neither yields a carveable image.
fn carve_or_unpack(blob: &[u8]) -> Option<(Vec<u8>, String)> {
    if let Some((fw, family)) = crate::xflash::carve(blob) {
        return Some((fw, format!("{family}: firmware carved by signature")));
    }
    if let Some(unpacked) = crate::af7::unpack(blob) {
        if let Some((fw, family)) = crate::xflash::carve(&unpacked) {
            return Some((
                fw,
                format!("af7df9fd unpacked offline, then {family}: firmware carved by signature"),
            ));
        }
    }
    None
}

/// Self-signoff on whether the emitted bytes are THE final firmware image. Used to
/// drive the debug + reprocess loop: anything not "confident"/"confident-encrypted"
/// is a candidate to re-run after a tool fix.
fn assess_confidence(lab: &Label) -> &'static str {
    // A readable chipset part or boot banner means we decoded a real image.
    if lab.chipset.is_some() || lab.boot_banner.is_some() {
        return "confident";
    }
    match lab.payload_form.as_deref() {
        // A plausible plaintext / microcode image — the firmware, just no stamped part.
        Some("plaintext") | Some("code-or-mixed") => "confident",
        // High-entropy opaque bytes that resisted every decoder: a valid final image
        // that is encrypted at rest (chipset unreadable) — still THE firmware.
        Some("encrypted-opaque") => "confident-encrypted",
        // We only got a wrapper/container that did not fully decode: not the final
        // bin — flag for debug + reprocess.
        _ => "unconfirmed",
    }
}

/// True when `blob` is a wrapper rather than a firmware image: an MZ (PE), a
/// plain zip (`PK\x03\x04`), or a word-swapped zip (`KP\x04\x03`).
fn is_wrapper(blob: &[u8]) -> bool {
    (blob.len() >= 2 && &blob[..2] == b"MZ")
        || (blob.len() >= 2 && &blob[..2] == b"PK")
        || (blob.len() >= 4 && blob[..4] == [0x4b, 0x50, 0x04, 0x03])
        // OEM signed-update frame: prefer its unwrapped payload over the raw frame.
        || crate::container::is_signed_update_container(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write `bytes` to a uniquely named temp file and return its path.
    fn tmp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "fwext_extract_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(uniq);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    #[test]
    fn legacy_dos_flasher_mz_without_pe() {
        // MZ header, e_lfanew (0x3c) points nowhere valid -> not a PE -> DOS flag.
        let mut d = vec![0u8; 0x80];
        d[0] = b'M';
        d[1] = b'Z';
        // e_lfanew = 0 (default) -> is_pe false.
        let p = tmp_file("dos", &d);
        let (fw, lab) = extract(&p, None, None);
        std::fs::remove_file(&p).ok();
        assert!(fw.is_none());
        assert_eq!(lab.status.as_deref(), Some("legacy-dos-flasher-embedded"));
        assert!(lab.original.is_some());
    }

    #[test]
    fn xflash_packed_needs_oracle() {
        // MZ + af7df9fd packer magic in the first 64 KiB -> oracle branch, which
        // is checked before the MZ/PE (DOS) branch.
        let mut d = vec![0u8; 0x100];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x40] = 0xaf;
        d[0x41] = 0x7d;
        d[0x42] = 0xf9;
        d[0x43] = 0xfd;
        let p = tmp_file("xflash", &d);
        let (fw, lab) = extract(&p, None, None);
        std::fs::remove_file(&p).ok();
        assert!(fw.is_none());
        assert_eq!(lab.status.as_deref(), Some("xflash-packed-needs-oracle"));
    }

    #[test]
    fn is_wrapper_detects_mz_pk_kp() {
        assert!(is_wrapper(b"MZabcd"));
        assert!(is_wrapper(b"PK\x03\x04rest"));
        assert!(is_wrapper(&[0x4b, 0x50, 0x04, 0x03, 0x00]));
        assert!(!is_wrapper(b"random firmware bytes"));
        assert!(!is_wrapper(b"M")); // too short
    }

    #[test]
    fn splitext_and_sibling_naming() {
        // splitext_root drops the final extension only.
        assert_eq!(splitext_root(Path::new("/a/b/foo.bin")), "/a/b/foo");
        assert_eq!(splitext_root(Path::new("/a/b/foo.tar.gz")), "/a/b/foo.tar");
        assert_eq!(splitext_root(Path::new("/a/b/noext")), "/a/b/noext");
        // Leading-dot files are not extensions.
        assert_eq!(splitext_root(Path::new("/a/b/.hidden")), "/a/b/.hidden");
    }

    #[test]
    fn sibling_unpacked_found_and_labeled() {
        // Create foo.bin and its foo.unpacked.bin sibling; extract must label
        // from the sibling and report status xflash-unpacked.
        let dir = std::env::temp_dir();
        let uniq = format!(
            "fwext_sib_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let main_path = dir.join(format!("{uniq}.bin"));
        let sib_path = dir.join(format!("{uniq}.unpacked.bin"));
        std::fs::write(&main_path, b"MZ dummy packed flasher body").unwrap();
        std::fs::write(&sib_path, vec![0u8; 4096]).unwrap();

        let (fw, lab) = extract(&main_path, Some("LG"), Some("GH24"));
        std::fs::remove_file(&main_path).ok();
        std::fs::remove_file(&sib_path).ok();

        assert!(fw.is_none());
        assert_eq!(lab.status.as_deref(), Some("xflash-unpacked"));
        assert_eq!(lab.brand.as_deref(), Some("LG"));
        assert_eq!(lab.model.as_deref(), Some("GH24"));
        assert!(lab.unpacked_path.is_some());
        assert_eq!(
            lab.original.as_deref(),
            Some(basename(&main_path)).as_deref()
        );
    }
}
