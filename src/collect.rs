//! collect_candidates() + emit(): recursive candidate gathering.
//!
//! Candidates are gathered in this order:
//!   1. the file itself + its in-memory container decodes (`emit`)
//!   2. the PE overlay (bytes appended after the image), if >= 4096
//!   3. every PE resource data entry, decoded
//!   4. on-disk unpack members (archives / SFX / installers), recursing one level
//!      into nested archives/PE, else emitted (with their own container decodes)
//!
//! Depth is limited to `max_depth = 3` (start depth 0).

use crate::archive::{magic_kind, unique_temp_dir, unpack_to};
use crate::container::decode_container;
use crate::pe::{pe_overlay, pe_resources};
use crate::Candidate;
use std::path::Path;

/// Gather candidate firmware blobs from `path` (recursive, depth-limited).
///
/// `root_bytes` lets the caller pass the top-level file contents it has already
/// read, so the whole input is not read into memory twice (the caller needs the
/// raw bytes for its own magic checks). Pass `None` to have this read `path`.
pub fn collect_candidates(path: &Path, root_bytes: Option<Vec<u8>>) -> Vec<Candidate> {
    let mut out = Vec::new();
    collect_inner(path, root_bytes, 0, 3, &mut out);
    out
}

/// Push `raw` itself plus every in-memory container decode (>= 256 bytes) as
/// `name::decoded`.
///
/// `decode_container` always returns `raw` as element 0; every later element is a
/// decode.
fn emit(out: &mut Vec<Candidate>, name: &str, raw: &[u8]) {
    for (i, blob) in decode_container(raw).into_iter().enumerate() {
        if i == 0 {
            out.push(Candidate {
                name: name.to_string(),
                data: blob,
            });
        } else if blob.len() >= 256 {
            out.push(Candidate {
                name: format!("{name}::decoded"),
                data: blob,
            });
        }
    }
}

fn collect_inner(
    path: &Path,
    root_bytes: Option<Vec<u8>>,
    depth: u32,
    max_depth: u32,
    out: &mut Vec<Candidate>,
) {
    // Reuse caller-provided bytes for the top level (moved in, no extra copy);
    // otherwise read the file.
    let raw = match root_bytes {
        Some(b) => b,
        None => match std::fs::read(path) {
            Ok(r) => r,
            Err(_) => return,
        },
    };
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // 1) the file itself / its in-memory container decodes
    emit(out, &base, &raw);

    // 2) PE overlay (firmware appended after the image)
    let ov = pe_overlay(&raw);
    if ov.len() >= 4096 {
        emit(out, &format!("{base}::overlay"), &ov);
    }

    // 2b) PE resources (LG/Asus/BenQ store firmware as an RCDATA word-swapped zip)
    let mut big_rsrc = false;
    for (i, (_, blob)) in pe_resources(&raw).into_iter().enumerate() {
        if blob.len() >= 65536 {
            big_rsrc = true;
        }
        emit(out, &format!("{base}::rsrc{i}"), &blob);
    }

    // 3) on-disk unpack (archives / SFX / installers), recurse one level.
    // 7z/unar are FAST and handle self-extracting installers whose payload is in an
    // overlay/appended archive — e.g. HP SoftPaq (SCG) SFX -> setup.exe -> the LG
    // word-swapped-zip firmware. So they always run for archive/PE inputs. Only the
    // slow, sometimes-hanging binwalk carve is gated: skipped when the PE resource
    // walk already found something sizable (LG/Asus/BenQ firmware in RCDATA), which
    // is what made binwalk-on-every-file the bottleneck.
    let top_kind = magic_kind(&raw[..raw.len().min(8)]);
    let allow_binwalk = !big_rsrc;
    if depth < max_depth && matches!(top_kind, "archive" | "pe") {
        for (fname, bytes) in unpack_to(path, allow_binwalk) {
            if bytes.len() < 256 {
                continue;
            }
            let head = &bytes[..bytes.len().min(8)];
            match magic_kind(head) {
                "archive" | "pe" => {
                    // Recurse: write the member to a temp file named `fname` so the
                    // recursive call derives `base` from that basename.
                    if let Some(tmp) = unique_temp_dir("fwext-member") {
                        let fp = tmp.join(&fname);
                        if std::fs::write(&fp, &bytes).is_ok() {
                            collect_inner(&fp, None, depth + 1, max_depth, out);
                        }
                        let _ = std::fs::remove_dir_all(&tmp);
                    }
                }
                _ => emit(out, &fname, &bytes),
            }
        }
    }
}
