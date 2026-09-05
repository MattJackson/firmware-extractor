//! fwext — generic firmware extractor + labeler.
//!
//! `binary in -> raw firmware image out + JSON label`
//!
//! Point it at any vendor firmware download (installer .exe, archive, self-extractor,
//! or a raw image) and it emits exactly one canonical raw firmware `.bin` plus a JSON
//! label — or a status explaining why no clean image could be carved. Extraction is
//! signature-based (no hardcoded offsets), deterministic (same input -> same output),
//! and fully offline. Originally built for optical-drive firmware; the pipeline is
//! generic (PE resources/overlays, archives, container decodes, vendor packers).
//!
//! Module map:
//!   identify   — is_xflash_packed(): af7df9fd MediaTek XFlash packer probe
//!   af7        — unpack(): offline decompressor for the af7df9fd XFlash packer
//!   container  — decode_container(): word-swapped-zip (KP), zip (PK), gzip, bz2
//!   pe         — pe_overlay(), pe_resources()  (LG/Asus RCDATA firmware)
//!   archive    — unpack_to() + magic_kind(): 7z / unar / innoextract / binwalk
//!   collect    — collect_candidates(): recursive candidate gathering + normalization
//!   score      — score_fw(): pick THE firmware image; exclude MZ/container wrappers
//!   xflash     — carve(): plaintext-firmware carving from unpacked XFlash flashers
//!   chipset    — detect_chipset(): MT part + context, exact parts, boot banner
//!   encryption — classify_encryption(): Shannon-entropy payload_form
//!   recipe     — detect_flash_recipe(): transport / CDBs / MTK DIOC / chip profiles
//!   extract    — the pipeline: -> (Option<Vec<u8>>, Label)

pub mod af7;
pub mod archive;
pub mod chipset;
pub mod collect;
pub mod container;
pub mod encryption;
pub mod extract;
pub mod identify;
pub mod pe;
pub mod recipe;
pub mod score;
pub mod xflash;

use serde::Serialize;

/// A candidate firmware blob gathered from an input (self, decoded, resource, member).
#[derive(Clone)]
pub struct Candidate {
    pub name: String,
    pub data: Vec<u8>,
}

/// The JSON label emitted alongside the firmware.
#[derive(Serialize, Default, Clone)]
pub struct Label {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chipset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chipset_confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chipset_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_form: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flash_recipe: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Self-signoff on whether the emitted bytes are THE final firmware image:
    ///   "confident"           — real firmware (chipset/banner/vendor magic, or a
    ///                           plausible plaintext/code image): this IS the bin.
    ///   "confident-encrypted" — a valid final image that is encrypted at rest
    ///                           (opaque; chipset unreadable but it's the firmware).
    ///   "unconfirmed"         — extracted a blob but it still looks like a wrapper/
    ///                           container (compressed/packed) — likely NOT the final
    ///                           bin; flag for debug + reprocess.
    ///   "none"                — no firmware bytes emitted (see `status` for why).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpacked_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Shannon entropy over the given bytes.
pub fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &x in b {
        freq[x as usize] += 1;
    }
    let n = b.len() as f64;
    -freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Hex sha256 of the bytes.
pub fn sha(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform_single_byte_is_zero() {
        // All identical bytes carry no information.
        assert_eq!(entropy(&[0x41; 4096]), 0.0);
    }

    #[test]
    fn entropy_two_symbols_is_one_bit() {
        // Equal mix of two symbols = exactly 1 bit/byte.
        let mut b = vec![0u8; 2048];
        b.extend(std::iter::repeat_n(1u8, 2048));
        assert!((entropy(&b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_all_256_symbols_is_eight_bits() {
        // Each of the 256 byte values once = maximal 8 bits/byte.
        let b: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&b) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn sha_matches_known_vector() {
        // sha256("") — the canonical empty-input digest.
        assert_eq!(
            sha(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
