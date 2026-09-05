//! classify_encryption(): entropy bands -> payload_form + encrypted.
//! Returns (encrypted, entropy, payload_form).

use crate::container::decode_container;
use crate::entropy;

/// Packer / wrapper header magics (firmware is compressed/encrypted INSIDE).
/// The full wrapper set is `{MZ, af7df9fd, beedeffb}`; the `MZ` entry is checked
/// separately via `blob[:2]`, so this table holds the 4-byte magics only (tested
/// against `blob[:4]`).
const WRAP_MAGIC: [[u8; 4]; 2] = [[0xaf, 0x7d, 0xf9, 0xfd], [0xbe, 0xed, 0xef, 0xfb]];

const FOUR_MIB: usize = 4 * 1024 * 1024;

/// Round to 3 decimal places.
fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Classify a blob's encryption/compression state from entropy.
///
/// Returns `(encrypted, entropy_rounded_to_3, payload_form)`.
pub fn classify_encryption(blob: &[u8]) -> (Option<bool>, f64, String) {
    let mut best_h = 8.0_f64;
    // `best_c`: None == "raw" winner, Some("container") == a decoded view won.
    let mut best_c: Option<&'static str> = None;

    // Views to score: the "raw" pair, then every decoded container view EXCEPT
    // the first (which is `blob` itself).
    let decoded = decode_container(blob);
    let mut views: Vec<(&'static str, &[u8])> = Vec::with_capacity(decoded.len());
    views.push(("raw", blob));
    for x in decoded.iter().skip(1) {
        views.push(("c", x.as_slice()));
    }

    for (lbl, b) in views {
        if b.len() < 256 {
            continue;
        }
        let start = b.len() / 8;
        let end = (start + FOUR_MIB).min(b.len());
        // Sample the interior slice; fall back to the whole buffer if that
        // slice would be empty (it is non-empty for len>=256).
        let body: &[u8] = if start < end { &b[start..end] } else { b };
        let h = entropy(body);
        if h < best_h {
            best_h = h;
            best_c = if lbl == "raw" {
                None
            } else {
                Some("container")
            };
        }
    }

    let head = &blob[..blob.len().min(200000)];
    let wrapper = (blob.len() >= 2 && &blob[..2] == b"MZ")
        || (blob.len() >= 4 && WRAP_MAGIC.contains(&[blob[0], blob[1], blob[2], blob[3]]))
        || contains(head, b"Sysutils")
        || contains(head, b"AnsiString");

    if wrapper && best_c.is_none() && best_h >= 7.0 {
        return (None, round3(best_h), "packed-wrapper".to_string());
    }
    if best_h < 7.0 {
        return (Some(false), round3(best_h), "plaintext".to_string());
    }
    if best_h < 7.85 {
        return (Some(false), round3(best_h), "code-or-mixed".to_string());
    }
    if best_c.is_some() {
        return (
            Some(false),
            round3(best_h),
            "compressed-container".to_string(),
        );
    }
    (Some(true), round3(best_h), "encrypted-opaque".to_string())
}

/// Substring search over bytes: is `needle` present anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_blob_is_plaintext() {
        let blob = vec![0u8; 4096];
        let (encrypted, h, form) = classify_encryption(&blob);
        assert_eq!(encrypted, Some(false));
        assert_eq!(form, "plaintext");
        assert_eq!(h, 0.0);
    }

    #[test]
    fn random_high_entropy_blob_is_encrypted_opaque() {
        // Deterministic full-byte-range fill: every value 0..=255 repeated,
        // giving entropy 8.0 (max), no wrapper magic, no container decode.
        let mut blob = Vec::with_capacity(65536);
        for i in 0..65536usize {
            blob.push((i % 256) as u8);
        }
        // Ensure it does not accidentally start with a wrapper magic.
        assert_ne!(&blob[..2], b"MZ");
        let (encrypted, h, form) = classify_encryption(&blob);
        assert_eq!(encrypted, Some(true));
        assert_eq!(form, "encrypted-opaque");
        assert!(h >= 7.85, "entropy should be high, got {h}");
    }
}
