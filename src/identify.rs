//! `is_xflash_packed()` — detect the MediaTek XFlash runtime packer.
//!
//! Magic-byte format sniffing for the extraction pipeline lives in
//! `archive::magic_kind` (used by `collect`); this module only carries the
//! af7df9fd packer probe, which is a whole-file scan rather than a head sniff.

/// af7df9fd MediaTek XFlash runtime packer anywhere in an MZ. Tolerates a little
/// leading junk before MZ (some vendor PHP endpoints prepend a stray byte).
pub fn is_xflash_packed(raw: &[u8]) -> bool {
    let has_mz = raw.len() >= 2 && raw[..raw.len().min(16)].windows(2).any(|w| w == b"MZ");
    has_mz && raw.windows(4).any(|w| w == [0xaf, 0x7d, 0xf9, 0xfd])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_packer_in_mz() {
        // MZ head then the af7df9fd marker later in the buffer -> packed.
        let mut d = vec![b'M', b'Z'];
        d.extend_from_slice(&[0u8; 64]);
        d.extend_from_slice(&[0xaf, 0x7d, 0xf9, 0xfd]);
        assert!(is_xflash_packed(&d));
    }

    #[test]
    fn tolerates_leading_junk_before_mz() {
        // A stray byte before MZ (still within the 16-byte window) is tolerated.
        let mut d = vec![0x20u8];
        d.extend_from_slice(b"MZ");
        d.extend_from_slice(&[0u8; 64]);
        d.extend_from_slice(&[0xaf, 0x7d, 0xf9, 0xfd]);
        assert!(is_xflash_packed(&d));
    }

    #[test]
    fn requires_both_mz_and_marker() {
        // marker but no MZ in the first 16 bytes -> not flagged.
        let mut no_mz = vec![0u8; 64];
        no_mz.extend_from_slice(&[0xaf, 0x7d, 0xf9, 0xfd]);
        assert!(!is_xflash_packed(&no_mz));
        // MZ but no marker -> not flagged.
        let mut no_marker = vec![b'M', b'Z'];
        no_marker.extend_from_slice(&[0u8; 128]);
        assert!(!is_xflash_packed(&no_marker));
        // MZ present but only past the 16-byte window -> not flagged.
        let mut mz_late = vec![0xabu8; 16];
        mz_late.extend_from_slice(b"MZ");
        mz_late.extend_from_slice(&[0xaf, 0x7d, 0xf9, 0xfd]);
        assert!(!is_xflash_packed(&mz_late));
    }

    #[test]
    fn no_panic_on_tiny_input() {
        assert!(!is_xflash_packed(&[]));
        assert!(!is_xflash_packed(b"M"));
        assert!(!is_xflash_packed(b"MZ"));
    }
}
