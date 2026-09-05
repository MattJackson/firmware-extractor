//! decode_container(): yields raw + any in-memory decoded views
//! (word-swapped zip / zip / gzip / bz2).

use std::io::{Cursor, Read};

/// Upper bound on any single decompressed member / reconstructed buffer. Optical
/// drive firmware and its installers are at most a few MB; this generous 256 MiB
/// cap lets every real input through while preventing a decompression bomb or a
/// crafted archive header from driving an unbounded allocation (OOM/DoS).
const MAX_DECODE: u64 = 256 * 1024 * 1024;

/// Read at most `MAX_DECODE + 1` bytes from `r`; returns the buffer only if it did
/// not exceed the cap (an over-cap stream is dropped rather than materialized).
fn read_capped<R: Read>(r: R) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(MAX_DECODE + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_DECODE {
        return None;
    }
    Some(buf)
}

/// Decode any container wrapping `raw`.
///
/// Always returns `raw` as the first element, followed by any in-memory
/// container decodes (word-swapped zip, plain zip, gzip, bz2). Any decode error
/// is skipped (never panics).
pub fn decode_container(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    out.push(raw.to_vec());

    let h = &raw[..raw.len().min(4)];

    if h.len() >= 2 && &h[..2] == b"KP" {
        // LG/Asus word-swapped zip: swap every adjacent 2-byte pair.
        // For odd-length input the final byte is left as 0 (never assigned).
        let mut sw = vec![0u8; raw.len()];
        let mut i = 0;
        while i + 1 < raw.len() {
            sw[i] = raw[i + 1];
            sw[i + 1] = raw[i];
            i += 2;
        }
        out.extend(unzip(&sw));
    } else if h.len() >= 2 && &h[..2] == b"PK" {
        out.extend(unzip(raw));
    } else if h.len() >= 2 && &h[..2] == b"\x1f\x8b" {
        if let Some(d) = gunzip(raw) {
            out.push(d);
        }
    } else if h.len() >= 3 && &h[..3] == b"BZh" {
        if let Some(d) = bunzip2(raw) {
            out.push(d);
        }
    }

    // OEM signed-update container. Unlike the archive forms above it carries no
    // leading magic byte (its first word is a big-endian payload length), so it is
    // recognised structurally and attempted independently of the magic dispatch.
    if let Some(payload) = unwrap_signed_update(raw) {
        out.push(payload);
    }

    out
}

/// Recognise the OEM signed-update container and return its inner payload.
///
/// Layout (all multi-byte fields big-endian):
///   `[u32 payload_len][payload_len bytes payload][u16 sig_len][sig_len bytes sig]`
///
/// The trailing signature is a DER-encoded ECDSA-P256 value, so it begins with the
/// ASN.1 SEQUENCE tag `0x30`. The frame is accepted only when the three lengths
/// exactly partition the blob *and* that tag is present — specific enough that a
/// raw firmware image (which would need a plausible BE length in its first word and
/// a `0x30` at precisely the implied offset) is not mistaken for one.
///
/// Returns the inner payload so a downstream consumer (modify / `score_fw`) sees the
/// raw image rather than the framed wrapper.
/// True when `raw` is an OEM signed-update container (see [`unwrap_signed_update`]).
///
/// Used by candidate selection to treat the framed blob as a *wrapper* — like an MZ
/// or zip — so the unwrapped payload view is preferred over the larger raw frame.
pub fn is_signed_update_container(raw: &[u8]) -> bool {
    unwrap_signed_update(raw).is_some()
}

fn unwrap_signed_update(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 7 {
        return None;
    }
    let payload_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    // header (4) + payload + the 2-byte sig-length field must all fit within the blob.
    let sig_len_at = 4usize.checked_add(payload_len)?;
    let sig_at = sig_len_at.checked_add(2)?;
    if sig_at >= raw.len() {
        return None;
    }
    let sig_len = u16::from_be_bytes([raw[sig_len_at], raw[sig_len_at + 1]]) as usize;
    // The three regions (header+payload, sig-length, signature) must exactly cover it.
    if sig_at.checked_add(sig_len)? != raw.len() {
        return None;
    }
    // DER SEQUENCE tag marks the start of the ECDSA signature.
    if raw.get(sig_at) != Some(&0x30) {
        return None;
    }
    Some(raw[4..sig_len_at].to_vec())
}

/// Open `blob` as a zip, read each member in central-directory order, skipping
/// members that error. Returns empty if the blob isn't a valid zip.
///
/// The `zip` crate iterates by index in central-directory order.
///
/// A zip whose recorded central-directory offset does not match its actual
/// position in the blob still needs to decode: the correct adjustment is
/// `actual_cd_pos - recorded_cd_offset`, applied to every header offset. That is
/// exactly what happens with an overlay/appended zip carved out of a larger file
/// (e.g. a PE overlay) — the stored offsets still reference the ORIGINAL file, so
/// the recorded CD offset is LARGER than the carved blob. The `zip` crate only
/// handles the opposite sign (prepended junk moves the CD forward) and rejects
/// this with "Invalid CDFH offset in EOCD". We detect that case and prepend the
/// missing bytes so the recorded offsets line up, then re-open — the crate's
/// normal offset detection then resolves it.
fn unzip(blob: &[u8]) -> Vec<Vec<u8>> {
    if let Some(m) = unzip_reader(blob) {
        return m;
    }
    if let Some(padded) = concat_corrected(blob) {
        if let Some(m) = unzip_reader(&padded) {
            return m;
        }
    }
    Vec::new()
}

/// Open `blob` as a zip and read every member in central-directory order. Returns
/// `None` only if the archive header itself cannot be parsed (a non-zip);
/// individual member read errors are skipped.
fn unzip_reader(blob: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(blob)).ok()?;
    let mut members: Vec<Vec<u8>> = Vec::new();
    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        // Cap each member to guard against a zip decompression bomb.
        if let Some(buf) = read_capped(&mut file) {
            members.push(buf);
        }
    }
    Some(members)
}

/// If `blob` is an overlay/appended zip whose recorded central-directory offset is
/// past the end of the blob (offsets reference a larger original file), return a
/// copy prefixed with the missing bytes so the recorded offsets become correct.
/// Returns `None` when no such correction applies (leaving the normal path).
fn concat_corrected(blob: &[u8]) -> Option<Vec<u8>> {
    // Locate the End Of Central Directory record (PK\x05\x06), scanning from the
    // end of the blob backward.
    let eocd = blob.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    // EOCD is 22 bytes: ... cd_size @ +12 (u32), cd_offset @ +16 (u32).
    let rec = blob.get(eocd..eocd + 22)?;
    let cd_size = u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]) as usize;
    let cd_offset = u32::from_le_bytes([rec[16], rec[17], rec[18], rec[19]]) as usize;
    // Actual position of the central directory within this blob.
    let actual_cd = eocd.checked_sub(cd_size)?;
    // Only the "recorded offset too large" (carved-from-larger) case needs fixing;
    // the crate already handles recorded <= actual (prepended junk).
    let prepend = cd_offset.checked_sub(actual_cd)?;
    // `cd_offset` is an attacker-controlled 32-bit field; reject an implausible
    // prepend rather than allocate up to ~4 GiB from a crafted EOCD record.
    if prepend == 0 || prepend as u64 > MAX_DECODE {
        return None;
    }
    let mut padded = vec![0u8; prepend];
    padded.extend_from_slice(blob);
    Some(padded)
}

fn gunzip(raw: &[u8]) -> Option<Vec<u8>> {
    // Capped to guard against a gzip bomb (tiny input -> many GB).
    read_capped(flate2::read::GzDecoder::new(Cursor::new(raw)))
}

fn bunzip2(raw: &[u8]) -> Option<Vec<u8>> {
    // Capped to guard against a bzip2 bomb.
    read_capped(bzip2::read::BzDecoder::new(Cursor::new(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zw.start_file(name, opts).unwrap();
            zw.write_all(data).unwrap();
            zw.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn word_swap(bytes: &[u8]) -> Vec<u8> {
        let mut sw = vec![0u8; bytes.len()];
        let mut i = 0;
        while i + 1 < bytes.len() {
            sw[i] = bytes[i + 1];
            sw[i + 1] = bytes[i];
            i += 2;
        }
        sw
    }

    #[test]
    fn raw_always_first() {
        let raw = b"hello world, not a container";
        let got = decode_container(raw);
        assert_eq!(got[0], raw.to_vec());
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn plain_zip_yields_member() {
        let inner = b"INNER-FIRMWARE-PAYLOAD";
        let zip_bytes = make_zip("fw.bin", inner);
        assert_eq!(&zip_bytes[..2], b"PK");
        let got = decode_container(&zip_bytes);
        assert_eq!(got[0], zip_bytes);
        assert!(got.iter().any(|m| m == inner));
    }

    #[test]
    fn word_swapped_zip_yields_member() {
        let inner = b"INNER-FIRMWARE-PAYLOAD-SWAPPED";
        let zip_bytes = make_zip("fw.bin", inner);
        // Word-swapped zip starts with "PK" -> swapped to "KP".
        let swapped = word_swap(&zip_bytes);
        assert_eq!(&swapped[..2], b"KP");
        let got = decode_container(&swapped);
        assert_eq!(got[0], swapped);
        assert!(got.iter().any(|m| m == inner));
    }

    /// A zip carved out of a larger file (e.g. a PE overlay) keeps central-directory
    /// offsets that reference the ORIGINAL file, so the recorded CD offset is past the
    /// end of the carved blob. The bare `zip` crate rejects this ("Invalid CDFH offset
    /// in EOCD"); `concat_corrected` must recover it.
    fn patch_u32(buf: &mut [u8], at: usize, delta: u32) {
        let v = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        buf[at..at + 4].copy_from_slice(&v.wrapping_add(delta).to_le_bytes());
    }

    #[test]
    fn carved_overlay_zip_recovered_via_concat() {
        let inner = vec![0xABu8; 4096];
        let mut blob = make_zip("fw.bin", &inner);
        // Locate EOCD and shift every stored offset forward by K, simulating a zip
        // whose offsets reference a K-byte-larger original file.
        const K: u32 = 1000;
        let eocd = blob.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
        let cd_size = u32::from_le_bytes(blob[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
        let actual_cd = eocd - cd_size;
        // Patch each central-directory file header's local-header offset (+42).
        let mut p = actual_cd;
        while p + 4 <= eocd && &blob[p..p + 4] == b"PK\x01\x02" {
            patch_u32(&mut blob, p + 42, K);
            let name_len = u16::from_le_bytes([blob[p + 28], blob[p + 29]]) as usize;
            let extra_len = u16::from_le_bytes([blob[p + 30], blob[p + 31]]) as usize;
            let comment_len = u16::from_le_bytes([blob[p + 32], blob[p + 33]]) as usize;
            p += 46 + name_len + extra_len + comment_len;
        }
        // Patch the EOCD central-directory offset (+16).
        patch_u32(&mut blob, eocd + 16, K);

        // Bare open now fails; decode_container must still yield the member.
        assert!(zip::ZipArchive::new(Cursor::new(&blob)).is_err());
        let got = decode_container(&blob);
        assert_eq!(got[0], blob);
        assert!(
            got.iter().any(|m| m == &inner),
            "carved overlay member recovered"
        );
    }

    /// The OEM signed-update container carries no leading magic byte: its first word
    /// is a big-endian payload length, followed by the payload, a big-endian sig
    /// length, and a DER (`0x30`-tagged) ECDSA signature. `decode_container` must
    /// strip the frame and yield the inner payload so a downstream consumer sees the
    /// raw image, not the wrapper.
    #[test]
    fn signed_update_container_yields_payload() {
        let payload = vec![0x5Au8; 4096];
        let sig = {
            // A minimal DER-tagged blob standing in for the ECDSA signature.
            let mut s = vec![0x30u8, 0x44];
            s.extend(std::iter::repeat_n(0xEEu8, 0x44));
            s
        };
        let mut blob = Vec::new();
        blob.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        blob.extend_from_slice(&payload);
        blob.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        blob.extend_from_slice(&sig);

        let got = decode_container(&blob);
        assert_eq!(got[0], blob, "raw is always first");
        assert!(
            got.iter().any(|m| m == &payload),
            "inner payload recovered from signed-update frame"
        );
    }

    /// The structural recogniser must not fire on a raw image that merely happens to
    /// begin with a large-looking word: the three lengths will not exactly partition
    /// the blob, so no spurious payload view is emitted.
    #[test]
    fn signed_update_rejects_non_container() {
        let raw = vec![0xFFu8; 8192]; // first word 0xFFFFFFFF -> lengths cannot partition.
        let got = decode_container(&raw);
        assert_eq!(got.len(), 1, "only raw, no spurious signed-update view");
    }

    #[test]
    fn multiple_members_preserve_order() {
        // Build a zip with two members; assert namelist (central-dir) order.
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zw.start_file("a.bin", opts).unwrap();
            zw.write_all(b"AAA").unwrap();
            zw.start_file("b.bin", opts).unwrap();
            zw.write_all(b"BBB").unwrap();
            zw.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();
        let got = decode_container(&zip_bytes);
        // got[0] is raw; members follow in order.
        assert_eq!(got[1], b"AAA".to_vec());
        assert_eq!(got[2], b"BBB".to_vec());
    }
}
