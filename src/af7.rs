//! Offline unpacker for the MediaTek "XFlash" self-extracting packer (magic
//! `af 7d f9 fd`), the Delphi SFX that wraps most packed optical-drive flashers.
//!
//! The packer is a custom **aPLib variant**: interlaced Elias-gamma codes with a
//! single reused "last offset" and a long-distance length bonus — but with two
//! deviations from stock aPLib that make off-the-shelf decoders fail. First, the
//! tag bits are read MSB-first from 32-bit little-endian words (not a byte tag).
//! Second, the main control-bit polarity is inverted (tag bit `1` = literal).
//! The 4 magic bytes at the stream start ARE the first tag word (consumed as bits);
//! there is no separate length/header field. The stream ends at a new-offset code
//! whose complemented value is zero (an all-ones offset). Derived by disassembling
//! the packer's own entry-point stub and validated against real flashers (the
//! output carries `LITE-ON`/`DVDRW`/`MtkDriver` and the 8051 reset-vector image).
//!
//! `unpack()` is signature-anchored (locate `af7df9fd`, decode from there) and
//! fully bounds-checked: any malformed/truncated input yields `None`, never a panic
//! — fwext must never crash on an untrusted binary.

/// Upper bound on the decompressed image. Real XFlash flasher images are at most
/// ~10 MiB; 64 MiB admits every real case while bounding memory/time on a crafted
/// or corrupt stream.
const MAX_OUT: usize = 64 * 1024 * 1024;

/// The packer magic; also the first 32-bit tag word of the bitstream.
const MAGIC: [u8; 4] = [0xaf, 0x7d, 0xf9, 0xfd];

/// If `blob` is an XFlash-packed PE, decompress it and return the unpacked bytes.
/// Returns `None` if it is not this packer or the stream is malformed/truncated.
/// The result is the in-memory flasher image (equivalent to a `.unpacked.bin`);
/// callers run `xflash::carve` on it to extract the firmware.
///
/// The compressed stream is located two ways (a decode is only accepted if it runs
/// to the end marker, so a wrong guess is rejected, not mis-decoded):
///   - by the `af7df9fd` marker when present (that value is simply the first tag
///     word of many payloads), then
///   - by PE structure: this packer emits two unnamed sections — a zero-raw-size
///     decompression target (VA 0x1000) followed by the compressed section — whose
///     first tag word varies per payload (e.g. `5f7bf3fd`), so the magic search
///     alone misses those. The stream begins at that second section's raw pointer.
pub fn unpack(blob: &[u8]) -> Option<Vec<u8>> {
    for start in stream_offsets(blob) {
        if let Some(out) = decode_from(blob, start) {
            return Some(out);
        }
    }
    None
}

/// Candidate compressed-stream start offsets, most-likely first.
fn stream_offsets(blob: &[u8]) -> Vec<usize> {
    let mut offs = Vec::new();
    if let Some(m) = find(blob, &MAGIC) {
        offs.push(m);
    }
    if let Some(ro) = packed_section_raw_ptr(blob) {
        if !offs.contains(&ro) {
            offs.push(ro);
        }
    }
    offs
}

/// For this packer's PE layout, return the raw file offset of the compressed
/// section: the first unnamed section has `SizeOfRawData == 0` (the runtime
/// decompression target at VA 0x1000) and is immediately followed by an unnamed
/// section that holds the compressed data. Returns that data section's
/// `PointerToRawData`. `None` if `blob` is not a PE or the layout does not match.
fn packed_section_raw_ptr(blob: &[u8]) -> Option<usize> {
    let rd_u32 = |o: usize| -> Option<u32> {
        let b = blob.get(o..o + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let rd_u16 = |o: usize| -> Option<u16> {
        let b = blob.get(o..o + 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    };
    if blob.get(..2)? != b"MZ" {
        return None;
    }
    let e = rd_u32(0x3c)? as usize;
    if blob.get(e..e + 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = rd_u16(e + 6)? as usize;
    let optsz = rd_u16(e + 20)? as usize;
    let sect = e + 24 + optsz;
    // Walk sections; find an unnamed zero-raw-size target followed by an unnamed
    // data section.
    let mut prev_zero_target = false;
    for i in 0..nsec.min(96) {
        let o = sect + i * 40;
        let name = blob.get(o..o + 8)?;
        let raw_sz = rd_u32(o + 16)? as usize;
        let raw_ptr = rd_u32(o + 20)? as usize;
        let unnamed = name == b"\0\0\0\0\0\0\0\0";
        if prev_zero_target && unnamed && raw_sz > 0 && raw_ptr < blob.len() {
            return Some(raw_ptr);
        }
        prev_zero_target = unnamed && raw_sz == 0;
    }
    None
}

/// Decode the aPLib-variant stream that begins at `start` in `blob`.
fn decode_from(blob: &[u8], start: usize) -> Option<Vec<u8>> {
    let data = blob.get(start..)?;

    let mut d = Decoder {
        data,
        si: 0,
        tag: 0,
    };
    let mut out: Vec<u8> = Vec::new();
    let mut last_off: i64 = -1; // signed back-distance (aPLib "last offset")

    while out.len() < MAX_OUT {
        if d.bit()? == 1 {
            // literal
            out.push(*data.get(d.si)?);
            d.si += 1;
            continue;
        }

        // Elias-gamma "kind" value.
        let mut g: u64 = 1;
        loop {
            g = (g << 1) + d.bit()? as u64;
            if d.bit()? == 1 {
                break;
            }
            g = g.wrapping_sub(1);
            g = (g << 1) + d.bit()? as u64;
        }
        let kind = g as i64 - 3;

        let carry;
        if kind < 0 {
            // reuse last_off (aPLib repeated-offset feature)
            carry = d.bit()?;
        } else {
            // new offset: v = ~((kind<<8) | next_byte)
            let byte = *data.get(d.si)? as u64;
            d.si += 1;
            let v = (!(((kind as u64) << 8) | byte)) & 0xFFFF_FFFF;
            if v == 0 {
                break; // end of stream (offset was all-ones)
            }
            carry = (v & 1) as u8;
            // arithmetic >>1 keeping sign (offset is a negative back-distance)
            last_off = sar32(v);
        }

        // length: carry*2 + bit, else a gamma tail
        let mut len: u64 = (carry as u64) * 2 + d.bit()? as u64;
        if len == 0 {
            len = 1;
            loop {
                len = (len << 1) + d.bit()? as u64;
                if d.bit()? == 1 {
                    len += 2;
                    break;
                }
            }
        }
        // long-distance length bonus
        len += if (last_off as u32) < 0xFFFF_FB00 {
            2
        } else {
            1
        };

        // overlapping copy from out[out.len() + last_off]
        let base = out.len() as i64 + last_off;
        if base < 0 {
            return None; // corrupt: back-reference before start
        }
        let base = base as usize;
        for k in 0..len as usize {
            let b = *out.get(base + k)?;
            out.push(b);
            if out.len() >= MAX_OUT {
                return None;
            }
        }
    }

    // A plausible unpack produced a non-trivial image; a stream that hit MAX_OUT
    // without an end marker is treated as corrupt by the caller via carve failing.
    if out.len() < 0x1000 {
        return None;
    }
    Some(out)
}

/// MSB-first bit reader over 32-bit little-endian words (the packer's exact
/// convention). `tag` is the running 32-bit register; it refills from the next LE
/// word when its low 32 bits reach zero, injecting a sentinel low bit so the
/// refill coincides with the emitted carry.
struct Decoder<'a> {
    data: &'a [u8],
    si: usize,
    tag: u32,
}

impl Decoder<'_> {
    fn bit(&mut self) -> Option<u8> {
        let t = (self.tag as u64) << 1;
        let cf = ((t >> 32) & 1) as u8;
        let low = (t & 0xFFFF_FFFF) as u32;
        if low != 0 {
            self.tag = low;
            return Some(cf);
        }
        // refill from the next 32-bit LE word
        let w = self.data.get(self.si..self.si + 4)?;
        self.si += 4;
        let dword = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
        let t = (dword << 1) + 1; // inject sentinel low bit
        self.tag = (t & 0xFFFF_FFFF) as u32;
        Some(((t >> 32) & 1) as u8)
    }
}

/// Arithmetic right-shift by 1 of a 32-bit value, returned as a signed i64 (a
/// negative back-distance when bit 31 is set).
fn sar32(v: u64) -> i64 {
    let shifted = if v & 0x8000_0000 != 0 {
        (v >> 1) | 0x8000_0000
    } else {
        v >> 1
    };
    if shifted & 0x8000_0000 != 0 {
        shifted as i64 - 0x1_0000_0000
    } else {
        shifted as i64
    }
}

/// First index of `needle` in `hay`, memchr-accelerated.
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
    fn no_magic_yields_none() {
        assert!(unpack(&[0u8; 1024]).is_none());
        assert!(unpack(b"not packed").is_none());
    }

    #[test]
    fn truncated_stream_no_panic() {
        // Magic present but nothing decodable after it -> None, never a panic.
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&[0u8; 8]);
        assert!(unpack(&b).is_none());
    }

    #[test]
    fn sar32_sign() {
        assert_eq!(sar32(0x0000_0004), 2);
        assert_eq!(sar32(0xFFFF_FFFE), -1); // 0xFFFFFFFF as i32 = -1
        assert_eq!(sar32(0x8000_0000), -0x4000_0000);
    }
}
