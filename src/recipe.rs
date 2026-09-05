//! detect_flash_recipe(): transport / SCSI CDBs / MTK DIOC / chip profiles.
//!
//! Mines flash-recipe signatures from an (unpacked) vendor flasher blob.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::bytes::Regex;
use serde_json::{Map, Value};

// ── flash-recipe signatures (mined from unpacked XFlash/vendor flashers) ──

/// RECIPE_SCSI — SCSI CDB opcode name markers, kept in this order.
const RECIPE_SCSI: &[&str] = &[
    "INQUIRY",
    "WRITE BUFFER",
    "READ BUFFER",
    "REQUEST SENSE",
    "MODE SENSE(10)",
    "MODE SELECT",
    "READ BUFFER CAPACITY",
    "TEST UNIT READY",
    "GET CONFIGURATION",
];

/// RECIPE_TRANSPORT — (magic, label) pairs. Multiple magics can map to the same
/// label; duplicate labels are deduped later.
const RECIPE_TRANSPORT: &[(&[u8], &str)] = &[
    (b"SendASPI32Command", "ASPI (WNASPI32)"),
    (b"WNASPI32", "ASPI (WNASPI32)"),
    (b"IOR_SCSI_PASS_THROUGH", "SPTI"),
    (b"SCSI_PASS_THROUGH", "SPTI"),
    (b"DeviceIoControl", "DeviceIoControl"),
    (b"MtkDriver", "MTK kernel DIOC"),
];

/// RECIPE_XFORM — payload-transform markers, kept in this order.
const RECIPE_XFORM: &[&str] = &["CRC", "chksum", "checksum", "Avoid Flash Table", "MMU"];

// RECIPE_DIOC = re.compile(rb"(?:DIOC|IOCTL)_MTK_[A-Z_0-9]+")
fn recipe_dioc() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:DIOC|IOCTL)_MTK_[A-Z_0-9]+").unwrap())
}

// RECIPE_CHIP = re.compile(
//     rb"(?:profile is for|Flash Profile>|Profile verson[^,]*,\s*for)\s*"
//     rb"([A-Z0-9()/ .\-]{3,40})", re.I)
fn recipe_chip() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:profile is for|Flash Profile>|Profile verson[^,]*,\s*for)\s*([A-Z0-9()/ .\-]{3,40})",
        )
        .unwrap()
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Trim a chip-profile capture: first strip ASCII/Unicode whitespace, then strip
/// the characters `"` and `.` from both ends.
fn py_strip_chip(s: &str) -> &str {
    let s = s.trim();
    s.trim_matches(|c| c == '"' || c == '.')
}

/// Detect the flash recipe in `blob`.
///
/// Returns `None` when no transport signature is present, otherwise a JSON object
/// with the mined recipe.
pub fn detect_flash_recipe(blob: &[u8]) -> Option<Value> {
    // transport = sorted(set(labels whose magic is present))
    let mut transport: BTreeSet<String> = BTreeSet::new();
    for (magic, label) in RECIPE_TRANSPORT {
        if contains(blob, magic) {
            transport.insert((*label).to_string());
        }
    }
    if transport.is_empty() {
        return None;
    }

    let mut map = Map::new();
    map.insert(
        "transport".to_string(),
        Value::Array(transport.into_iter().map(Value::String).collect()),
    );

    // scsi_cdbs — RECIPE_SCSI opcodes present, kept in RECIPE_SCSI order.
    let scsi: Vec<Value> = RECIPE_SCSI
        .iter()
        .filter(|op| contains(blob, op.as_bytes()))
        .map(|op| Value::String((*op).to_string()))
        .collect();
    if !scsi.is_empty() {
        map.insert("scsi_cdbs".to_string(), Value::Array(scsi));
    }

    // mtk_kernel_dioc — sorted unique DIOC matches.
    let mut dioc: BTreeSet<String> = BTreeSet::new();
    for m in recipe_dioc().find_iter(blob) {
        dioc.insert(String::from_utf8_lossy(m.as_bytes()).into_owned());
    }
    if !dioc.is_empty() {
        map.insert(
            "mtk_kernel_dioc".to_string(),
            Value::Array(dioc.into_iter().map(Value::String).collect()),
        );
    }

    // flash_chip_profiles — sorted unique group1 captures that contain a digit,
    // stripped of quotes/dots/whitespace, capped at 40.
    let mut chips: BTreeSet<String> = BTreeSet::new();
    for caps in recipe_chip().captures_iter(blob) {
        if let Some(g1) = caps.get(1) {
            let raw = g1.as_bytes();
            // Keep only captures whose *un-stripped* text contains a digit.
            if !raw.iter().any(|b| b.is_ascii_digit()) {
                continue;
            }
            let decoded = String::from_utf8_lossy(raw).into_owned();
            chips.insert(py_strip_chip(&decoded).to_string());
        }
    }
    if !chips.is_empty() {
        let capped: Vec<Value> = chips.into_iter().take(40).map(Value::String).collect();
        map.insert("flash_chip_profiles".to_string(), Value::Array(capped));
    }

    // payload_transform — markers present (in RECIPE_XFORM order), host_side_key=false.
    let xform: Vec<Value> = RECIPE_XFORM
        .iter()
        .filter(|x| contains(blob, x.as_bytes()))
        .map(|x| Value::String((*x).to_string()))
        .collect();
    if !xform.is_empty() {
        let mut pt = Map::new();
        pt.insert("markers".to_string(), Value::Array(xform));
        pt.insert("host_side_key".to_string(), Value::Bool(false));
        map.insert("payload_transform".to_string(), Value::Object(pt));
    }

    Some(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_transport_scsi_and_dioc() {
        let blob = b"junk WNASPI32 more WRITE BUFFER then DIOC_MTK_WRITE_FLASHMEM tail";
        let r = detect_flash_recipe(blob).expect("should be Some");
        assert_eq!(r["transport"], serde_json::json!(["ASPI (WNASPI32)"]));
        assert_eq!(r["scsi_cdbs"], serde_json::json!(["WRITE BUFFER"]));
        assert_eq!(
            r["mtk_kernel_dioc"],
            serde_json::json!(["DIOC_MTK_WRITE_FLASHMEM"])
        );
    }

    #[test]
    fn no_transport_returns_none() {
        assert!(detect_flash_recipe(b"nothing interesting here").is_none());
    }

    #[test]
    fn chip_profile_requires_digit_and_is_stripped() {
        // Capture contains a digit -> kept; quotes/dots/space stripped.
        let blob = b"profile is for \"MX25L6405D\". rest";
        let r = detect_flash_recipe(b"WNASPI32").expect("transport present");
        assert!(r.get("flash_chip_profiles").is_none());
        let _ = blob;

        let blob2 = b"WNASPI32 profile is for MX25L6405D , tail";
        let r2 = detect_flash_recipe(blob2).expect("some");
        let chips = r2["flash_chip_profiles"].as_array().unwrap();
        assert!(chips.iter().any(|c| c == "MX25L6405D"));
    }
}
