//! detect_chipset(): MTK part (MT1[389]xx) gated by MTK context, EXACT_PARTS
//! (Ricoh/Renesas/Hitachi/NXP), boot banner. Returns (chipset, conf, ev, banner).

use regex::bytes::Regex;
use std::sync::OnceLock;

/// STRING_RUN: runs of printable ASCII, >= 4 bytes.
fn string_run() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\x20-\x7e]{4,}").unwrap())
}

fn mtk_part() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"MT1[389][0-9]{2}[A-Z]?").unwrap())
}

fn mtk_ctx() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)MEDIATEK|SRVMTK|MTKDW|MTKFLASH|MTEKMT|Mtk\.SYS|\bMTK[0-9]").unwrap()
    })
}

fn banner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"Boot[ _][A-Z0-9]{2,8}").unwrap())
}

/// EXACT_PARTS: (pattern, label) pairs, iterated in order.
fn exact_parts() -> &'static Vec<(Regex, &'static str)> {
    static RE: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RE.get_or_init(|| {
        vec![
            (Regex::new(r"MMP[0-9]{3}").unwrap(), "Ricoh"),
            (Regex::new(r"SH7[0-9]{3}").unwrap(), "Renesas"),
            (
                Regex::new(r"HD64F30[0-9]{2}|\b30[0-9]{2}F\b").unwrap(),
                "Hitachi H8",
            ),
            (Regex::new(r"Renesas").unwrap(), "Renesas"),
            (Regex::new(r"Nexperia|PNX[0-9]{3,}").unwrap(), "NXP/Philips"),
        ]
    })
}

/// Join all printable runs with 0x0a.
fn strings_blob(b: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for (i, m) in string_run().find_iter(b).enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(m.as_bytes());
    }
    out
}

/// latin-1 decode: every byte maps 1:1 to a Unicode code point U+00..U+FF.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Detect the controller chipset from `blob`. Returns
/// (chipset, confidence, evidence, banner).
pub fn detect_chipset(
    blob: &[u8],
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut banner: Option<String> = None;

    for b in crate::container::decode_container(blob) {
        let s = strings_blob(&b);

        if banner.is_none() {
            if let Some(m) = banner_re().find(&s) {
                banner = Some(latin1(m.as_bytes()));
            }
        }

        if let Some(m) = mtk_part().find(&s) {
            if mtk_ctx().is_match(&s) {
                let part = latin1(m.as_bytes());
                return (
                    Some(format!("MediaTek {part}")),
                    Some("exact".to_string()),
                    Some(part),
                    banner,
                );
            }
        }

        for (pat, lab) in exact_parts() {
            if let Some(x) = pat.find(&s) {
                let hit = latin1(x.as_bytes());
                return (
                    Some(format!("{lab} {hit}")),
                    Some("exact".to_string()),
                    Some(hit),
                    banner,
                );
            }
        }
    }

    (None, None, None, banner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtk_part_with_context() {
        let blob = b"garbage\x00\x00MTKDW loader\x00\x00part MT1959 rev\x00";
        let (chip, conf, ev, _banner) = detect_chipset(blob);
        assert_eq!(chip.as_deref(), Some("MediaTek MT1959"));
        assert_eq!(conf.as_deref(), Some("exact"));
        assert_eq!(ev.as_deref(), Some("MT1959"));
    }

    #[test]
    fn mtk_part_without_context_is_not_exact() {
        // MT1959 present but no MTK context string -> falls through to None.
        let blob = b"random MT1959 string only, nothing else printable here";
        let (chip, conf, ev, _banner) = detect_chipset(blob);
        assert_eq!(chip, None);
        assert_eq!(conf, None);
        assert_eq!(ev, None);
    }

    #[test]
    fn exact_part_ricoh() {
        let blob = b"header MMP330 device firmware payload";
        let (chip, conf, ev, _banner) = detect_chipset(blob);
        assert_eq!(chip.as_deref(), Some("Ricoh MMP330"));
        assert_eq!(conf.as_deref(), Some("exact"));
        assert_eq!(ev.as_deref(), Some("MMP330"));
    }

    #[test]
    fn banner_captured_even_when_no_chipset() {
        let blob = b"some Boot_AB12 banner text but no known chipset here";
        let (chip, _conf, _ev, banner) = detect_chipset(blob);
        assert_eq!(chip, None);
        assert_eq!(banner.as_deref(), Some("Boot_AB12"));
    }
}
