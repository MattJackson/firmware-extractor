//! `unpack_to()` + `magic_kind()`.
//!
//! Best-effort shell-out to 7z / unar / innoextract / upx / binwalk. Every tool
//! is optional: a missing binary (spawn error) or a non-zero exit simply yields
//! nothing and we move on. The recursive directory walk is folded INTO
//! `unpack_to`: we read every produced regular file (size >= 256, symlinks
//! skipped) into memory, delete the scratch dir, and return `(name, bytes)` so
//! `collect.rs` can consume the members directly.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bound on any single unpacked member read into memory. Optical-drive
/// firmware images and their installer members are at most a few MB; a 256 MiB cap
/// admits every real payload while preventing a nested/bomb archive from driving
/// unbounded memory during the recursive unpack.
const MAX_MEMBER: u64 = 256 * 1024 * 1024;

/// Archive magic table (`ARCHIVE_MAGIC`).
const ARCHIVE_MAGIC: &[&[u8]] = &[
    b"PK\x03\x04",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"MSCF",
    b"\x1f\x8b",
    b"BZh",
    b"-lh",
];

/// Classify a file head:
/// "archive" if it starts with any ARCHIVE_MAGIC sig, "pe" for `MZ`, else "raw".
pub fn magic_kind(head: &[u8]) -> &'static str {
    for sig in ARCHIVE_MAGIC {
        if head.starts_with(sig) {
            return "archive";
        }
    }
    if head.len() >= 2 && &head[..2] == b"MZ" {
        return "pe";
    }
    "raw"
}

/// Best-effort unpack of `src`. Runs the tool sequence and returns every produced
/// regular file as `(basename, bytes)` (size >= 256, symlinks skipped). Missing
/// tools are ignored; returns empty if nothing unpacked.
pub fn unpack_to(src: &Path, allow_binwalk: bool) -> Vec<(String, Vec<u8>)> {
    let dest = match unique_temp_dir("fwext-unpack") {
        Some(d) => d,
        None => return Vec::new(),
    };
    let files = unpack_inner(src, &dest, allow_binwalk);
    let _ = std::fs::remove_dir_all(&dest);
    files
}

/// Try each unpacker in turn. When one succeeds, we walk `dest` and return the
/// collected files; otherwise we return empty. (After the binwalk tail, walking
/// `dest` yields whatever it carved — an empty walk yields empty.)
fn unpack_inner(src: &Path, dest: &Path, allow_binwalk: bool) -> Vec<(String, Vec<u8>)> {
    // 7z x -y -o<dest> <src>
    let o_flag = format!("-o{}", dest.display());
    if run(
        "7z",
        &[
            OsStr::new("x"),
            OsStr::new("-y"),
            OsStr::new(&o_flag),
            src.as_os_str(),
        ],
    ) && dir_nonempty(dest)
    {
        return walk(dest);
    }

    // unar -force-overwrite -o <dest> <src>
    if run(
        "unar",
        &[
            OsStr::new("-force-overwrite"),
            OsStr::new("-o"),
            dest.as_os_str(),
            src.as_os_str(),
        ],
    ) && dir_nonempty(dest)
    {
        return walk(dest);
    }

    // head[:2] == b"MZ": PE-specific carvers.
    let head = read_head(src, 8);
    if head.len() >= 2 && &head[..2] == b"MZ" {
        let inno = dest.join("_inno");
        if run(
            "innoextract",
            &[
                OsStr::new("-e"),
                OsStr::new("-s"),
                OsStr::new("-d"),
                inno.as_os_str(),
                src.as_os_str(),
            ],
        ) && inno.is_dir()
        {
            return walk(dest);
        }

        let upx = dest.join("_upx.bin");
        if run(
            "upx",
            &[
                OsStr::new("-d"),
                OsStr::new("-o"),
                upx.as_os_str(),
                src.as_os_str(),
            ],
        ) {
            return walk(dest);
        }

        // binwalk -e -q --directory <dest> <src>
        // Slow and can hang; only run when the caller allows it (i.e. the PE has no
        // sizable resource that already yielded a firmware candidate). 7z/unar above
        // already handled SFX/overlay installers (e.g. HP SoftPaq -> setup.exe).
        // We deliberately do NOT pass `--run-as=root`: on untrusted input that flag
        // lets binwalk's third-party extractors run with root privileges when fwext
        // happens to be run as root; omitting it makes binwalk refuse that dangerous
        // path while non-root extraction (the normal case) is unaffected.
        if allow_binwalk {
            run(
                "binwalk",
                &[
                    OsStr::new("-e"),
                    OsStr::new("-q"),
                    OsStr::new("--directory"),
                    dest.as_os_str(),
                    src.as_os_str(),
                ],
            );
        }
        return walk(dest);
    }

    Vec::new()
}

/// Run a command with stdout/stderr suppressed and a 180 s timeout. Returns
/// whether it exited 0 within the timeout. A spawn failure (tool absent) or a
/// timeout (killed child) returns `false`. The timeout is essential: `binwalk`
/// can hang indefinitely, and without it a single input stalls the whole batch.
fn run(program: &str, args: &[&OsStr]) -> bool {
    use std::time::{Duration, Instant};
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            // try_wait itself errored (e.g. EINTR / fd pressure under a concurrent
            // batch) while the child may still be alive: kill and reap it before
            // returning, so we never leak the subprocess.
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn read_head(path: &Path, n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    match std::fs::File::open(path) {
        Ok(mut f) => match f.read(&mut buf) {
            Ok(got) => {
                buf.truncate(got);
                buf
            }
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

fn dir_nonempty(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(mut it) => it.next().is_some(),
        Err(_) => false,
    }
}

/// Recursively collect regular files under `root`: `(basename, bytes)` for each
/// non-symlink regular file with size >= 256. Symlinks (both files and dirs) are
/// skipped, so symlinked directories are not followed. Entries are sorted for
/// reproducibility.
fn walk(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    walk_into(root, &mut out);
    out
}

fn walk_into(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => return,
    };
    entries.sort();
    for path in entries {
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            // Skip symlinks (both file and dir); do not follow symlinked dirs.
            continue;
        }
        if ft.is_dir() {
            walk_into(&path, out);
        } else if ft.is_file() {
            // Skip trivially-small files, and cap the largest file we materialize:
            // an optical-drive firmware image and its members are at most a few MB,
            // so a member above MAX_MEMBER is never the payload. This bounds peak
            // memory when an installer nests a huge archive (a decompression bomb or
            // a bundled OS image), which the recursive unpack would otherwise read
            // fully into a Vec.
            if meta.len() < 256 || meta.len() > MAX_MEMBER {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push((name, bytes));
            }
        }
    }
}

/// Create a unique empty directory under the system temp dir. `tempfile`-free.
pub(crate) fn unique_temp_dir(prefix: &str) -> Option<PathBuf> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    for attempt in 0..64u64 {
        let name = format!("{prefix}-{pid}-{nanos}-{n}-{attempt}");
        let dir = std::env::temp_dir().join(name);
        match std::fs::create_dir(&dir) {
            Ok(()) => return Some(dir),
            Err(_) => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_kind_classifies_heads() {
        assert_eq!(magic_kind(b"PK\x03\x04rest"), "archive");
        assert_eq!(magic_kind(b"Rar!\x1a\x07\x00"), "archive");
        assert_eq!(magic_kind(b"7z\xbc\xaf\x27\x1c"), "archive");
        assert_eq!(magic_kind(b"MSCF\x00\x00"), "archive");
        assert_eq!(magic_kind(b"\x1f\x8b\x08\x00"), "archive"); // gzip
        assert_eq!(magic_kind(b"BZh91AY"), "archive"); // bzip2
        assert_eq!(magic_kind(b"-lh5-abc"), "archive"); // lzh
        assert_eq!(magic_kind(b"MZ\x90\x00"), "pe");
        assert_eq!(magic_kind(b"\x7fELF"), "raw");
        assert_eq!(magic_kind(b""), "raw");
        assert_eq!(magic_kind(b"M"), "raw"); // too short for MZ
    }
}
