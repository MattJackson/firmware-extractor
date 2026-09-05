# Security Policy

`fwext` parses **untrusted, attacker-controllable binary files** (firmware
downloads, installers, archives, self-extractors). Its hard requirement is that it
never crashes, never executes input, and never allocates unbounded memory on any
input — the worst case is an honest `confidence: none` label.

Classes of bug that qualify as security issues:

- A reachable panic, out-of-bounds read, or integer overflow on a crafted input.
- Unbounded memory/CPU from a crafted length field or a decompression bomb
  (archive/zip/gzip/bz2 or a vendor codec).
- Path traversal / zip-slip when writing unpacked members to a temp directory.
- Any way input bytes cause code execution.

## Supported versions

| Version | Supported |
|---|---|
| `main` branch | ✅ |
| latest tagged release | ✅ |
| `0.0.x` / `0.1.x` pre-release | ⚠ best-effort |

## Reporting a vulnerability

Please report privately to **matthew@pq.io** (or open a GitHub Security Advisory on
the repository). Include the input file (or a minimal reproducer) and the observed
behavior. Please do not open a public issue for a crash-on-input until it is fixed.
