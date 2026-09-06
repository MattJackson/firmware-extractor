# firmware-extractor (`fwext`)

[![CI](https://github.com/MattJackson/firmware-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/MattJackson/firmware-extractor/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MattJackson/firmware-extractor?display_name=tag&sort=semver)](https://github.com/MattJackson/firmware-extractor/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue.svg)](#build-from-source)

**Any firmware download in → one canonical raw firmware `.bin` + a JSON label out.**

`fwext` takes a vendor firmware download — an installer `.exe`, a self-extracting
flasher, an archive (zip/7z/rar/cab/gzip/bz2), a PE with the image in a resource or
overlay, or a plain raw image — and produces exactly **one** flashable raw firmware
image plus a JSON sidecar describing it. Extraction is **signature-based** (no
hardcoded offsets), **deterministic** (same input → same output), and **100%
offline** (no network, no running the vendor tool).

It was originally built to recover optical-drive (CD/DVD/BD) firmware at scale, but
the pipeline is generic and vendor-agnostic.

## Install

### Homebrew (macOS & Linux)

```sh
brew install MattJackson/tap/fwext
```

Upgrades come through Homebrew: `brew upgrade fwext`.

### Prebuilt binaries

Grab a build for your platform from the [latest release][latest], or use these
stable "always the newest" URLs:

| Platform | Download |
| --- | --- |
| Linux x86_64 (static musl) | [`fwext-x86_64-unknown-linux-musl.tar.gz`](https://github.com/MattJackson/firmware-extractor/releases/latest/download/fwext-x86_64-unknown-linux-musl.tar.gz) |
| macOS Apple Silicon | [`fwext-aarch64-apple-darwin.tar.gz`](https://github.com/MattJackson/firmware-extractor/releases/latest/download/fwext-aarch64-apple-darwin.tar.gz) |
| macOS Intel | [`fwext-x86_64-apple-darwin.tar.gz`](https://github.com/MattJackson/firmware-extractor/releases/latest/download/fwext-x86_64-apple-darwin.tar.gz) |
| Windows x86_64 | [`fwext-x86_64-pc-windows-msvc.zip`](https://github.com/MattJackson/firmware-extractor/releases/latest/download/fwext-x86_64-pc-windows-msvc.zip) |

Each archive ships with a matching `.sha256`. Verify before use, e.g.:

```sh
shasum -a 256 -c fwext-x86_64-unknown-linux-musl.tar.gz.sha256
```

### From Cargo

```sh
cargo install --git https://github.com/MattJackson/firmware-extractor --tag v0.1.0
```

## Usage

```sh
fwext <input>                 # writes <stem>.fw.bin + <stem>.fw.json next to cwd
fwext <input> -o OUTDIR       # write outputs to OUTDIR
fwext <input> --print         # print the JSON label only (no files written)
```

Exit code `0` when a firmware image was produced, `2` when none could be carved
(the JSON still explains why).

## What it does

For each input `fwext` runs an identify → dispatch → carve pipeline:

1. **identify** the container/format by magic bytes.
2. **decode** in-memory containers (zip, word-swapped zip, gzip, bz2) and shell out
   to `7z`/`unar`/`innoextract`/`upx`/`binwalk` for archives and self-extractors
   (each optional — a missing tool is skipped).
3. **unpack** vendor runtime packers offline (e.g. the MediaTek "XFlash" `af7df9fd`
   aPLib-variant SFX, PEBundle wrappers).
4. **carve** the firmware image by family signature (8051 reset/vector tables,
   vendor boot headers, distribution headers, INQUIRY banners) with size/entropy
   validation.
5. **label** it: sha256, size, detected chipset/part, boot banner, entropy-based
   payload form, and a self-signoff `confidence`.

### The `confidence` field

- `confident` — a real firmware image (chipset/banner/vendor magic, or a plausible
  plaintext/code image): this **is** the bin.
- `confident-encrypted` — a valid final image that is encrypted at rest (opaque,
  but it is the firmware).
- `unconfirmed` — a blob was extracted but still looks like a wrapper/container;
  likely not the final bin.
- `none` — no firmware bytes could be produced (the `status` says why).

## Build from source

```sh
cargo build --release      # -> target/release/fwext
cargo test                 # unit tests (no external corpus needed)
```

Minimum supported Rust: **1.86**.

Optional external tools that widen coverage when present on `PATH`: `7z`, `unar`,
`innoextract`, `upx`, `binwalk`.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
and our [Code of Conduct](CODE_OF_CONDUCT.md) first. CI runs `cargo fmt --check`,
`cargo clippy -D warnings`, and the test suite on every push and pull request, plus
macOS/Windows compile checks for changes headed to `main`.

## Security

Found a vulnerability? Please follow the process in [SECURITY.md](SECURITY.md)
rather than opening a public issue.

## Changelog

See [CHANGELOG.md](CHANGELOG.md). This project follows
[Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

## License

Licensed under the [MIT License](LICENSE) © Matthew Jackson.

[latest]: https://github.com/MattJackson/firmware-extractor/releases/latest
