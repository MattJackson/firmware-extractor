# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-05

Initial public release.

### Added
- `fwext` CLI: `binary in -> raw firmware .bin + JSON label out`, offline and
  deterministic, with a self-signoff `confidence` field.
- identify → decode → unpack → carve → label pipeline:
  - container decodes: word-swapped zip, zip, gzip, bz2 (bounded/bomb-guarded).
  - archive/self-extractor unpacking via optional `7z`/`unar`/`innoextract`/`upx`/
    `binwalk`.
  - PE overlay + resource extraction (tolerant of a stray byte before `MZ`).
  - offline decompressor for the MediaTek "XFlash" `af7df9fd` runtime packer (a
    custom aPLib variant), stream located by marker or PE structure.
  - PEBundle-wrapped payloads carved directly from `.data`.
  - signature-based firmware carvers: 8051 reset/vector tables (LiteOn/Plextor/
    TDK/Sony), BenQ boot vector, Sony/ATAPI banners, Plextor `.data` vector table,
    Pioneer MT1868 `MTKDW`, and verbatim distribution-image headers.
- chipset/part detection, entropy-based payload classification, flash-recipe hints.

[Unreleased]: https://github.com/MattJackson/firmware-extractor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MattJackson/firmware-extractor/releases/tag/v0.1.0
