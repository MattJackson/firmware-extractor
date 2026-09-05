# firmware-extractor (`fwext`)

**Any firmware download in → one canonical raw firmware `.bin` + a JSON label out.**

`fwext` takes a vendor firmware download — an installer `.exe`, a self-extracting
flasher, an archive (zip/7z/rar/cab/gzip/bz2), a PE with the image in a resource or
overlay, or a plain raw image — and produces exactly **one** flashable raw firmware
image plus a JSON sidecar describing it. Extraction is **signature-based** (no
hardcoded offsets), **deterministic** (same input → same output), and **100%
offline** (no network, no running the vendor tool).

It was originally built to recover optical-drive (CD/DVD/BD) firmware at scale, but
the pipeline is generic and vendor-agnostic.

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

## Build

```sh
cargo build --release      # -> target/release/fwext
cargo test                 # unit tests (no external corpus needed)
```

Minimum supported Rust: **1.86**.

Optional external tools that widen coverage when present on `PATH`: `7z`, `unar`,
`innoextract`, `upx`, `binwalk`.

## License

MIT © Matthew Jackson. See [LICENSE](LICENSE).
