# Contributing to firmware-extractor

Thanks for your interest! `fwext` aims to turn *any* firmware download into one
canonical raw `.bin` + JSON label, offline and deterministically.

## Ground rules

- **Signature-based, no hardcoded offsets.** New format support is added as a
  signature-anchored carve/decode strategy that generalizes across a family, not a
  per-file offset.
- **Never panic on untrusted input.** Inputs are arbitrary, possibly-malformed
  binaries. All parsing is bounds-checked; the worst case is an honest
  `confidence: none` label, never a crash.
- **Deterministic.** The same input must always produce the same output.

## Workflow

- Branch from and open PRs against **`dev`**. CI on `dev` runs `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`, and an MSRV build
  (Rust 1.86). `main` builds and publishes the `fwext` binary.
- Keep the gate green locally before pushing:

  ```sh
  cargo fmt --all
  cargo clippy --all-targets -- -D warnings
  cargo test
  ```

## Adding a new firmware family

1. Characterize the format on a few samples (start signature, boundaries,
   size/entropy).
2. Add a strategy (see `src/xflash.rs` for the identify→carve pattern, or
   `src/af7.rs` for a decompressor) that is signature-anchored and validated
   (size + entropy + a family marker where a generic opcode could false-match).
3. Add unit tests that cover success, rejection, and a truncated/empty input.

## License

By contributing you agree your contributions are licensed under the MIT License.
