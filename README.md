# leviculum

Leviculum is a Rust implementation of the [Reticulum](https://reticulum.network/) network stack. It is wire-compatible with the Python reference implementation and runs on Linux, macOS, and embedded devices.

## What is Reticulum?

Reticulum is a networking stack for building resilient, encrypted mesh networks over any transport medium. It works over LoRa radios, TCP, UDP, serial links, or anything that can carry bytes. Every node gets a cryptographic identity. Every connection is end-to-end encrypted. No servers, no accounts, no infrastructure required.

## What does leviculum do?

Leviculum provides the same functionality as Python Reticulum but compiled to native code. The `lnsd` daemon is a drop-in replacement for `rnsd`. The `lncp` file transfer tool replaces `rncp`. Python CLI tools like `rnstatus`, `rnpath`, and `rnprobe` work against a running `lnsd` without modification.

The protocol core (`reticulum-core`) compiles as `no_std` with only `alloc`, so it runs on microcontrollers. The same code powers the Linux daemon, a future Android app, and embedded firmware.

## Status

Leviculum is in active development. The protocol implementation is functionally complete: routing, path discovery, link establishment, encrypted channels, segmented file transfer, forward secrecy ratchets, and LoRa radio support all work and are tested against Python Reticulum on real hardware. It is not yet production-ready.

## Getting started

### Nightly binary builds

Prebuilt, statically-linked binaries (no libc dependency, runs on any Linux ≥ 3.2) are published nightly. The download URLs are stable — the same URL always points at the latest nightly:

```sh
# amd64
wget https://codeberg.org/Lew_Palm/leviculum/releases/download/nightly/leviculum-nightly-linux-amd64.tar.gz
# arm64
wget https://codeberg.org/Lew_Palm/leviculum/releases/download/nightly/leviculum-nightly-linux-arm64.tar.gz

tar xzf leviculum-nightly-linux-*.tar.gz
./leviculum-nightly-linux-*/bin/lnsd --version
```

Each tarball contains `bin/{lnsd,lns,lncp}` plus `README.md`, `LICENSE`, `CHANGELOG.md`, and a `VERSION` file. The exact build is embedded in the binaries (`lnsd --version` prints e.g. `0.6.3-nightly.20260419-5a5df20`). SHA-256 checksums are published alongside the tarballs with the suffix `.sha256`.

### Build from source

```sh
git clone https://codeberg.org/Lew_Palm/leviculum.git
cd leviculum
cargo build --release --bin lnsd --bin lncp --bin lns
./target/release/lnsd -v
```

No system C libraries are required. To run unit tests:

```sh
cargo test-core
```

To run the interop test suite against Python Reticulum:

```sh
git submodule update --init vendor/Reticulum
cargo test-interop
```

See the [installation guide](https://codeberg.org/Lew_Palm/leviculum/src/branch/master/docs/src/guide/installation.md) for all cargo aliases and test levels.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.
