# Installation

## Requirements

- Rust stable toolchain ([rustup.rs](https://rustup.rs/))
- Git (for submodules)

No system C libraries are required. All cryptography is compiled from Rust source.

## Build from source

```sh
git clone https://codeberg.org/Lew_Palm/leviculum.git
cd leviculum
cargo build --release --bin lnsd --bin lns --bin lncp
```

The binaries are in `target/release/`.

## Running the daemon

```sh
./target/release/lnsd -v
```

Reads its config from `~/.reticulum/config`, the same location as Python Reticulum.

## Development

### Cargo aliases

Common workflows are available as cargo aliases (defined in `.cargo/config.toml`):

| Command | What it does |
|---------|-------------|
| `cargo test-core` | Run all reticulum-core unit tests |
| `cargo test-std` | Run all reticulum-std unit tests |
| `cargo test-interop` | Run interop tests against Python Reticulum |
| `cargo test-integ` | Run Docker-based integration tests |
| `cargo lint` | Run clippy on all crates |
| `cargo fmt --all -- --check` | Check formatting |

### Test levels

Tests are organized by what they require:

**Unit tests** -- just Rust, no extra dependencies:

```sh
cargo test-core
cargo test-std
```

**Interop tests** -- require Python 3 and the vendored Reticulum:

```sh
git submodule update --init vendor/Reticulum
cargo test-interop
```

**Integration tests** -- require Docker:

```sh
cargo build --release --bin lnsd
cargo test-integ
```

### Embedded cross-compilation

Embedded targets are not downloaded automatically. Install them when needed:

```sh
rustup target add thumbv7em-none-eabihf   # nRF52840
rustup target add thumbv6m-none-eabi       # RP2040
cargo check-nrf52
cargo check-embedded
```

### Before submitting changes

```sh
cargo fmt --all -- --check
cargo lint
cargo test-core
cargo test-interop
```
