# leviculum

A Rust implementation of the [Reticulum](https://reticulum.network/) network stack.

## Goals

- Full compatibility with the Python Reticulum implementation
- `no_std` core for embedded systems
- C-API with stable ABI for use from other languages
- Minimal dependencies
- Single codebase for embedded, Unix daemons, Android, and iOS

## Status

Early development. The cryptographic primitives and basic data structures are implemented and tested. Network interfaces and the transport layer are work in progress.

What works:
- Cryptographic primitives (X25519, Ed25519, AES-256-CBC, HKDF, HMAC-SHA256)
- Identity creation and signing
- Packet serialization
- HDLC framing

What's missing:
- Network interfaces (TCP, UDP, Serial)
- Transport layer (routing, path discovery)
- Link establishment
- Resource transfers

## Building

```sh
cargo build --workspace
cargo test --workspace
```

## Project Structure

```
leviculum/
├── leviculum-core/     # no_std compatible core library
├── leviculum-std/      # std extensions (networking, file I/O)
├── leviculum-ffi/      # C-API bindings
└── leviculum-cli/      # Command-line tools (lrnsd, lrns)
```

### leviculum-core

The core library is designed to work without the standard library. It contains:

- Cryptographic primitives
- Identity and Destination types
- Packet encoding/decoding
- Link and Resource state machines

To use without std:

```toml
[dependencies]
leviculum-core = { version = "0.1", default-features = false, features = ["alloc"] }
```

### leviculum-ffi

Provides C bindings. Build as a shared or static library:

```sh
cargo build -p leviculum-ffi --release
```

Generate C headers (requires cbindgen):

```sh
cd leviculum-ffi
cbindgen --output leviculum.h
```

## License

MIT
