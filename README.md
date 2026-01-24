# leviculum

A Rust implementation of the [Reticulum](https://reticulum.network/) network stack.

## Goals

- Full compatibility with the Python Reticulum implementation
- `no_std` core for embedded systems
- C-API for use from other languages
- Minimal dependencies
- Single codebase for embedded, Unix daemons, Android, and iOS

## Status

Work in progress. The cryptographic layer is complete and validated against the Python implementation. Packet serialization works for all packet types. Link structure is in place but the transport layer is not yet functional.

**What works:**

- Cryptographic primitives (X25519, Ed25519, AES-256-CBC, HKDF, HMAC-SHA256)
- Identity creation, signing, encryption/decryption
- Packet serialization (all types, Header 1/2, all contexts)
- Link structure and link ID calculation
- HDLC framing
- Config and storage system
- Basic daemon structure (lrnsd)

**What's missing:**

- Network interfaces (TCP, UDP, Serial)
- Transport layer (routing, path discovery)
- Full link establishment flow
- Resource transfers
- Channel/Buffer abstractions

**Test coverage:** 198 tests (unit, property-based, Python test vectors), plus 17 integration tests against a running rnsd.

## Building

```sh
cargo build --workspace
cargo test --workspace
```

### Running interop tests

The integration tests verify compatibility with a running Python rnsd. Start rnsd with a TCP interface on localhost:4242, then:

```sh
cargo test --package leviculum-std --test rnsd_interop -- --ignored
```

## Project Structure

```
leviculum/
├── leviculum-core/     # no_std compatible core library
├── leviculum-std/      # std extensions (networking, config, storage)
├── leviculum-ffi/      # C-API bindings
├── leviculum-cli/      # Command-line tools (lrnsd, lrns)
├── doc/                   # Protocol documentation
└── tests/vectors/         # Test vectors generated from Python
```

### leviculum-core

The core library works without the standard library. Contains:

- Cryptographic primitives
- Identity, Destination, Link, Packet types
- State machines for links and resources

To use without std:

```toml
[dependencies]
leviculum-core = { version = "0.1", default-features = false, features = ["alloc"] }
```

### leviculum-std

Extensions that require the standard library:

- Config file parsing
- Persistent storage
- Network interfaces (WIP)
- Reticulum instance management

### leviculum-ffi

C bindings. Build as shared or static library:

```sh
cargo build -p leviculum-ffi --release
```

Generate C headers (requires cbindgen):

```sh
cd leviculum-ffi
cbindgen --output leviculum.h
```

### leviculum-cli

Command-line tools:

- `lrnsd` - Daemon process (equivalent to rnsd)
- `lrns` - Management utility (planned)

## Documentation

Protocol documentation is in `doc/`. See also [ROADMAP.md](ROADMAP.md) for the development plan.

## License

MIT
