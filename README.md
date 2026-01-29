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

**Test coverage:** 198 Rust tests + 13 C tests (unit, property-based, Python test vectors), plus 17 integration tests against a running rnsd.

## Building

```sh
cargo build --workspace
cargo test --workspace
```

### Running interop tests

The integration tests verify compatibility with the Python Reticulum implementation. They use a vendored copy of Python Reticulum as a git submodule:

```sh
git submodule update --init  # One-time setup
cargo test --package reticulum-std --test rnsd_interop
```

The tests will auto-initialize the submodule if needed, so the explicit `git submodule update` is optional.

To use your own Reticulum checkout instead:

```sh
RETICULUM_PATH=/path/to/Reticulum cargo test --package reticulum-std --test rnsd_interop
```

## Project Structure

```
leviculum/
├── reticulum-core/     # no_std compatible core library
├── reticulum-std/      # std extensions (networking, config, storage)
├── reticulum-ffi/      # C-API bindings
├── reticulum-cli/      # Command-line tools (lrnsd, lrns)
├── doc/                # Protocol documentation
└── tests/vectors/      # Test vectors generated from Python
```

### reticulum-core

The core library works without the standard library. Contains:

- Cryptographic primitives
- Identity, Destination, Link, Packet types
- State machines for links and resources

To use without std:

```toml
[dependencies]
reticulum-core = { version = "0.1", default-features = false, features = ["alloc"] }
```

### reticulum-std

Extensions that require the standard library:

- Config file parsing
- Persistent storage
- Network interfaces (WIP)
- Reticulum instance management

### reticulum-ffi

C bindings. Build as shared or static library:

```sh
cargo build -p reticulum-ffi --release
```

Generate C headers (requires cbindgen):

```sh
cd reticulum-ffi
cbindgen --output reticulum.h
```

### reticulum-cli

Command-line tools:

- `lrnsd` - Daemon process (equivalent to rnsd)
- `lrns` - Management utility (planned)

## License

MIT
