# leviculum

A Rust implementation of the [Reticulum](https://reticulum.network/) network stack.

## Goals

- Full compatibility with the Python Reticulum implementation
- `no_std` core for embedded systems
- C-API for use from other languages
- Minimal dependencies
- Single codebase for embedded, Unix daemons, Android, and iOS

## Status

Version 0.5.19. The core uses a sans-I/O architecture — `reticulum-core` is a pure state machine that never performs I/O directly, making it suitable for embedded targets (`no_std + alloc`). The transport layer is fully functional with routing, path discovery, announce relay, and multi-hop support. 242 interop tests pass against the Python Reticulum reference implementation.

**What works:**

- Cryptographic primitives (X25519, Ed25519, AES-256-CBC, HKDF, HMAC-SHA256)
- Identity creation, signing, encryption/decryption
- Packet serialization (all types, Header 1/2, all contexts)
- Destination management (hashing, types, announce creation/validation)
- Full link establishment (3-packet handshake, initiator + responder)
- Link encryption, keepalive, stale detection, graceful close
- Transport layer (routing, path discovery, announce relay, multi-hop)
- Transport relay (Rust node relays between Python daemons)
- Ratchets (forward secrecy) with disk persistence
- IFAC (Interface Access Codes) — end-to-end (inbound verification, outbound application)
- Channel system (reliable streams, message envelopes)
- Buffer system (RawChannelReader/Writer, StreamDataMessage)
- BZ2 compression
- Resource transfer (segmented data over links, metadata, sliding window)
- Sans-I/O architecture (core returns Action values, driver dispatches I/O)
- High-level Node API (NodeCore for no_std, ReticulumNode for async)
- TCP server + client interfaces (with reconnection)
- UDP interface
- AutoInterface (IPv6 multicast LAN discovery)
- LocalInterface (Unix socket IPC for shared instance)
- RNode/LoRa interface
- HDLC framing (no_std)
- Config and storage system (persistent, Python-compatible)
- RPC server (rnstatus, rnpath, rnprobe compatibility)
- `lrnsd` daemon (drop-in replacement for rnsd)
- `lrns` CLI (identity, connect, selftest, probe, cp)
- Request/Response pattern (link.request/link.response, link.identify)
- `lrncp` standalone file transfer (shared instance client, rncp-compatible, fetch mode)
- C-API basics (identity, sign, verify)

**What's missing:**

- `lrns` remaining subcommands (status, path, interfaces)
- Resource compression (bz2 over links)

**Test coverage:** ~1360 tests (935 unit + 175 std + 243 interop against rnsd).

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

The core library works without the standard library (`no_std + alloc`). Contains:

- Cryptographic primitives (X25519, Ed25519, AES-256-CBC, HKDF, HMAC-SHA256)
- Identity, Destination, Link, Packet types
- Announce creation and validation
- Transport layer (routing, path discovery, relay)
- Ratchets (forward secrecy) and IFAC
- Channel and Buffer system
- NodeCore high-level API
- HDLC framing

To use without std:

```toml
[dependencies]
reticulum-core = { version = "0.3", default-features = false, features = ["alloc"] }
```

### reticulum-std

Extensions that require the standard library:

- Config file parsing
- Persistent storage
- TCP client interface
- Sans-I/O driver (event loop dispatching Action values)
- ReticulumNode high-level async API

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

- `lrnsd` - Daemon process (equivalent to rnsd, planned)
- `lrns` - Management utility (`identity` subcommand implemented, others pending)

## License

MIT
