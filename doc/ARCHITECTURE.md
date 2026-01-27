# Leviculum Architecture

## Design Principles

1. **All protocol logic in core** - Transport, routing, announces, links
2. **Platform abstraction via traits** - Interface, Clock, Storage
3. **no_std + alloc in core** - Runs on ESP32, nRF52840, RP2040, Linux
4. **Thin platform layers** - Only I/O implementations, no logic

## Crate Structure

```
leviculum/
├── reticulum-core/          # no_std + alloc - ALL protocol logic
│   ├── src/
│   │   ├── lib.rs
│   │   ├── constants.rs     # Protocol constants
│   │   ├── crypto/          # Cryptographic primitives
│   │   │   ├── mod.rs
│   │   │   ├── aes_cbc.rs
│   │   │   ├── hashes.rs
│   │   │   ├── hkdf_impl.rs
│   │   │   ├── hmac_impl.rs
│   │   │   └── token.rs
│   │   ├── identity.rs      # Identity management
│   │   ├── destination.rs   # Destination types (type-state)
│   │   ├── packet.rs        # Packet encoding/decoding
│   │   ├── link.rs          # Link state machine
│   │   ├── announce.rs      # NEW: Announce creation/validation
│   │   ├── resource.rs      # Resource transfer state machine
│   │   ├── channel.rs       # Channel abstraction
│   │   ├── transport.rs     # NEW: Routing, path tables, protocol logic
│   │   └── traits.rs        # NEW: Platform abstraction traits
│   └── Cargo.toml
│
├── reticulum-std/           # std - Desktop/Server platform
│   ├── src/
│   │   ├── lib.rs
│   │   ├── interfaces/      # Concrete interface implementations
│   │   │   ├── mod.rs
│   │   │   ├── tcp.rs       # TCP client/server
│   │   │   ├── udp.rs       # UDP broadcast/unicast
│   │   │   ├── serial.rs    # Serial/UART (for KISS/HDLC)
│   │   │   └── hdlc.rs      # HDLC framing (already exists)
│   │   ├── clock.rs         # System clock implementation
│   │   ├── storage.rs       # File-based storage
│   │   ├── config.rs        # Config file parsing
│   │   └── runtime.rs       # Tokio async wrapper
│   └── Cargo.toml
│
├── reticulum-ffi/           # C-API bindings
└── reticulum-cli/           # Command-line tools
```

Future crates (not now):
```
├── reticulum-embassy/       # no_std - Embassy async runtime
├── reticulum-lora/          # no_std - LoRa radio (SX1262/SX1276)
└── reticulum-ble/           # no_std - BLE interface
```

## Core Traits (reticulum-core/src/traits.rs)

```rust
//! Platform abstraction traits for reticulum-core
//!
//! These traits allow the protocol logic to run on any platform
//! by abstracting I/O, time, and storage.

use alloc::vec::Vec;

/// Error type for interface operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceError {
    /// Would block (non-blocking mode)
    WouldBlock,
    /// Connection closed or unavailable
    Disconnected,
    /// Buffer too small
    BufferTooSmall,
    /// Other error
    Other,
}

/// A network interface that can send and receive packets
///
/// Implementations: TCP, UDP, LoRa, BLE, Serial
pub trait Interface {
    /// Human-readable name for logging
    fn name(&self) -> &str;

    /// Maximum transmission unit (payload size)
    fn mtu(&self) -> usize;

    /// Unique hash identifying this interface (for routing)
    fn hash(&self) -> [u8; 16];

    /// Send a packet (may be framed by implementation)
    fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError>;

    /// Receive a packet into buffer, returns bytes read
    /// Returns WouldBlock if no data available (non-blocking)
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, InterfaceError>;

    /// Check if interface is online/connected
    fn is_online(&self) -> bool;

    /// Interface mode flags
    fn is_broadcast(&self) -> bool { false }
    fn is_local(&self) -> bool { false }
}

/// Clock for timestamps and timeouts
///
/// Implementations: SystemClock (std), embassy::Instant (no_std)
pub trait Clock {
    /// Milliseconds since some arbitrary epoch (monotonic)
    fn now_ms(&self) -> u64;

    /// Convenience: seconds since epoch
    fn now_secs(&self) -> u64 {
        self.now_ms() / 1000
    }
}

/// Persistent storage for identities, paths, etc.
///
/// Implementations: FileStorage (std), FlashStorage (no_std)
/// Optional - transport works without it (no persistence)
pub trait Storage {
    /// Load data by key
    fn load(&self, category: &str, key: &[u8]) -> Option<Vec<u8>>;

    /// Store data by key
    fn store(&mut self, category: &str, key: &[u8], value: &[u8]) -> Result<(), ()>;

    /// Delete data by key
    fn delete(&mut self, category: &str, key: &[u8]) -> Result<(), ()>;

    /// List all keys in category
    fn list(&self, category: &str) -> Vec<Vec<u8>>;
}

/// No-op storage for devices without persistence
pub struct NoStorage;

impl Storage for NoStorage {
    fn load(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> { None }
    fn store(&mut self, _: &str, _: &[u8], _: &[u8]) -> Result<(), ()> { Ok(()) }
    fn delete(&mut self, _: &str, _: &[u8]) -> Result<(), ()> { Ok(()) }
    fn list(&self, _: &str) -> Vec<Vec<u8>> { Vec::new() }
}

/// Random number generator abstraction
///
/// Implementations: OsRng (std), hardware RNG (no_std)
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

// Blanket impl for rand_core::CryptoRngCore
impl<T: rand_core::CryptoRngCore> Rng for T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dest)
    }
}
```

## Transport in Core (reticulum-core/src/transport.rs)

```rust
//! Transport layer - routing, path discovery, packet handling
//!
//! This is the heart of the Reticulum protocol. It manages:
//! - Interface registration
//! - Packet routing
//! - Path/announce tables
//! - Destination registration

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::announce::ReceivedAnnounce;
use crate::packet::Packet;
use crate::traits::{Clock, Interface, Rng, Storage};
use crate::{Destination, Identity, Link};

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Enable routing for other nodes
    pub enable_transport: bool,
    /// Maximum hops for path finding
    pub max_hops: u8,
    /// Path expiry in seconds
    pub path_expiry_secs: u64,
    /// Announce rate limit (per destination, per second)
    pub announce_rate_limit: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enable_transport: false,
            max_hops: 128,
            path_expiry_secs: 3600,
            announce_rate_limit: 1,
        }
    }
}

/// Path table entry
#[derive(Debug, Clone)]
pub struct PathEntry {
    pub destination_hash: [u8; 16],
    pub next_hop_interface: usize,  // index into interfaces
    pub hops: u8,
    pub expires_at_ms: u64,
    pub announce_packet: Vec<u8>,   // for retransmission
}

/// Announce table entry (for rate limiting and retransmission)
#[derive(Debug, Clone)]
pub struct AnnounceEntry {
    pub destination_hash: [u8; 16],
    pub received_at_ms: u64,
    pub retransmit_at_ms: Option<u64>,
    pub hops: u8,
}

/// Events emitted by Transport for the application to handle
#[derive(Debug)]
pub enum TransportEvent {
    /// A new announce was received and validated
    AnnounceReceived(ReceivedAnnounce),
    /// A packet arrived for a registered destination
    PacketReceived {
        destination_hash: [u8; 16],
        packet: Packet,
    },
    /// A link request arrived
    LinkRequestReceived {
        link: Link,
        interface_index: usize,
    },
    /// A link proof arrived
    LinkProofReceived {
        link_id: [u8; 16],
        proof_data: Vec<u8>,
    },
    /// Path to destination found
    PathFound {
        destination_hash: [u8; 16],
        hops: u8,
    },
    /// Path to destination lost
    PathLost {
        destination_hash: [u8; 16],
    },
}

/// The Transport layer
///
/// Generic over platform traits - same code runs everywhere.
pub struct Transport<C: Clock, S: Storage> {
    config: TransportConfig,
    clock: C,
    storage: S,
    identity: Identity,

    // Interface management (indices are stable)
    interfaces: Vec<Option<Box<dyn Interface>>>,

    // Routing tables
    path_table: BTreeMap<[u8; 16], PathEntry>,
    announce_table: BTreeMap<[u8; 16], AnnounceEntry>,

    // Registered destinations (we accept packets for these)
    destinations: BTreeMap<[u8; 16], DestinationEntry>,

    // Active links
    links: BTreeMap<[u8; 16], Link>,

    // Pending events for application
    events: Vec<TransportEvent>,
}

struct DestinationEntry {
    // Type info, callbacks, etc.
}

impl<C: Clock, S: Storage> Transport<C, S> {
    /// Create a new transport instance
    pub fn new(config: TransportConfig, clock: C, storage: S, identity: Identity) -> Self {
        Self {
            config,
            clock,
            storage,
            identity,
            interfaces: Vec::new(),
            path_table: BTreeMap::new(),
            announce_table: BTreeMap::new(),
            destinations: BTreeMap::new(),
            links: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Register an interface, returns interface index
    pub fn register_interface(&mut self, interface: Box<dyn Interface>) -> usize {
        let index = self.interfaces.len();
        self.interfaces.push(Some(interface));
        index
    }

    /// Register a destination (we will receive packets for it)
    pub fn register_destination(&mut self, dest: &impl Destination) {
        self.destinations.insert(*dest.hash(), DestinationEntry {});
    }

    /// Send an announce for a destination
    pub fn announce<R: Rng>(
        &mut self,
        rng: &mut R,
        dest: &impl AnnouncingDestination,
        app_data: Option<&[u8]>,
    ) -> Result<(), TransportError> {
        let packet = dest.create_announce(rng, app_data)?;
        self.send_on_all_interfaces(&packet)
    }

    /// Check if we have a path to a destination
    pub fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.path_table.contains_key(dest_hash)
    }

    /// Get hop count to destination
    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        self.path_table.get(dest_hash).map(|p| p.hops)
    }

    /// Request a path to a destination
    pub fn request_path(&mut self, dest_hash: [u8; 16]) {
        // TODO: Send path request packet
    }

    /// Send a packet to a destination
    pub fn send(&mut self, packet: Packet) -> Result<(), TransportError> {
        if let Some(path) = self.path_table.get(&packet.destination_hash) {
            if let Some(Some(iface)) = self.interfaces.get_mut(path.next_hop_interface) {
                let data = packet.pack()?;
                iface.send(&data).map_err(TransportError::Interface)?;
                return Ok(());
            }
        }
        Err(TransportError::NoPath)
    }

    /// Process incoming data from an interface
    ///
    /// Call this when data is available on an interface.
    /// Returns events that occurred during processing.
    pub fn process_incoming(
        &mut self,
        interface_index: usize,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let packet = Packet::unpack(data)?;
        self.handle_packet(packet, interface_index)
    }

    /// Poll for work - call periodically
    ///
    /// Handles timeouts, retransmissions, etc.
    pub fn poll(&mut self) {
        let now = self.clock.now_ms();
        self.expire_paths(now);
        self.process_announce_retransmissions(now);
    }

    /// Drain pending events
    pub fn drain_events(&mut self) -> impl Iterator<Item = TransportEvent> + '_ {
        self.events.drain(..)
    }

    // --- Internal methods ---

    fn handle_packet(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        match packet.flags.packet_type {
            PacketType::Announce => self.handle_announce(packet, interface_index),
            PacketType::LinkRequest => self.handle_link_request(packet, interface_index),
            PacketType::Proof => self.handle_proof(packet, interface_index),
            PacketType::Data => self.handle_data(packet, interface_index),
        }
    }

    fn handle_announce(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        // Validate announce (signature check)
        let announce = ReceivedAnnounce::from_packet(&packet)?;

        // Rate limiting
        let now = self.clock.now_ms();
        if let Some(entry) = self.announce_table.get(&announce.address_hash) {
            let elapsed_secs = (now - entry.received_at_ms) / 1000;
            if elapsed_secs < (1000 / self.config.announce_rate_limit as u64) {
                return Ok(()); // Rate limited, drop silently
            }
        }

        // Update path table
        let is_new_path = !self.path_table.contains_key(&announce.address_hash);
        let path_entry = PathEntry {
            destination_hash: announce.address_hash,
            next_hop_interface: interface_index,
            hops: packet.hops,
            expires_at_ms: now + (self.config.path_expiry_secs * 1000),
            announce_packet: packet.pack()?,
        };
        self.path_table.insert(announce.address_hash, path_entry);

        // Update announce table
        self.announce_table.insert(announce.address_hash, AnnounceEntry {
            destination_hash: announce.address_hash,
            received_at_ms: now,
            retransmit_at_ms: if self.config.enable_transport {
                Some(now + self.calculate_retransmit_delay(packet.hops))
            } else {
                None
            },
            hops: packet.hops,
        });

        // Emit event
        if is_new_path {
            self.events.push(TransportEvent::PathFound {
                destination_hash: announce.address_hash,
                hops: packet.hops,
            });
        }
        self.events.push(TransportEvent::AnnounceReceived(announce));

        Ok(())
    }

    fn handle_link_request(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        // TODO: Create incoming link, emit event
        Ok(())
    }

    fn handle_proof(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        // TODO: Match to pending link, emit event
        Ok(())
    }

    fn handle_data(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        // Check if we have this destination registered
        if self.destinations.contains_key(&packet.destination_hash) {
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: packet.destination_hash,
                packet,
            });
        } else if self.config.enable_transport {
            // Forward packet (we're a router)
            self.forward_packet(packet)?;
        }
        Ok(())
    }

    fn send_on_all_interfaces(&mut self, packet: &Packet) -> Result<(), TransportError> {
        let data = packet.pack()?;
        for iface in self.interfaces.iter_mut().flatten() {
            let _ = iface.send(&data); // Best effort on each interface
        }
        Ok(())
    }

    fn forward_packet(&mut self, mut packet: Packet) -> Result<(), TransportError> {
        packet.hops = packet.hops.saturating_add(1);
        if packet.hops > self.config.max_hops {
            return Ok(()); // TTL exceeded, drop
        }
        self.send(packet)
    }

    fn expire_paths(&mut self, now: u64) {
        let expired: Vec<_> = self.path_table
            .iter()
            .filter(|(_, p)| p.expires_at_ms < now)
            .map(|(k, _)| *k)
            .collect();

        for hash in expired {
            self.path_table.remove(&hash);
            self.events.push(TransportEvent::PathLost {
                destination_hash: hash,
            });
        }
    }

    fn process_announce_retransmissions(&mut self, now: u64) {
        // TODO: Retransmit announces if we're a transport node
    }

    fn calculate_retransmit_delay(&self, hops: u8) -> u64 {
        // Longer delay for closer announces (they'll spread faster)
        (hops as u64 + 1) * 1000
    }
}

#[derive(Debug)]
pub enum TransportError {
    NoPath,
    PacketError(crate::packet::PacketError),
    AnnounceError(crate::announce::AnnounceError),
    Interface(InterfaceError),
}
```

## Destination Types (reticulum-core/src/destination.rs)

```rust
//! Destination types with compile-time type safety
//!
//! Only InboundSingle can announce (enforced at compile time).

use core::marker::PhantomData;
use alloc::string::String;
use alloc::vec::Vec;

use crate::identity::Identity;
use crate::packet::Packet;
use crate::traits::Rng;

/// Direction markers
pub struct Inbound;
pub struct Outbound;

/// Type markers
pub struct Single;
pub struct Group;
pub struct Plain;

/// Common destination trait
pub trait DestinationBase {
    fn hash(&self) -> &[u8; 16];
    fn name_hash(&self) -> &[u8; 10];
}

/// Marker trait for destinations that can announce
pub trait CanAnnounce: DestinationBase {
    fn identity(&self) -> &Identity;
    fn create_announce<R: Rng>(
        &self,
        rng: &mut R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, crate::packet::PacketError>;
}

/// A typed destination
pub struct Destination<Dir, Type> {
    identity: Identity,
    name_hash: [u8; 10],
    address_hash: [u8; 16],
    app_name: String,
    aspects: Vec<String>,
    _phantom: PhantomData<(Dir, Type)>,
}

/// Inbound Single - can receive packets AND announce
pub type InboundSingle = Destination<Inbound, Single>;

/// Outbound Single - can only send to (from received announce)
pub type OutboundSingle = Destination<Outbound, Single>;

impl InboundSingle {
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let name_hash = compute_name_hash(app_name, aspects);
        let address_hash = compute_address_hash(&name_hash, identity.hash());
        Self {
            identity,
            name_hash,
            address_hash,
            app_name: app_name.into(),
            aspects: aspects.iter().map(|s| (*s).into()).collect(),
            _phantom: PhantomData,
        }
    }
}

impl DestinationBase for InboundSingle {
    fn hash(&self) -> &[u8; 16] { &self.address_hash }
    fn name_hash(&self) -> &[u8; 10] { &self.name_hash }
}

impl CanAnnounce for InboundSingle {
    fn identity(&self) -> &Identity { &self.identity }

    fn create_announce<R: Rng>(
        &self,
        rng: &mut R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, crate::packet::PacketError> {
        crate::announce::create_announce_packet(
            &self.address_hash,
            &self.name_hash,
            &self.identity,
            rng,
            app_data,
        )
    }
}

impl OutboundSingle {
    /// Create from a received announce
    pub fn from_announce(announce: &crate::announce::ReceivedAnnounce) -> Self {
        Self {
            identity: announce.identity.clone(),
            name_hash: announce.name_hash,
            address_hash: announce.address_hash,
            app_name: String::new(),
            aspects: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

impl DestinationBase for OutboundSingle {
    fn hash(&self) -> &[u8; 16] { &self.address_hash }
    fn name_hash(&self) -> &[u8; 10] { &self.name_hash }
}

// OutboundSingle does NOT implement CanAnnounce - compile error if you try!

fn compute_name_hash(app_name: &str, aspects: &[&str]) -> [u8; 10] {
    // Implementation: SHA256 of app_name.aspect1.aspect2...
    todo!()
}

fn compute_address_hash(name_hash: &[u8; 10], identity_hash: &[u8; 16]) -> [u8; 16] {
    // Implementation: truncated_hash(name_hash + identity_hash)
    todo!()
}
```

## Platform Implementation Example (reticulum-std)

```rust
// reticulum-std/src/clock.rs
use reticulum_core::traits::Clock;
use std::time::Instant;

pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

// reticulum-std/src/storage.rs
use reticulum_core::traits::Storage;
use std::path::PathBuf;

pub struct FileStorage {
    base_path: PathBuf,
}

impl Storage for FileStorage {
    fn load(&self, category: &str, key: &[u8]) -> Option<Vec<u8>> {
        let path = self.base_path.join(category).join(hex::encode(key));
        std::fs::read(path).ok()
    }

    fn store(&mut self, category: &str, key: &[u8], value: &[u8]) -> Result<(), ()> {
        let dir = self.base_path.join(category);
        std::fs::create_dir_all(&dir).map_err(|_| ())?;
        std::fs::write(dir.join(hex::encode(key)), value).map_err(|_| ())
    }

    // ... etc
}

// reticulum-std/src/interfaces/tcp.rs
use reticulum_core::traits::{Interface, InterfaceError};
use std::net::TcpStream;

pub struct TcpClientInterface {
    stream: TcpStream,
    name: String,
    hash: [u8; 16],
}

impl Interface for TcpClientInterface {
    fn name(&self) -> &str { &self.name }
    fn mtu(&self) -> usize { 1500 }
    fn hash(&self) -> [u8; 16] { self.hash }

    fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        use std::io::Write;
        // Add HDLC framing
        let framed = hdlc::frame(data);
        self.stream.write_all(&framed).map_err(|_| InterfaceError::Disconnected)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, InterfaceError> {
        use std::io::Read;
        self.stream.set_nonblocking(true).ok();
        match self.stream.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(InterfaceError::WouldBlock)
            }
            Err(_) => Err(InterfaceError::Disconnected),
        }
    }

    fn is_online(&self) -> bool { true }
}
```

## Usage Example

```rust
// Works on both std and no_std!
use reticulum_core::{Identity, InboundSingle, Transport, TransportConfig, TransportEvent};

fn run<C: Clock, S: Storage, R: Rng>(
    clock: C,
    storage: S,
    rng: &mut R,
    interface: impl Interface,
) {
    // Create transport
    let identity = Identity::new_with_rng(rng);
    let mut transport = Transport::new(
        TransportConfig::default(),
        clock,
        storage,
        identity.clone(),
    );

    // Register interface
    let iface_idx = transport.register_interface(Box::new(interface));

    // Create and register destination
    let dest = InboundSingle::new(identity, "myapp", &["echo", "server"]);
    transport.register_destination(&dest);

    // Announce ourselves
    transport.announce(rng, &dest, Some(b"ready")).unwrap();

    // Main loop
    loop {
        // Poll interfaces (platform-specific)
        let mut buf = [0u8; 1500];
        // ... read from interface into buf ...

        // Process incoming
        if let Ok(n) = /* interface.recv(&mut buf) */ Ok(0usize) {
            if n > 0 {
                transport.process_incoming(iface_idx, &buf[..n]).ok();
            }
        }

        // Handle events
        for event in transport.drain_events() {
            match event {
                TransportEvent::AnnounceReceived(ann) => {
                    println!("Discovered: {:?}", ann.address_hash);
                }
                TransportEvent::PacketReceived { packet, .. } => {
                    println!("Got packet: {:?}", packet);
                }
                _ => {}
            }
        }

        // Periodic tasks
        transport.poll();
    }
}
```

## Migration Plan

### Phase 1: Add Traits
1. Create `reticulum-core/src/traits.rs` with Interface, Clock, Storage, Rng
2. Add `NoStorage` implementation
3. Update Cargo.toml for alloc feature

### Phase 2: Move/Create Announce Logic
1. Create `reticulum-core/src/announce.rs`
2. Move announce packet creation from tests
3. Add `ReceivedAnnounce::from_packet()` validation
4. Add announce to Destination types

### Phase 3: Create Transport in Core
1. Create `reticulum-core/src/transport.rs`
2. Implement path table, announce table
3. Implement packet routing
4. Implement event system

### Phase 4: Refactor reticulum-std
1. Implement Clock, Storage traits
2. Refactor interfaces to implement Interface trait
3. Create async wrapper around sync Transport
4. Update CLI tools

### Phase 5: Testing
1. Unit tests for Transport in core
2. Integration tests against rnsd
3. Test on actual embedded hardware (if available)

## Open Questions

1. **Async in core?** Current design is sync/polling. Could use `core::future` for optional async.

2. **Buffer allocation?** Currently uses `Vec`. Could add `heapless` support for truly no-alloc.

3. **Interface ownership?** Currently `Box<dyn Interface>`. Could use generics or arena allocation.

4. **Event delivery?** Currently a `Vec` that's drained. Could use a ring buffer or callback.
