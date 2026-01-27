# Announce API Design

Draft design for the leviculum announce API.

## Goals

1. Clean separation: `reticulum-core` (no_std) vs `reticulum-std` (networking)
2. Type-safe: only valid destinations can announce (compile-time)
3. Ergonomic: simple common case, flexible advanced case
4. Rust-idiomatic: channels over callbacks, builders for options

## Core Layer (reticulum-core)

### Destination Types

```rust
/// Direction marker types
pub struct Inbound;
pub struct Outbound;

/// Destination type markers
pub struct Single;
pub struct Group;
pub struct Plain;

/// A network destination with compile-time type safety
pub struct Destination<Dir, Type> {
    identity: Identity,
    name_hash: [u8; NAME_HASH_LENGTH],
    address_hash: [u8; TRUNCATED_HASHBYTES],
    app_name: heapless::String<64>,
    aspects: heapless::Vec<heapless::String<32>, 8>,
    _phantom: PhantomData<(Dir, Type)>,
}

/// Type aliases for common destination types
pub type InboundSingle = Destination<Inbound, Single>;
pub type OutboundSingle = Destination<Outbound, Single>;
```

### Creating Destinations

```rust
impl<Dir, Type> Destination<Dir, Type> {
    /// Compute the address hash for this destination
    pub fn hash(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.address_hash
    }

    /// Get the identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

impl InboundSingle {
    /// Create a new inbound single destination (can receive and announce)
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

impl OutboundSingle {
    /// Create from a received announce (for connecting to remote destinations)
    pub fn from_announce(announce: &ReceivedAnnounce) -> Self {
        Self {
            identity: announce.identity.clone(),
            name_hash: announce.name_hash,
            address_hash: announce.address_hash,
            app_name: heapless::String::new(),  // unknown
            aspects: heapless::Vec::new(),       // unknown
            _phantom: PhantomData,
        }
    }
}
```

### Creating Announce Packets

Only `InboundSingle` destinations can create announces (enforced at compile time):

```rust
impl InboundSingle {
    /// Create an announce packet (core only creates the packet, doesn't send)
    pub fn create_announce(&self, app_data: Option<&[u8]>) -> Result<Packet, PacketError> {
        self.create_announce_with_rng(&mut OsRng, app_data)
    }

    /// Create announce with custom RNG (for testing/no_std)
    pub fn create_announce_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, PacketError> {
        // Generate random hash (5 random bytes + 5 timestamp bytes)
        let random_hash = generate_random_hash(rng);

        // Build signed data: dest_hash + pub_keys + name_hash + random_hash + app_data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&self.address_hash);
        signed_data.extend_from_slice(self.identity.public_key_bytes());
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&random_hash);
        if let Some(data) = app_data {
            signed_data.extend_from_slice(data);
        }

        // Sign
        let signature = self.identity.sign(&signed_data);

        // Build announce payload: pub_keys + name_hash + random_hash + signature + app_data
        let mut payload = Vec::new();
        payload.extend_from_slice(self.identity.public_key_bytes());  // 64 bytes
        payload.extend_from_slice(&self.name_hash);                    // 10 bytes
        payload.extend_from_slice(&random_hash);                       // 10 bytes
        payload.extend_from_slice(&signature);                         // 64 bytes
        if let Some(data) = app_data {
            payload.extend_from_slice(data);
        }

        // Create packet
        Ok(Packet {
            flags: PacketFlags {
                header_type: HeaderType::Type1,
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                transport_type: TransportType::Broadcast,
                ..Default::default()
            },
            hops: 0,
            destination_hash: self.address_hash,
            context: PacketContext::None,
            data: payload,
        })
    }
}
```

### Parsing Received Announces

```rust
/// A validated announce received from the network
#[derive(Debug, Clone)]
pub struct ReceivedAnnounce {
    pub address_hash: [u8; TRUNCATED_HASHBYTES],
    pub identity: Identity,  // public keys only
    pub name_hash: [u8; NAME_HASH_LENGTH],
    pub random_hash: [u8; RANDOM_HASH_LENGTH],
    pub app_data: Vec<u8>,
    pub hops: u8,
}

impl ReceivedAnnounce {
    /// Parse and validate an announce packet
    /// Returns None if signature verification fails
    pub fn from_packet(packet: &Packet) -> Result<Self, AnnounceError> {
        if packet.flags.packet_type != PacketType::Announce {
            return Err(AnnounceError::NotAnnounce);
        }

        if packet.data.len() < MIN_ANNOUNCE_LENGTH {
            return Err(AnnounceError::TooShort);
        }

        // Parse fields
        let public_keys = &packet.data[0..64];
        let name_hash = &packet.data[64..74];
        let random_hash = &packet.data[74..84];
        let signature = &packet.data[84..148];
        let app_data = &packet.data[148..];

        // Reconstruct identity from public keys
        let identity = Identity::from_public_key_bytes(public_keys)?;

        // Verify signature
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&packet.destination_hash);
        signed_data.extend_from_slice(public_keys);
        signed_data.extend_from_slice(name_hash);
        signed_data.extend_from_slice(random_hash);
        signed_data.extend_from_slice(app_data);

        if !identity.verify(&signed_data, signature) {
            return Err(AnnounceError::InvalidSignature);
        }

        Ok(Self {
            address_hash: packet.destination_hash,
            identity,
            name_hash: name_hash.try_into().unwrap(),
            random_hash: random_hash.try_into().unwrap(),
            app_data: app_data.to_vec(),
            hops: packet.hops,
        })
    }
}

#[derive(Debug)]
pub enum AnnounceError {
    NotAnnounce,
    TooShort,
    InvalidSignature,
    InvalidPublicKey,
}
```

## Std Layer (reticulum-std)

### Transport - Sending Announces

```rust
impl Transport {
    /// Send an announce for a destination
    pub async fn announce(
        &self,
        destination: &InboundSingle,
        app_data: Option<&[u8]>,
    ) -> Result<(), TransportError> {
        let packet = destination.create_announce(app_data)?;
        self.send_packet(packet).await
    }

    /// Send an announce on a specific interface only
    pub async fn announce_on(
        &self,
        destination: &InboundSingle,
        app_data: Option<&[u8]>,
        interface: &dyn Interface,
    ) -> Result<(), TransportError> {
        let packet = destination.create_announce(app_data)?;
        self.send_packet_on(packet, interface).await
    }
}
```

### Transport - Receiving Announces

```rust
use tokio::sync::broadcast;

/// Event emitted when an announce is received
#[derive(Debug, Clone)]
pub struct AnnounceEvent {
    pub announce: ReceivedAnnounce,
    pub received_at: Instant,
    pub interface_hash: [u8; TRUNCATED_HASHBYTES],
}

impl Transport {
    /// Subscribe to all announces
    pub fn subscribe_announces(&self) -> AnnounceSubscription {
        AnnounceSubscription {
            receiver: self.announce_tx.subscribe(),
            filter: None,
        }
    }
}

/// A subscription to announce events with optional filtering
pub struct AnnounceSubscription {
    receiver: broadcast::Receiver<AnnounceEvent>,
    filter: Option<AnnounceFilter>,
}

impl AnnounceSubscription {
    /// Filter by app name and aspects (dot-separated)
    /// Example: "myapp.service.v1"
    pub fn filter_aspect(mut self, aspect: &str) -> Self {
        self.filter = Some(AnnounceFilter::Aspect(compute_name_hash_from_str(aspect)));
        self
    }

    /// Filter by specific destination hash
    pub fn filter_destination(mut self, hash: [u8; TRUNCATED_HASHBYTES]) -> Self {
        self.filter = Some(AnnounceFilter::Destination(hash));
        self
    }

    /// Receive the next matching announce
    pub async fn recv(&mut self) -> Result<AnnounceEvent, RecvError> {
        loop {
            let event = self.receiver.recv().await?;
            if self.matches(&event) {
                return Ok(event);
            }
        }
    }

    fn matches(&self, event: &AnnounceEvent) -> bool {
        match &self.filter {
            None => true,
            Some(AnnounceFilter::Aspect(hash)) => event.announce.name_hash == *hash,
            Some(AnnounceFilter::Destination(hash)) => event.announce.address_hash == *hash,
        }
    }
}

enum AnnounceFilter {
    Aspect([u8; NAME_HASH_LENGTH]),
    Destination([u8; TRUNCATED_HASHBYTES]),
}
```

## Usage Examples

### Server: Announce a Service

```rust
use reticulum_core::{Identity, InboundSingle};
use reticulum_std::Transport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create transport
    let transport = Transport::new(config).await?;

    // Create identity and destination
    let identity = Identity::new();
    let destination = InboundSingle::new(identity, "myapp", &["echo", "server"]);

    println!("Destination hash: {}", hex::encode(destination.hash()));

    // Announce periodically
    loop {
        transport.announce(&destination, Some(b"status:ready")).await?;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
```

### Client: Discover Services

```rust
use reticulum_core::OutboundSingle;
use reticulum_std::Transport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let transport = Transport::new(config).await?;

    // Subscribe to announces for our service
    let mut announces = transport
        .subscribe_announces()
        .filter_aspect("myapp.echo.server");

    println!("Waiting for server...");

    // Wait for first announce
    let event = announces.recv().await?;
    println!("Found server: {}", hex::encode(&event.announce.address_hash));

    if let Some(status) = event.announce.app_data.as_slice().strip_prefix(b"status:") {
        println!("Status: {}", String::from_utf8_lossy(status));
    }

    // Create outbound destination for linking
    let server = OutboundSingle::from_announce(&event.announce);

    // Now we can establish a link...
    let link = transport.create_link(&server).await?;

    Ok(())
}
```

### Advanced: Multiple Filters

```rust
// Subscribe to all announces (no filter)
let mut all = transport.subscribe_announces();

// Subscribe to specific service
let mut service = transport
    .subscribe_announces()
    .filter_aspect("myapp.echo");

// Subscribe to known destination
let mut known = transport
    .subscribe_announces()
    .filter_destination(known_hash);

// Process in separate tasks
tokio::spawn(async move {
    while let Ok(event) = all.recv().await {
        log::debug!("Any announce: {:?}", event.announce.address_hash);
    }
});

tokio::spawn(async move {
    while let Ok(event) = service.recv().await {
        log::info!("Service online: {:?}", event.announce.address_hash);
    }
});
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum AnnounceError {
    #[error("packet is not an announce")]
    NotAnnounce,

    #[error("announce too short: {0} bytes")]
    TooShort(usize),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("announce rate limited")]
    RateLimited,
}
```

## Implementation Plan

### Phase 1: Core Types
1. Add `Destination<Dir, Type>` with type-state pattern to `reticulum-core`
2. Add `InboundSingle::create_announce()` method
3. Add `ReceivedAnnounce::from_packet()` parser
4. Unit tests with test vectors

### Phase 2: Transport Integration
1. Add `announce_tx: broadcast::Sender<AnnounceEvent>` to Transport
2. Add `Transport::announce()` method
3. Add `Transport::subscribe_announces()` method
4. Add `AnnounceSubscription` with filtering
5. Integration tests against rnsd

### Phase 3: Rate Limiting & Retransmission
1. Add announce rate limiting (per source)
2. Add announce table for multi-hop retransmission
3. Add path table updates from announces

## Open Questions

1. **Ratchet support?** Python supports ratcheted announces for forward secrecy.
   Should we add this now or later?

2. **Path responses?** Announces can be sent as path responses.
   Add `create_path_response()` variant?

3. **Announce persistence?** Should we persist known destinations to disk?
   Python does this in `~/.reticulum/storage/`.

4. **no_std allocations?** Current design uses `Vec` in core.
   Should we use `heapless` for full no_std support?
