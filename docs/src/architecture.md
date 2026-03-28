# Architecture

Leviculum follows an embedded-first, sans-I/O design. All protocol logic lives in `reticulum-core` as a pure state machine that never performs I/O directly. Platform glue (networking, storage, timers) lives in `reticulum-std`.

## Crate hierarchy

```
reticulum-core (no_std + alloc)  ← all protocol logic, embedded-compatible
    │
    ▼
reticulum-std (std)              ← interfaces: Clock, Storage, RNG, TCP, UDP, LoRa
    │
    ▼
reticulum-cli                    ← binaries: lnsd, lns, lncp
```

`reticulum-core` accepts packets via `handle_packet()` and returns `Action` values for the driver to execute. It never touches the network.

## Sans-I/O core

```
                     ┌─────────────────────────────────┐
                     │         reticulum-core           │
                     │                                  │
  handle_packet() ──►│  NodeCore<R, C, S>               │──► TickOutput {
  (iface_id, data)   │    ├── Transport (routing)       │      actions: Vec<Action>,
                     │    ├── Links + Channels           │      events: Vec<NodeEvent>,
  handle_timeout() ─►│    └── Destinations              │    }
                     │                                  │
  next_deadline() ──►│  Returns: Option<u64>            │
                     └─────────────────────────────────┘
```

## Interfaces

| Interface | Transport | Framing |
|-----------|-----------|---------|
| TCP | TCP stream | HDLC |
| UDP | UDP datagram | None |
| LocalInterface | Unix abstract socket | HDLC |
| AutoInterface | IPv6 multicast + unicast UDP | None |
| RNode | Serial (USB-CDC) to LoRa radio | KISS |

## Further reading

See the `doc/` directory in the repository for detailed driver internals and RNode protocol research.
