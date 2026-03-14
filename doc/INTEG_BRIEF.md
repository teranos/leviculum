# leviculum Integration Test Framework — Agent Briefing

## Read First

conventions, and architecture rules. This document describes a NEW component you
will build: a Docker-based integration test framework for testing Rust and Python
Reticulum nodes together.

---

## Why This Exists

leviculum (`lrnsd`) is a Rust reimplementation of the Python Reticulum mesh
networking daemon (`rnsd`). It must be wire-compatible with Python nodes.

Every bug found in the past weeks was discovered through hours of manual debugging
on live machines — SSH into hamster, restart lrnsd, SSH into schneckenschreck,
run rnprobe, read logs, repeat. The agent (you) got lost repeatedly because:

- Live networks have timing-dependent behavior (which node announces first?)
- Multiple machines with different Python versions caused false positives
- No way to reproduce a specific scenario deterministically
- Debugging required coordinating state across 3 physical machines

This framework eliminates all of that. You define a network topology in TOML,
the framework spins up Docker containers, and runs assertions. Red/green. Done.

### Bugs this framework would have caught immediately

| Bug | Scenario |
|-----|----------|
| Hop count 0 instead of 1 for direct neighbor | Probe through shared instance, check hops |
| Announce forwarding with wrong Header/transport_id | Probe through relay, verify proof returns |
| Random blob replay blocking better paths | Restart node, verify path improves after announce |
| Announce cache cleanup deleting local entries | Probe to local destination after cleanup timer |
| Path request response excluding the requester | Path request through relay, check hop count |
| 2-hop path not replaced by 1-hop direct announce | Start all nodes, wait for announces, check hops |

---

## Architecture Overview

```
reticulum-integ/
├── Dockerfile                # Base image: Debian + Python + RNS + lrnsd
├── entrypoint.sh             # Starts rnsd or lrnsd based on NODE_TYPE env
├── src/
│   ├── main.rs               # CLI: parse TOML, run test
│   ├── topology.rs           # TOML parser → config generation
│   ├── compose.rs            # Generates docker-compose.yml
│   ├── runner.rs             # Container lifecycle, readiness, log collection
│   └── steps.rs              # Step executor (rnprobe, rnpath, wait_for_path, etc.)
├── tests/
│   ├── basic_probe.toml      # First test: probe direct neighbor
│   ├── probe_through_relay.toml
│   ├── path_self_healing.toml
│   └── integration_tests.rs  # #[test] functions that run TOML scenarios
└── Cargo.toml
```

### Flow

1. Parse TOML test definition
2. Generate transport identities for all nodes (deterministic from node name)
3. Compute probe destination hashes from identities
4. Generate `~/.reticulum/config` files for each node
5. Write `docker-compose.yml`
6. `docker compose up -d`
7. Wait for all nodes to be ready (poll TCP ports or Unix sockets)
8. Execute `[[steps]]` sequentially via `docker exec`
9. On failure: collect `docker compose logs` into a file
10. `docker compose down`

---

## Docker Setup

### Base Image

One image for both Python and Rust nodes. Debian Bookworm based.

```dockerfile
FROM debian:bookworm-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    iproute2 iputils-ping net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python Reticulum from vendor submodule (mounted at build or runtime)
# The vendor directory is bind-mounted, not copied, for fast iteration.
# At container start, entrypoint.sh installs RNS if not cached.

# Create reticulum config directory
RUN mkdir -p /root/.reticulum/storage

# lrnsd binary is bind-mounted at /usr/local/bin/lrnsd

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

### Entrypoint

```bash
#!/bin/bash
set -e

# Install RNS from mounted vendor dir if available
if [ -d /opt/vendor/Reticulum ] && ! python3 -c "import RNS" 2>/dev/null; then
    pip3 install --break-system-packages /opt/vendor/Reticulum
fi

case "${NODE_TYPE}" in
    rust)
        exec /usr/local/bin/lrnsd -v --config /root/.reticulum
        ;;
    python)
        exec python3 -m RNS.Utilities.rnsd -v --config /root/.reticulum
        ;;
    *)
        echo "Unknown NODE_TYPE: ${NODE_TYPE}" >&2
        exit 1
        ;;
esac
```

### Volume Mounts (per container)

| Host path | Container path | Purpose |
|-----------|---------------|---------|
| `./target/release/lrnsd` | `/usr/local/bin/lrnsd` | Rust daemon binary (read-only) |
| `./target/release/lrns` | `/usr/local/bin/lrns` | Rust CLI binary (read-only, for selftest) |
| `./vendor/Reticulum` | `/opt/vendor/Reticulum` | Python RNS source (read-only) |
| `{tempdir}/{node_name}/config` | `/root/.reticulum/config` | Generated config |
| `{tempdir}/{node_name}/storage/` | `/root/.reticulum/storage/` | Identity files |

---

## TOML Test Definition Format

### Minimal Example

```toml
[test]
name = "basic_probe"
description = "Two nodes, direct TCP link, probe each other"
timeout_secs = 60

[nodes.alice]
type = "rust"
respond_to_probes = true

[nodes.bob]
type = "python"
respond_to_probes = true

[links]
alice-bob = "tcp"

[[steps]]
action = "wait_for_path"
on = "alice"
destination = "bob.probe"
timeout_secs = 30

[[steps]]
action = "rnprobe"
from = "alice"
to = "bob.probe"
expect_hops = 1
expect_result = "success"
```

### Node Definition

```toml
[nodes.<name>]
type = "rust"              # Required: "rust" or "python"
respond_to_probes = true   # Optional, default false
enable_transport = true    # Optional, default true
```

All nodes get `enable_transport = true` and `share_instance = yes` by default
(needed for rnprobe/rnpath to connect as shared instance clients).

### Links

```toml
[links]
alice-bob = "tcp"       # TCP connection between alice and bob
bob-charlie = "tcp"     # Can chain for relay topologies
```

The framework:
- Allocates TCP ports automatically
- Generates matching `[[TCPServerInterface]]` and `[[TCPClientInterface]]`
  entries in each node's config
- Convention: alphabetically first node gets the server, second gets the client

### LAN Segments (AutoInterface)

```toml
[lans.office]
members = ["alice", "bob", "charlie"]
```

Creates a Docker bridge network. All members are attached. Multicast discovery
works over Docker bridges, so AutoInterface finds peers automatically.
No config entries needed — AutoInterface is enabled by default in Reticulum.

### Steps

Steps execute sequentially after all nodes are ready. Any failure = test fails.

#### `wait_for_path`

Wait until a node knows how to reach a destination.

```toml
[[steps]]
action = "wait_for_path"
on = "alice"                    # Node to check
destination = "bob.probe"      # Symbolic reference
timeout_secs = 30              # Fail if not found in time
```

Implementation: repeatedly run `rnpath <hash>` via `docker exec` until it
returns a path or timeout expires.

#### `rnprobe`

Send a probe and verify the result.

```toml
[[steps]]
action = "rnprobe"
from = "alice"                  # Run rnprobe on this node
to = "bob.probe"                # Target destination
expect_hops = 2                 # Expected hop count
expect_result = "success"       # "success" or "timeout"
timeout_secs = 15               # Optional, default 15
```

Implementation: `docker exec` runs rnprobe as shared instance client. Parse
stdout for "over N hops". Assert hops and success/failure.

#### `rnpath`

Check path table entry.

```toml
[[steps]]
action = "rnpath"
on = "alice"
destination = "bob.probe"
expect_min_hops = 1
expect_max_hops = 1
```

#### `rnstatus`

Verify node is running as transport instance.

```toml
[[steps]]
action = "rnstatus"
on = "alice"
expect_transport = true
```

#### `exec`

Escape hatch for custom commands.

```toml
[[steps]]
action = "exec"
on = "alice"
command = "rnpath -t"
expect_exit_code = 0
expect_stdout_contains = "hops"
```

#### `sleep`

Wait a fixed duration (use sparingly — prefer `wait_for_path`).

```toml
[[steps]]
action = "sleep"
duration_secs = 20
```

#### `restart`

Restart a node (for testing path recovery, announce re-propagation).

```toml
[[steps]]
action = "restart"
node = "alice"
```

#### `file_transfer`

Transfer files between nodes using `lrncp` or `rncp`, with md5sum verification
and timing measurement.

```toml
[[steps]]
action = "file_transfer"
sender = "alpha"
receiver = "charlie"
sender_tool = "lrncp"       # "lrncp" or "rncp"
receiver_tool = "rncp"      # "lrncp" or "rncp"
file_sizes = [102400, 1048576]  # bytes
direction = "both"          # "a_to_b", "b_to_a", or "both"
repeats = 3                 # runs per size per direction
timeout_secs = 300
mode = "push"               # "push" (default) or "fetch"
receiver_flags = ""         # extra flags for listener (e.g., "-F -n", "-F -j /tmp/jail")
sender_flags = ""           # extra flags for sender
auth_from = ""              # node whose identity hash is used for -a on the listener
expect_result = "success"   # "success" (default) or "failure"
fetch_path = ""             # override remote file path for fetch requests
```

The step:
1. If `auth_from` is set, runs `<tool> -p` on that node to get its identity hash
2. Runs `<tool> -p` on the receiver to get the destination hash
3. Starts a detached listener (`<tool> -l [-a <hash>] [receiver_flags] -s /tmp/received -b 0`)
4. Waits for path availability on the sender via `rnpath`
5. For each file size × repeat: creates a random file with `dd`, sends it,
   verifies md5sum on the receiver, and records transfer time
6. Prints a summary table with per-run and average times

### Symbolic References

`bob.probe` resolves at runtime to the hex hash of bob's probe destination.
The framework computes this from bob's transport identity:

```
probe_hash = SHA256("rnstransport" + "." + "probe" + bob_identity_hash)[:16]
```

The identity is generated deterministically per test (seeded from node name)
or pre-generated and written to the storage directory.

---

## Config Generation

For each node, the framework generates a Reticulum INI config file.

### Python node example (bob, TCP client to alice)

```ini
[reticulum]
  enable_transport = yes
  share_instance = yes
  respond_to_probes = yes

[logging]
  loglevel = 5

[interfaces]
  [[TCPClientInterface]]
    type = TCPClientInterface
    enabled = yes
    target_host = alice
    target_port = 4242
```

### Rust node example (alice, TCP server)

```ini
[reticulum]
  enable_transport = yes
  share_instance = yes
  respond_to_probes = yes

[logging]
  loglevel = 5

[interfaces]
  [[TCPServerInterface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4242
```

Docker Compose service names are used as hostnames (`alice`, `bob`, etc.).
This means TCP interfaces can reference other nodes by name directly.

---

## Readiness Detection

After `docker compose up -d`, the framework must wait until all nodes are ready
before executing steps.

### Strategy

Poll each container every 500ms:

1. **For all nodes**: `docker exec <container> rnstatus --config /root/.reticulum`
   returns exit code 0 when the shared instance socket is accepting connections.

2. **Timeout**: If a node isn't ready within 30 seconds, fail the test and
   collect logs.

---

## Log Collection on Failure

When a step fails:

1. Run `docker compose logs --no-color > {test_name}_failure.log`
2. Print the failing step and assertion to stderr
3. Keep containers running for 5 seconds (for manual inspection if running
   interactively), then `docker compose down`

---

## Implementation Steps

Build these in order. Each step should compile and be testable before moving on.

### Step 1: Dockerfile + entrypoint.sh

Create the base Docker image. Test manually:

```bash
docker build -t reticulum-test .
docker run --rm -e NODE_TYPE=python \
  -v ./vendor/Reticulum:/opt/vendor/Reticulum:ro \
  -v /tmp/test-config:/root/.reticulum:ro \
  reticulum-test
```

Verify: Python rnsd starts and listens on the shared instance socket.

### Step 2: TOML parser + config generator

Parse the TOML format. Generate identity files and config files for each node
into a temp directory. No Docker yet — just file generation.

Test: parse `basic_probe.toml`, inspect generated files.

### Step 3: Docker Compose generator

From the parsed topology, generate a `docker-compose.yml` with:
- One service per node
- Correct environment variables, volume mounts, network attachments
- TCP port mappings (internal only — containers talk to each other)

Test: generate compose file, `docker compose config` validates it.

### Step 4: Lifecycle runner

Implement `docker compose up`, readiness polling, and `docker compose down`.
Log collection on failure.

Test: start a 2-node topology, verify both become ready, tear down.

### Step 5: Step executor

Implement each step action. Start with `wait_for_path` and `rnprobe` — these
cover the most important test scenarios.

Test: run `basic_probe.toml` end-to-end.

### Step 6: First real test

Write `probe_through_relay.toml`:

```toml
[test]
name = "probe_through_relay"
description = "Probe from A through relay R to B, verify 2 hops"
timeout_secs = 90

[nodes.alice]
type = "rust"
respond_to_probes = true

[nodes.relay]
type = "python"
respond_to_probes = false

[nodes.bob]
type = "rust"
respond_to_probes = true

[links]
alice-relay = "tcp"
relay-bob = "tcp"

[[steps]]
action = "wait_for_path"
on = "alice"
destination = "bob.probe"
timeout_secs = 30

[[steps]]
action = "rnprobe"
from = "alice"
to = "bob.probe"
expect_hops = 2
expect_result = "success"

[[steps]]
action = "rnprobe"
from = "bob"
to = "alice.probe"
expect_hops = 2
expect_result = "success"
```

### Step 7: Regression tests for known bugs

Write TOML tests for each bug from the table at the top of this document.
Most important: `path_self_healing.toml` — start 3 nodes, verify that after
announces propagate, direct paths have 1 hop even if relay paths arrived first.

---

## Important Technical Details

### Management Announce Timing

Reticulum nodes send their first management announce 15 seconds after startup,
then every 2 hours. For tests, this means:

- `wait_for_path` needs at least 20 seconds timeout for probe destinations
- Path requests can resolve paths faster (don't wait for announce)
- The `restart` action should account for the 15-second announce delay

### Python vs Rust rnprobe/rnpath

Always use the Python tools (`rnprobe`, `rnpath`, `rnstatus`) as shared instance
clients. They connect to the local daemon's Unix socket. Both Python and Rust
daemons support this. The Python tools are installed as part of the RNS package.

### Transport Identity

Each node needs a transport identity (X25519 + Ed25519 keypair). The framework
generates these and writes them to `{storage_dir}/transport_identity` (64 bytes:
32-byte X25519 private key + 32-byte Ed25519 private key). Both Python and Rust
read this file.

### Docker Networking

- TCP links: containers reference each other by Docker Compose service name
- LAN segments: Docker bridge networks with multicast enabled
- All containers are on a default network for Docker DNS resolution
- No host port mapping needed — everything is container-to-container

### lrnsd Binary

The test framework expects release builds of `lrnsd` and `lrns` at
`./target/release/lrnsd` and `./target/release/lrns` (relative to the repo
root). Build before running tests:

```bash
cargo build --release -p reticulum-cli
```

---

## Non-Goals (for now)

- **Chaos testing** (random network partitions, packet loss) — later
- **Performance benchmarks** — later
- **50+ node scale tests** — later, but the architecture supports it
- **GUI or web dashboard** — never
- **Windows support** — never

---

## Repo Location

This framework lives at `reticulum-integ/` in the leviculum workspace root.
Add it to the workspace `Cargo.toml`:

```toml
[workspace]
members = ["reticulum-core", "reticulum-std", "reticulum-integ"]
```

The `reticulum-integ` crate is a binary crate (not a library). It can also
be invoked via `cargo test -p reticulum-integ` for the integration test suite.
