# Chapter 13: Interoperability Testing

This chapter provides test vectors and guidance for testing your Reticulum implementation against the Python reference implementation.

## 13.1 Test Environment Setup

### Python RNS Installation

```bash
pip install rns

# Verify installation
rnsd --version
```

### Running rnsd for Testing

```bash
# Start with verbose logging
rnsd -v

# Or with specific config
rnsd -c /path/to/config
```

### Minimal Test Config

Create `~/.reticulum/config`:

```ini
[reticulum]
  enable_transport = Yes
  share_instance = Yes

[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = 4242
```

## 13.2 Cryptographic Test Vectors

### SHA-256

```
Input:  "" (empty)
Output: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Input:  "hello"
Output: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

Input:  "Reticulum"
Output: 0ad856791793677b9c73a9076c130009035d6bd14b54f16ae33325e286d3e97f
```

### Truncated Hash (First 16 Bytes)

```
Input:  "hello"
SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
Trunc:  2cf24dba5fb0a30e26e83b2ac5b9e29e
```

### HMAC-SHA256

```
Key:    0000000000000000000000000000000000000000000000000000000000000000 (32 zeros)
Data:   "hello"
HMAC:   82c7a445f7104cc78e4c0a61e2a652c33a31c7d7cc78c13b5c1e2e3aeb693b95
```

### X25519 Key Exchange

```
Alice Private: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
Alice Public:  8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a

Bob Private:   5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
Bob Public:    de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Shared Secret: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```

### Ed25519 Signatures

```
Private Seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
Public Key:   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

Message:      "" (empty)
Signature:    e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b

Message:      "hello"
Signature:    (compute with your implementation and verify against Python)
```

### HKDF-SHA256

```
Input Key Material: 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
Salt:               000102030405060708090a0b0c (13 bytes)
Info:               f0f1f2f3f4f5f6f7f8f9 (10 bytes)
Output Length:      42 bytes

Output: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
```

## 13.3 Packet Test Vectors

### Packet Header Parsing

```
Header Byte: 0x00
  IFAC:            0 (no interface auth)
  Header Type:     0 (type 1 - no transport)
  Propagation:     0 (broadcast)
  Destination Type: 0 (SINGLE)
  Packet Type:     0 (DATA)

Header Byte: 0x02
  IFAC:            0
  Header Type:     0
  Propagation:     0
  Destination Type: 0 (SINGLE)
  Packet Type:     2 (LINKREQUEST)

Header Byte: 0x0F
  IFAC:            0
  Header Type:     0
  Propagation:     0
  Destination Type: 3 (LINK)
  Packet Type:     3 (PROOF)

Header Byte: 0x41
  IFAC:            0
  Header Type:     1 (type 2 - with transport)
  Propagation:     0
  Destination Type: 0 (SINGLE)
  Packet Type:     1 (ANNOUNCE)
```

### HDLC Framing

```
Unframed: 00 01 02 03
Framed:   7e 00 01 02 03 7e

Unframed: 00 7e 01 7d 02
Framed:   7e 00 7d 5e 01 7d 5d 02 7e
          (7e escaped to 7d 5e, 7d escaped to 7d 5d)

Unframed: 7e 7e 7e
Framed:   7e 7d 5e 7d 5e 7d 5e 7e
```

## 13.4 Identity Test Vectors

### Identity Hash Computation

Given:
```
X25519 Public:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
Ed25519 Public: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
```

Computation:
```
Concatenated: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
              3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c

SHA256:       (compute full hash)
Identity Hash: (first 16 bytes)
```

### Destination Hash Computation

Given:
```
App Name:      "testapp"
Identity Hash: (16 bytes from above)
```

Computation:
```
Name Hash = SHA256("testapp")[0:10]
Dest Hash = SHA256(Name Hash || Identity Hash)[0:16]
```

## 13.5 Link Establishment Test Vectors

### Link ID Computation

Given a LINKREQUEST packet:
```
Header:        0x02
Hops:          0x00
Destination:   a1b2c3d4e5f6789012345678abcdef01
Context:       0x00
Payload:       [64 bytes: initiator X25519 pub + Ed25519 pub]
```

Link ID computation:
```
Header Meta = 0x02 & 0x0F = 0x02

Hash Input = [0x02] + [destination 16B] + [0x00] + [payload first 64B]

Link ID = SHA256(Hash Input)[0:16]
```

### Signed Data Format (83 Bytes)

For proof verification, the signed data is:
```
Offset  Size  Field
0       16    Link ID
16      32    Responder X25519 Public Key (from proof)
48      32    Responder Ed25519 Public Key (from destination)
80      3     Signalling bytes (from proof)
---
Total:  83 bytes
```

### Proof Packet Format (99 Bytes Payload)

```
Offset  Size  Field
0       64    Ed25519 Signature
64      32    Responder X25519 Public Key
96      3     Signalling bytes
---
Total:  99 bytes
```

## 13.6 Integration Test Script

### Python Test Destination

Create `test_destination.py`:

```python
#!/usr/bin/env python3
import RNS
import time
import sys

def packet_callback(data, packet):
    print(f"Received: {data.decode('utf-8', errors='replace')}")
    # Send response
    RNS.Packet(packet.destination, b"Response from Python").send()

def link_established(link):
    print(f"Link established: {RNS.prettyhexrep(link.link_id)}")
    link.set_packet_callback(link_packet_callback)

def link_packet_callback(data, packet):
    print(f"Link data: {data.decode('utf-8', errors='replace')}")

def main():
    reticulum = RNS.Reticulum()

    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "testapp",
        "receiver"
    )

    destination.set_packet_callback(packet_callback)
    destination.set_link_established_callback(link_established)

    print("=" * 60)
    print("Test Destination Running")
    print("=" * 60)
    print(f"Destination hash: {RNS.prettyhexrep(destination.hash)}")
    print(f"Signing key:      {identity.get_public_key().hex()[64:]}")
    print("=" * 60)
    print("Waiting for packets and link requests...")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        reticulum.exit_handler()

if __name__ == "__main__":
    main()
```

Run with:
```bash
python3 test_destination.py
```

### C Test Client

```c
// test_client.c
#include <stdio.h>
#include <string.h>
#include "reticulum.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dest_hash_hex> <signing_key_hex>\n", argv[0]);
        return 1;
    }

    // Parse destination hash
    uint8_t dest_hash[16];
    hex_to_bytes(argv[1], dest_hash, 16);

    // Parse signing key
    uint8_t signing_key[32];
    hex_to_bytes(argv[2], signing_key, 32);

    // Initialize
    rns_transport_t *transport = rns_transport_create();

    // Add TCP interface to rnsd
    rns_interface_t *tcp = rns_tcp_interface_create("127.0.0.1", 4242);
    rns_transport_add_interface(transport, tcp);

    // Create link
    rns_link_t *link = rns_link_create_to(dest_hash, signing_key);

    printf("Requesting link to %s...\n", argv[1]);

    // Wait for link establishment
    time_t start = time(NULL);
    while (link->state != LINK_ACTIVE && time(NULL) - start < 10) {
        rns_transport_poll(transport);
        usleep(10000);
    }

    if (link->state == LINK_ACTIVE) {
        printf("Link established!\n");
        printf("Link ID: %s\n", bytes_to_hex(link->id, 16));

        // Send test message
        rns_link_send(link, (uint8_t*)"Hello from C!", 13);

        // Wait for response
        sleep(2);

        printf("Test passed!\n");
        return 0;
    } else {
        fprintf(stderr, "Link establishment failed!\n");
        return 1;
    }
}
```

## 13.7 Common Issues and Debugging

### Link Proof Verification Fails

**Symptom**: Link never becomes active, proof rejected.

**Check**:
1. Signed data is exactly 83 bytes
2. Using responder's keys (from proof and destination), not initiator's
3. Signalling bytes included (3 bytes from end of proof)
4. Ed25519 verify is strict mode

```c
// WRONG: Using initiator's keys
signed_data = link_id + initiator_x25519 + initiator_ed25519 + signalling

// RIGHT: Using responder's keys
signed_data = link_id + responder_x25519 + responder_ed25519 + signalling
//                      ^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^
//                      (from proof)       (from destination)
```

### HDLC Deframing Issues

**Symptom**: Packets not recognized, garbage data.

**Check**:
1. Looking for 0x7E frame delimiters
2. Properly handling escape sequences (0x7D followed by XOR 0x20)
3. Not including delimiters in packet data

```c
// After 0x7D, XOR the next byte with 0x20
if (byte == 0x7D) {
    next_byte = read_byte();
    actual_byte = next_byte ^ 0x20;
}
```

### Encryption/Decryption Fails

**Symptom**: Fernet decrypt returns error, HMAC mismatch.

**Check**:
1. Key is correct length (32 or 64 bytes)
2. First half is HMAC key, second half is AES key
3. Version byte is 0x80
4. HMAC is verified before decryption
5. Padding removal is correct

### Path Table Not Populating

**Symptom**: Cannot route to announced destinations.

**Check**:
1. Announce signature verification passing
2. Destination hash derivation correct
3. Random blob extraction (bytes 74-84 of announce data)
4. Path entry not expired

## 13.8 Test Checklist

### Cryptographic Tests

- [ ] SHA-256 produces correct output for empty string
- [ ] SHA-256 produces correct output for "hello"
- [ ] Truncated hash is first 16 bytes
- [ ] HMAC-SHA256 matches test vector
- [ ] X25519 shared secret matches test vector
- [ ] Ed25519 signature verifies correctly
- [ ] HKDF output matches test vector
- [ ] Fernet encrypt/decrypt round-trips

### Packet Tests

- [ ] Header byte parsing correct
- [ ] HDLC framing correct
- [ ] HDLC deframing correct
- [ ] Escape sequences handled
- [ ] Packet parsing extracts correct fields

### Identity Tests

- [ ] Identity hash computation correct
- [ ] Destination hash computation correct
- [ ] Sign and verify round-trip works

### Link Tests

- [ ] Link ID computation correct
- [ ] Link request packet format correct
- [ ] Proof packet parsing correct (99 bytes)
- [ ] Signed data reconstruction correct (83 bytes)
- [ ] Proof verification passes
- [ ] Key derivation produces same key on both sides
- [ ] Encrypted data decrypts correctly

### Integration Tests

- [ ] Connect to Python rnsd via TCP
- [ ] Send packet to Python destination
- [ ] Receive packet from Python
- [ ] Establish link with Python destination
- [ ] Exchange encrypted data on link
- [ ] Keep-alive works
- [ ] Link closes gracefully

## 13.9 Packet Capture Analysis

### Using tcpdump

```bash
# Capture Reticulum traffic on localhost
tcpdump -i lo -X port 4242

# Save to file for analysis
tcpdump -i lo -w reticulum.pcap port 4242
```

### Using Wireshark

1. Capture on loopback interface
2. Filter: `tcp.port == 4242`
3. Follow TCP stream
4. Look for 0x7E frame delimiters

### Manual Packet Analysis

```
Raw TCP data:
7e 02 00 a1 b2 c3 d4 e5 f6 78 90 12 34 56 78 ab cd ef 01 00
[64 bytes of public keys]
7e

Breakdown:
7e          - HDLC start
02          - Header: LINKREQUEST
00          - Hops: 0
a1...01     - Destination hash (16 bytes)
00          - Context: NONE
[64B]       - Payload: initiator public keys
7e          - HDLC end
```

## 13.10 Automated Testing

### Test Runner Script

```bash
#!/bin/bash
# run_tests.sh

set -e

echo "Starting Python test destination..."
python3 test_destination.py &
PYTHON_PID=$!
sleep 2

echo "Running C tests..."
./test_client $(cat /tmp/dest_hash) $(cat /tmp/signing_key)
TEST_RESULT=$?

echo "Stopping Python destination..."
kill $PYTHON_PID

if [ $TEST_RESULT -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Tests failed!"
    exit 1
fi
```

### CI Configuration (GitHub Actions)

```yaml
name: Reticulum Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y libsodium-dev
        pip install rns

    - name: Build
      run: |
        mkdir build && cd build
        cmake ..
        make

    - name: Run unit tests
      run: |
        cd build
        ctest --output-on-failure

    - name: Run integration tests
      run: |
        ./scripts/run_integration_tests.sh
```

## 13.11 Summary

### Critical Test Points

| Component | Test | Expected Result |
|-----------|------|-----------------|
| SHA-256 | Hash "hello" | 2cf24dba5fb0a30e... |
| Link proof | 99 byte payload | Signature valid |
| Signed data | 83 bytes | Matches Python |
| HDLC | 0x7E escape | 0x7D 0x5E |
| Fernet | Version byte | 0x80 |

### Testing Strategy

1. **Unit tests**: Test each cryptographic primitive
2. **Integration tests**: Test against Python RNS
3. **Packet capture**: Verify wire format
4. **Round-trip tests**: Send and receive on links

### Debugging Tools

- Python `rnsd -vvv` for verbose logging
- Wireshark for packet capture
- Hex dumps for byte-level analysis
- Test vectors for known-good values

With these tests passing, your implementation should be interoperable with the Python reference implementation.
