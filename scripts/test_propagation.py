#!/usr/bin/env python3
"""
Python-only announce propagation test.

Isolates whether announce propagation failure is in rnsd or in our Rust code.
Uses the RNS library (known-good) to build announces, but sends them over
raw TCP sockets with manual HDLC framing — exactly what the Rust tests do.

Usage:
    PYTHONPATH=/home/lew/coding/Reticulum python3 scripts/test_propagation.py

Requires: rnsd running with TCPServerInterface on 127.0.0.1:4242
"""

import os
import socket
import struct
import sys
import time

# Use local Reticulum source
RETICULUM_SRC = "/home/lew/coding/Reticulum"
if RETICULUM_SRC not in sys.path:
    sys.path.insert(0, RETICULUM_SRC)

try:
    import RNS
except ImportError:
    print("ERROR: Cannot import RNS from", RETICULUM_SRC)
    sys.exit(1)

# --- Constants ---

RNSD_HOST = "127.0.0.1"
RNSD_PORT = 4242
INTERFACE_SETTLE_SECS = 2.0
PROPAGATION_TIMEOUT_SECS = 10.0

# HDLC framing (must match Rust and Python RNS)
HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_MASK = 0x20


# --- HDLC helpers ---

def hdlc_escape(data: bytes) -> bytes:
    """Escape FLAG and ESC bytes in data."""
    out = bytearray()
    for b in data:
        if b == HDLC_FLAG or b == HDLC_ESC:
            out.append(HDLC_ESC)
            out.append(b ^ HDLC_ESC_MASK)
        else:
            out.append(b)
    return bytes(out)


def hdlc_frame(data: bytes) -> bytes:
    """Frame raw packet bytes with HDLC."""
    return bytes([HDLC_FLAG]) + hdlc_escape(data) + bytes([HDLC_FLAG])


def hdlc_deframe(data: bytes) -> list[bytes]:
    """Extract all HDLC frames from a byte buffer."""
    frames = []
    in_frame = False
    escape_next = False
    buf = bytearray()

    for b in data:
        if b == HDLC_FLAG:
            if in_frame and len(buf) > 0:
                frames.append(bytes(buf))
                buf.clear()
            in_frame = True
            buf.clear()
            escape_next = False
        elif in_frame:
            if escape_next:
                buf.append(b ^ HDLC_ESC_MASK)
                escape_next = False
            elif b == HDLC_ESC:
                escape_next = True
            else:
                buf.append(b)

    return frames


# --- Packet construction ---

def build_announce_packet(identity, app_name: str, aspects: list[str], app_data: bytes) -> tuple[bytes, bytes]:
    """
    Build a valid announce packet using RNS crypto, returning (raw_packet_bytes, destination_hash).

    Packet format (Type1, Broadcast, Announce):
      [flags:1][hops:1][destination_hash:16][context:1][payload...]

    Payload format (no ratchet):
      [public_key:64][name_hash:10][random_hash:10][signature:64][app_data:N]
    """
    # Compute name hash the same way RNS does
    full_name = app_name
    for aspect in aspects:
        full_name += "." + aspect

    name_hash = RNS.Identity.full_hash(full_name.encode("utf-8"))[:10]

    # Random hash: 5 random bytes + 5 timestamp bytes (big-endian)
    random_part = os.urandom(5)
    timestamp_bytes = int(time.time()).to_bytes(5, "big")
    random_hash = random_part + timestamp_bytes

    # Identity hash (truncated hash of public key)
    public_key = identity.get_public_key()  # 64 bytes: X25519(32) + Ed25519(32)
    identity_hash = RNS.Identity.truncated_hash(public_key)

    # Destination hash
    hash_material = name_hash + identity_hash
    destination_hash = RNS.Identity.truncated_hash(hash_material)

    # Sign: destination_hash + public_key + name_hash + random_hash + app_data
    signed_data = destination_hash + public_key + name_hash + random_hash + app_data
    signature = identity.sign(signed_data)

    # Payload
    payload = public_key + name_hash + random_hash + signature + app_data

    # Packet header
    # flags byte layout: [unused:1][header_type:1][context_flag:1][transport_type:1][dest_type:2][packet_type:2]
    #   header_type=0 (Type1), context_flag=0, transport_type=0 (Broadcast),
    #   dest_type=0 (Single), packet_type=1 (Announce)
    # = 0b0_0_0_0_00_01 = 0x01
    flags = 0x01
    hops = 0
    context = 0  # PacketContext::None

    raw = bytes([flags, hops]) + destination_hash + bytes([context]) + payload

    return raw, destination_hash


# --- Test ---

def ts() -> str:
    """Current timestamp for logging."""
    return time.strftime("%H:%M:%S", time.localtime()) + f".{int(time.time() * 1000) % 1000:03d}"


def main():
    print(f"[{ts()}] === Python Announce Propagation Test ===")
    print(f"[{ts()}] RNS version: {RNS.__version__}")
    print(f"[{ts()}] RNS source:  {RNS.__file__}")
    print()

    # Step 1: Open two TCP connections to rnsd
    print(f"[{ts()}] Connecting socket 1 to {RNSD_HOST}:{RNSD_PORT}...")
    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.settimeout(5.0)
        sock1.connect((RNSD_HOST, RNSD_PORT))
    except Exception as e:
        print(f"[{ts()}] FAILED to connect socket 1: {e}")
        print("Is rnsd running? Start with: bash scripts/test_env.sh")
        sys.exit(1)
    print(f"[{ts()}] Socket 1 connected")

    print(f"[{ts()}] Connecting socket 2 to {RNSD_HOST}:{RNSD_PORT}...")
    try:
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(5.0)
        sock2.connect((RNSD_HOST, RNSD_PORT))
    except Exception as e:
        print(f"[{ts()}] FAILED to connect socket 2: {e}")
        sock1.close()
        sys.exit(1)
    print(f"[{ts()}] Socket 2 connected")

    # Step 2: Wait for interface initialization
    print(f"[{ts()}] Waiting {INTERFACE_SETTLE_SECS}s for interface settle...")
    time.sleep(INTERFACE_SETTLE_SECS)

    # Step 3: Build announce
    print(f"[{ts()}] Building announce packet...")
    identity = RNS.Identity(create_keys=True)
    raw_packet, dest_hash = build_announce_packet(
        identity,
        "leviculum",
        ["propagation", "pytest"],
        b"python-propagation-test",
    )
    print(f"[{ts()}] Raw packet: {len(raw_packet)} bytes")
    print(f"[{ts()}] Dest hash:  {dest_hash.hex()[:8]}...")
    print(f"[{ts()}] Flags byte: 0x{raw_packet[0]:02x}")
    print(f"[{ts()}] Hops byte:  {raw_packet[1]}")

    # Step 4: HDLC-frame and send on socket 1
    framed = hdlc_frame(raw_packet)
    print(f"[{ts()}] Framed:     {len(framed)} bytes")
    print(f"[{ts()}] Sending on socket 1...")
    try:
        sock1.sendall(framed)
    except Exception as e:
        print(f"[{ts()}] FAILED to send: {e}")
        sock1.close()
        sock2.close()
        sys.exit(1)
    print(f"[{ts()}] Sent {len(framed)} bytes on socket 1")

    # Step 5: Read from socket 2 with timeout
    print(f"[{ts()}] Waiting for propagation on socket 2 (timeout {PROPAGATION_TIMEOUT_SECS}s)...")
    sock2.setblocking(False)
    received_data = bytearray()
    found = False
    start = time.time()

    while time.time() - start < PROPAGATION_TIMEOUT_SECS:
        try:
            chunk = sock2.recv(4096)
            if len(chunk) == 0:
                print(f"[{ts()}] Socket 2 closed by remote!")
                break
            received_data.extend(chunk)
            print(f"[{ts()}] Received {len(chunk)} bytes on socket 2 (total: {len(received_data)})")

            # Try to deframe and check for our announce
            frames = hdlc_deframe(bytes(received_data))
            for frame_data in frames:
                if len(frame_data) < 19:
                    continue
                # Check packet type: flags byte, bits 0-1 = packet_type
                pkt_flags = frame_data[0]
                pkt_type = pkt_flags & 0x03
                header_type = (pkt_flags >> 6) & 0x01  # 0=Type1, 1=Type2
                # Announce = 1
                if pkt_type == 1:
                    # Type1: [flags:1][hops:1][dest_hash:16][context:1][payload...]
                    # Type2: [flags:1][hops:1][transport_id:16][dest_hash:16][context:1][payload...]
                    if header_type == 0:
                        pkt_dest = frame_data[2:18]
                    else:
                        if len(frame_data) < 35:
                            continue
                        pkt_dest = frame_data[18:34]
                    print(f"[{ts()}] Found announce frame (H{header_type + 1}), dest: {pkt_dest.hex()[:8]}...")
                    if pkt_dest == dest_hash:
                        print(f"[{ts()}] MATCH! Our announce was propagated!")
                        found = True
                        break
            if found:
                break
        except BlockingIOError:
            time.sleep(0.1)
        except Exception as e:
            print(f"[{ts()}] Read error: {e}")
            break

    elapsed = time.time() - start

    # Step 6: Report results
    print()
    print("=" * 60)
    if found:
        print(f"PASS: Announce propagated in {elapsed:.1f}s")
        print()
        print("This means rnsd propagation works correctly.")
        print("If the Rust test fails, the problem is in the Rust")
        print("HDLC framing, packet format, or timing.")
    else:
        print(f"FAIL: No announce received after {elapsed:.1f}s")
        print(f"  Bytes received on socket 2: {len(received_data)}")
        if received_data:
            print(f"  Raw data (first 100): {received_data[:100].hex()}")
            frames = hdlc_deframe(bytes(received_data))
            print(f"  Deframed {len(frames)} frame(s)")
            for i, f in enumerate(frames):
                print(f"    Frame {i}: {len(f)} bytes, flags=0x{f[0]:02x}" if len(f) > 0 else f"    Frame {i}: empty")
        print()
        print("This means rnsd itself is not propagating announces.")
        print("Check:")
        print("  1. rnsd logs: ~/.reticulum/logfile (loglevel=7)")
        print("  2. Transport.py ingress limiting / rate blocking")
        print("  3. Whether enable_transport = True in config")
    print("=" * 60)

    # Also dump what socket 1 received (rnsd may send us other announces)
    sock1.setblocking(False)
    try:
        s1_data = sock1.recv(4096)
        if s1_data:
            print(f"\nSocket 1 also received {len(s1_data)} bytes (other announces from rnsd)")
    except:
        pass

    sock1.close()
    sock2.close()
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
