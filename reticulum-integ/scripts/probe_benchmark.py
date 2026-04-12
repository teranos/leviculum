#!/usr/bin/env python3
"""Probe throughput benchmark with persistent RNS connection.

Connects once as a shared-instance client, resolves the path once, then sends
probes in a loop using the RNS API. Each probe generates only 2 radio TX
(probe + reply), not 4 (no per-probe path re-request).

Usage: python3 probe_benchmark.py <config_path> <dest_hash> <duration_secs> <min_interval_secs> [probe_timeout_secs]

Output (one JSON line on stdout):
  {"sent":N,"received":N,"lost":N,"pdr":0.XX,
   "avg_rtt_ms":N,"p95_rtt_ms":N,"min_rtt_ms":N,"max_rtt_ms":N,"rtts_ms":[...]}
"""
import json
import os
import random
import sys
import time

import RNS

config_path = sys.argv[1]
dest_hash_hex = sys.argv[2]
duration = int(sys.argv[3])
min_interval = float(sys.argv[4])
probe_timeout = int(sys.argv[5]) if len(sys.argv) > 5 else 15

dest_hash = bytes.fromhex(dest_hash_hex)

# Connect as shared-instance client
reticulum = RNS.Reticulum(config_path)
time.sleep(2)

print(f"benchmark: resolving path to {dest_hash_hex}", file=sys.stderr, flush=True)

# Resolve path ONCE
if not RNS.Transport.has_path(dest_hash):
    RNS.Transport.request_path(dest_hash)
    path_timeout = time.time() + probe_timeout
    while not RNS.Transport.has_path(dest_hash):
        if time.time() > path_timeout:
            print(json.dumps({"sent": 0, "received": 0, "lost": 0, "pdr": 0,
                              "error": "path resolution timeout", "rtts_ms": []}))
            sys.exit(0)
        time.sleep(0.1)

# Build destination object (reused for all probes)
server_identity = RNS.Identity.recall(dest_hash)
if server_identity is None:
    print(json.dumps({"sent": 0, "received": 0, "lost": 0, "pdr": 0,
                      "error": "identity not found", "rtts_ms": []}))
    sys.exit(0)

request_destination = RNS.Destination(
    server_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rnstransport",
    "probe",
)

print(f"benchmark: probing {dest_hash_hex} for {duration}s, interval >= {min_interval}s, "
      f"timeout {probe_timeout}s", file=sys.stderr, flush=True)

sent = 0
received = 0
rtts = []

# Random initial jitter to desynchronize parallel benchmark threads.
# Without this, dual-pair benchmarks send probes simultaneously and
# every probe collides with the other pair's probe.
jitter = random.uniform(0, min_interval)
print(f"  initial jitter: {jitter:.1f}s", file=sys.stderr, flush=True)
time.sleep(jitter)

deadline = time.time() + duration
while time.time() < deadline:
    probe_start = time.time()
    sent += 1

    try:
        probe = RNS.Packet(request_destination, os.urandom(16))
        receipt = probe.send()

        # Wait for reply or timeout
        per_probe_deadline = time.time() + probe_timeout
        while receipt.status == RNS.PacketReceipt.SENT:
            if time.time() > per_probe_deadline:
                break
            time.sleep(0.1)

        if receipt.status == RNS.PacketReceipt.DELIVERED:
            rtt = receipt.get_rtt()
            rtt_ms = round(rtt * 1000, 1) if rtt < 1 else round(rtt * 1000, 1)
            received += 1
            rtts.append(rtt_ms)
            print(f"  probe {sent}: {rtt_ms:.0f}ms", file=sys.stderr, flush=True)
        else:
            print(f"  probe {sent}: timeout", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"  probe {sent}: error ({e})", file=sys.stderr, flush=True)

    # Wait at least min_interval between probes
    elapsed = time.time() - probe_start
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)

lost = sent - received
pdr = received / max(sent, 1)

rtts_sorted = sorted(rtts)
stats = {
    "sent": sent,
    "received": received,
    "lost": lost,
    "pdr": round(pdr, 4),
    "min_rtt_ms": round(min(rtts), 1) if rtts else None,
    "max_rtt_ms": round(max(rtts), 1) if rtts else None,
    "avg_rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
    "p95_rtt_ms": round(rtts_sorted[int(len(rtts_sorted) * 0.95)], 1) if rtts else None,
    "rtts_ms": [round(r, 1) for r in rtts],
}

print(json.dumps(stats), flush=True)
