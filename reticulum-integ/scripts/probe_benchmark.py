#!/usr/bin/env python3
"""Probe throughput benchmark: send rnprobe in a loop, output JSON stats.

Usage: python3 probe_benchmark.py <config_path> <dest_hash> <duration_secs> <min_interval_secs>

Output (one JSON line on stdout):
  {"sent":N,"received":N,"lost":N,"pdr":0.XX,
   "avg_rtt_ms":N,"p95_rtt_ms":N,"min_rtt_ms":N,"max_rtt_ms":N,"rtts_ms":[...]}
"""
import json
import re
import subprocess
import sys
import time

config_path = sys.argv[1]       # /root/.reticulum
dest_hash = sys.argv[2]         # hex destination hash (e.g., "lnode.probe" resolved hash)
duration = int(sys.argv[3])     # seconds
min_interval = float(sys.argv[4])  # minimum seconds between probes

sent = 0
received = 0
rtts = []

print(f"benchmark: probing {dest_hash} for {duration}s, interval >= {min_interval}s",
      file=sys.stderr, flush=True)

deadline = time.time() + duration
while time.time() < deadline:
    probe_start = time.time()
    sent += 1
    try:
        result = subprocess.run(
            ["rnprobe", "rnstransport.probe", dest_hash,
             "--config", config_path, "-t", "30"],
            capture_output=True, text=True, timeout=35
        )
        if result.returncode == 0:
            received += 1
            # rnprobe outputs "Round-trip time is X.XXX milliseconds" or "X.XXX seconds"
            m = re.search(r"Round-trip time is (\d+(?:\.\d+)?)\s+(milliseconds|seconds)", result.stdout)
            if m:
                rtt_val = float(m.group(1))
                if m.group(2) == "seconds":
                    rtt_val *= 1000.0
                rtts.append(rtt_val)
            print(f"  probe {sent}: ok ({result.stdout.strip()})", file=sys.stderr, flush=True)
        else:
            print(f"  probe {sent}: failed (exit {result.returncode})", file=sys.stderr, flush=True)
    except subprocess.TimeoutExpired:
        print(f"  probe {sent}: timeout", file=sys.stderr, flush=True)

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
    "p95_rtt_ms": round(rtts_sorted[int(len(rtts_sorted) * 0.95)] if rtts_sorted else 0, 1) if rtts else None,
    "rtts_ms": [round(r, 1) for r in rtts],
}

print(json.dumps(stats), flush=True)
