#!/usr/bin/env python3
"""Send an announce with 100 bytes of app_data padding.

Connects to the running lnsd/rnsd as a shared-instance client via the
abstract Unix socket. The padded announce is ~267 bytes on the wire,
which triggers the RNode split protocol for LoRa transmission.
"""
import sys
import time
import RNS

r = RNS.Reticulum("/root/.reticulum")
time.sleep(2)

i = RNS.Identity()
d = RNS.Destination(i, RNS.Destination.IN, RNS.Destination.SINGLE, "split", "test")

pad_size = int(sys.argv[1]) if len(sys.argv) > 1 else 100
app_data = bytes([0x58] * pad_size)

for attempt in range(3):
    d.announce(app_data=app_data)
    print(f"announced with {pad_size} bytes app_data (attempt {attempt + 1}/3)")
    time.sleep(5)

print("done")
