#!/usr/bin/env python3
"""
Link test destination for testing Rust link implementation.

This script creates a Reticulum destination that accepts links and prints
the destination hash and signing key for use with the Rust link_test binary.

Usage:
    python link_test_destination.py

Then use the printed destination hash and signing key with:
    cargo run -p leviculum-std --example link_test -- <dest_hash> <signing_key>
"""

import sys
import time

try:
    import RNS
except ImportError:
    print("ERROR: Reticulum (RNS) not installed.")
    print("Install with: pip install rns")
    sys.exit(1)


class LinkTestDestination:
    def __init__(self):
        # Initialize Reticulum
        self.reticulum = RNS.Reticulum()

        # Create identity (or load existing)
        self.identity = RNS.Identity()

        # Create destination
        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            "linktest",
            "echo"
        )

        # Enable link acceptance
        self.destination.set_link_established_callback(self.link_established)

        # Set app_data that identifies this destination (unique to avoid conflicts with other linktest destinations)
        self.destination.default_app_data = b"leviculum.linktest.echo"

        # Announce the destination so others can find it
        self.destination.announce()

        # Get the signing key (Ed25519 public key)
        # In Reticulum, the identity's public keys are: encryption_pub + signing_pub
        # Each is 32 bytes
        pub_bytes = self.identity.get_public_key()
        self.signing_key = pub_bytes[32:64]  # Second 32 bytes is the signing key

        print("=" * 60)
        print("Link Test Destination Running")
        print("=" * 60)
        print()
        print(f"Destination hash: {self.destination.hash.hex()}")
        print(f"Signing key:      {self.signing_key.hex()}")
        print()
        print("Use these with the Rust link_test binary:")
        print()
        print(f"  cargo run -p leviculum-std --example link_test -- \\")
        print(f"    {self.destination.hash.hex()} \\")
        print(f"    {self.signing_key.hex()}")
        print()
        print("=" * 60)
        print("Waiting for link requests...")
        print()

    def link_established(self, link):
        """Called when a link is established."""
        print(f"[+] Link established!")
        print(f"    Link hash: {link.hash.hex() if link.hash else 'None'}")
        print(f"    Remote: {link.get_remote_identity().hash.hex() if link.get_remote_identity() else 'Anonymous'}")

        # Set up packet callback
        link.set_packet_callback(self.packet_received)
        link.set_link_closed_callback(self.link_closed)

    def packet_received(self, message, packet):
        """Called when a packet is received over the link."""
        print(f"[<] Received packet: {message}")

        # Echo it back
        data = message
        if isinstance(data, str):
            data = data.encode('utf-8')
        RNS.Packet(packet.link, data).send()
        print(f"[>] Echoed back")

    def link_closed(self, link):
        """Called when a link is closed."""
        print(f"[-] Link closed")

    def run(self):
        """Run the destination loop."""
        announce_interval = 10  # Re-announce every 10 seconds
        last_announce = time.time()
        try:
            while True:
                time.sleep(1)
                # Periodically re-announce
                if time.time() - last_announce >= announce_interval:
                    self.destination.announce()
                    print(f"Re-announced at {time.strftime('%H:%M:%S')}")
                    last_announce = time.time()
        except KeyboardInterrupt:
            print("\nShutting down...")


def main():
    dest = LinkTestDestination()
    dest.run()


if __name__ == "__main__":
    main()
