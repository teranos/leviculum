#!/usr/bin/env python3
"""
Minimal RNS daemon for Rust interop testing.

This daemon provides:
1. A standalone Reticulum instance with a TCPServerInterface
2. A JSON-RPC command interface for querying internal state

Usage:
    python3 test_daemon.py --rns-port 4242 --cmd-port 9999

The daemon will:
- Create a temporary config directory
- Start Reticulum in standalone mode (no shared instance)
- Listen for Reticulum packets on the RNS port
- Accept JSON-RPC commands on the command port

JSON-RPC methods:
- get_path_table: Returns all known paths
- get_announces: Returns pending announces
- has_path: Check if path exists for a destination hash
- get_interfaces: List active interfaces
- register_destination: Create a destination that accepts links
- get_destinations: List registered destinations
- enable_ratchets: Enable ratchets for a destination
- get_ratchet_info: Get ratchet state for a destination
- add_client_interface: Connect to another daemon's TCPServerInterface
- get_transport_status: Get transport/routing status
- get_link_table: Get link table for relay verification
- rotate_ratchet: Force ratchet rotation for a destination
- close_link: Gracefully close a link by its hash
- get_link_status: Get detailed status of a link
- wait_for_link_state: Wait for a link to reach a specific state
- shutdown: Gracefully stop the daemon
"""

import argparse
import json
import os
import socket
import sys
import tempfile
import threading
import time


def find_reticulum_path():
    """Find Reticulum in order: env var, vendor submodule, system."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    candidates = [
        os.environ.get("RETICULUM_PATH"),  # 1. Explicit override
        os.path.join(project_root, "vendor", "Reticulum"),  # 2. Vendor submodule
    ]

    for path in candidates:
        if path and os.path.isdir(path) and os.path.exists(os.path.join(path, "RNS")):
            return path

    return None  # Fall back to system-installed


RETICULUM_PATH = find_reticulum_path()
if RETICULUM_PATH:
    sys.path.insert(0, RETICULUM_PATH)

try:
    import RNS
    from RNS import Transport
    from RNS.Interfaces.TCPInterface import TCPClientInterface
except ImportError:
    print("ERROR: Reticulum (RNS) not found.")
    print("Options:")
    print("  1. Run: git submodule update --init vendor/Reticulum")
    print("  2. Set RETICULUM_PATH=/path/to/Reticulum")
    print("  3. Install system-wide: pip install rns")
    sys.exit(1)


class TestDaemon:
    def __init__(self, rns_port: int, cmd_port: int, verbose: bool = False):
        self.rns_port = rns_port
        self.cmd_port = cmd_port
        self.verbose = verbose
        self.running = True
        self.destinations = {}  # hash -> (identity, destination)
        self.links = {}  # link_hash -> link
        self.received_packets = []  # [(timestamp, link, data)]
        self.client_interfaces = {}  # name -> TCPClientInterface

        # Create temp config directory
        self.config_dir = tempfile.mkdtemp(prefix="rns_test_")
        self._write_config()

        if self.verbose:
            print(f"Config dir: {self.config_dir}")
            print(f"RNS port: {self.rns_port}")
            print(f"CMD port: {self.cmd_port}")

        # Initialize Reticulum in standalone mode
        loglevel = RNS.LOG_DEBUG if self.verbose else RNS.LOG_WARNING
        self.rns = RNS.Reticulum(
            configdir=self.config_dir,
            loglevel=loglevel
        )

        if self.verbose:
            print("Reticulum initialized")

        # Start JSON-RPC command server
        self._start_cmd_server()

    def _write_config(self):
        """Write minimal Reticulum config."""
        config = f"""[reticulum]
  enable_transport = yes
  share_instance = no
  panic_on_interface_error = no

[interfaces]
  [[Test TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {self.rns_port}
"""
        config_path = os.path.join(self.config_dir, "config")
        with open(config_path, 'w') as f:
            f.write(config)

    def _start_cmd_server(self):
        """Start the JSON-RPC command server in a separate thread."""
        self.cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cmd_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cmd_socket.bind(('127.0.0.1', self.cmd_port))
        self.cmd_socket.listen(5)
        self.cmd_socket.settimeout(1.0)

        self.cmd_thread = threading.Thread(target=self._cmd_server_loop, daemon=True)
        self.cmd_thread.start()

        if self.verbose:
            print(f"Command server listening on port {self.cmd_port}")

    def _cmd_server_loop(self):
        """Accept and handle command connections."""
        while self.running:
            try:
                conn, addr = self.cmd_socket.accept()
                threading.Thread(
                    target=self._handle_cmd_connection,
                    args=(conn,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Command server error: {e}")

    def _handle_cmd_connection(self, conn):
        """Handle a single command connection."""
        try:
            conn.settimeout(5.0)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Try to parse complete JSON
                try:
                    cmd = json.loads(data.decode('utf-8'))
                    response = self._handle_cmd(cmd)
                    conn.sendall(json.dumps(response).encode('utf-8'))
                    break
                except json.JSONDecodeError:
                    # Need more data
                    continue
        except Exception as e:
            try:
                conn.sendall(json.dumps({"error": str(e)}).encode('utf-8'))
            except:
                pass
        finally:
            conn.close()

    def _handle_cmd(self, cmd):
        """Handle a JSON-RPC command."""
        method = cmd.get("method")
        params = cmd.get("params", {})

        if method == "ping":
            return {"result": "pong"}

        elif method == "get_path_table":
            # Return path table as hex strings
            paths = {}
            for h, entry in Transport.path_table.items():
                # entry = [timestamp, received_from, hops, expires, ...]
                paths[h.hex()] = {
                    "timestamp": entry[0],
                    "hops": entry[2] if len(entry) > 2 else None,
                    "expires": entry[3] if len(entry) > 3 else None,
                }
            return {"result": paths}

        elif method == "get_announces":
            # Return announce table
            announces = {}
            for h, entry in Transport.announce_table.items():
                # entry = [timestamp, retransmit_timeout, retries, ...]
                announces[h.hex()] = {
                    "timestamp": entry[0] if len(entry) > 0 else None,
                }
            return {"result": announces}

        elif method == "has_path":
            h = bytes.fromhex(params.get("hash", ""))
            return {"result": Transport.has_path(h)}

        elif method == "get_interfaces":
            interfaces = []
            for iface in Transport.interfaces:
                interfaces.append({
                    "name": str(iface),
                    "online": getattr(iface, 'online', None),
                    "IN": getattr(iface, 'IN', None),
                    "OUT": getattr(iface, 'OUT', None),
                })
            return {"result": interfaces}

        elif method == "register_destination":
            # Create a destination that accepts links
            app_name = params.get("app_name", "test")
            aspects = params.get("aspects", [])

            identity = RNS.Identity()
            dest = RNS.Destination(
                identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                app_name,
                *aspects
            )

            # Set up link acceptance
            dest.set_link_established_callback(
                lambda link, d=dest: self._on_link_established(link, d)
            )

            dest_hash = dest.hash.hex()
            self.destinations[dest_hash] = (identity, dest)

            # Return destination info
            pub_key = identity.get_public_key()
            return {
                "result": {
                    "hash": dest_hash,
                    "public_key": pub_key.hex(),
                    "signing_key": pub_key[32:64].hex(),
                }
            }

        elif method == "get_destinations":
            dests = {}
            for h, (identity, dest) in self.destinations.items():
                dests[h] = {
                    "app_name": getattr(dest, 'app_name', None),
                }
            return {"result": dests}

        elif method == "get_links":
            links = {}
            for h, link in self.links.items():
                links[h] = {
                    "status": str(link.status),
                    "activated_at": getattr(link, 'activated_at', None),
                }
            return {"result": links}

        elif method == "get_received_packets":
            # Return packets received over links
            packets = []
            for ts, link, data in self.received_packets:
                packets.append({
                    "timestamp": ts,
                    "link_hash": link.hash.hex() if link.hash else None,
                    "data": data.hex() if isinstance(data, bytes) else str(data),
                })
            return {"result": packets}

        elif method == "announce_destination":
            dest_hash = params.get("hash")
            app_data = params.get("app_data", b"")
            if isinstance(app_data, str):
                app_data = bytes.fromhex(app_data)

            if dest_hash not in self.destinations:
                return {"error": f"Destination {dest_hash} not registered"}

            _, dest = self.destinations[dest_hash]
            dest.announce(app_data=app_data)
            return {"result": "announced"}

        elif method == "enable_ratchets":
            # Enable ratchets for a destination (forward secrecy)
            dest_hash = params.get("hash")

            if dest_hash not in self.destinations:
                return {"error": f"Destination {dest_hash} not registered"}

            _, dest = self.destinations[dest_hash]

            # Create ratchet storage path - RNS expects this to be a file path
            # (it writes to <path> and creates <path>.tmp during writes)
            ratchet_dir = os.path.join(self.config_dir, "ratchets")
            os.makedirs(ratchet_dir, exist_ok=True)
            ratchet_path = os.path.join(ratchet_dir, dest_hash)

            try:
                dest.enable_ratchets(ratchet_path)
                return {"result": {
                    "enabled": True,
                    "ratchet_dir": ratchet_path,
                }}
            except Exception as e:
                return {"error": f"Failed to enable ratchets: {str(e)}"}

        elif method == "get_ratchet_info":
            # Get ratchet state for a destination
            dest_hash = params.get("hash")

            if dest_hash not in self.destinations:
                return {"error": f"Destination {dest_hash} not registered"}

            _, dest = self.destinations[dest_hash]

            # Check if ratchets are enabled
            ratchets_enabled = hasattr(dest, 'ratchets') and dest.ratchets is not None

            result = {
                "enabled": ratchets_enabled,
            }

            if ratchets_enabled:
                # Get ratchet count and latest ID
                ratchet_count = len(dest.ratchets) if hasattr(dest.ratchets, '__len__') else 0
                latest_id = dest.latest_ratchet_id.hex() if hasattr(dest, 'latest_ratchet_id') and dest.latest_ratchet_id else None
                result["count"] = ratchet_count
                result["latest_id"] = latest_id

            return {"result": result}

        elif method == "create_link":
            # Create a link to an external destination (Python as initiator)
            dest_hash = params.get("dest_hash")
            dest_key = params.get("dest_key")  # 64-byte public key hex
            timeout = params.get("timeout", 10)

            if not dest_hash or not dest_key:
                return {"error": "dest_hash and dest_key required"}

            try:
                dest_hash_bytes = bytes.fromhex(dest_hash)
                dest_key_bytes = bytes.fromhex(dest_key)

                # Create identity from public key (no private key)
                dest_identity = RNS.Identity(create_keys=False)
                dest_identity.load_public_key(dest_key_bytes)

                # Create outgoing destination
                dest = RNS.Destination(
                    dest_identity,
                    RNS.Destination.OUT,
                    RNS.Destination.SINGLE,
                    "rust",
                    "interop"
                )

                # Override the hash (for testing - destination was registered externally)
                dest.hash = dest_hash_bytes

                # Create link with timeout
                link = RNS.Link(dest)

                # Wait for link establishment
                start = time.time()
                while link.status != RNS.Link.ACTIVE and time.time() - start < timeout:
                    time.sleep(0.1)
                    if link.status == RNS.Link.CLOSED:
                        return {"error": "Link closed before establishment"}

                if link.status != RNS.Link.ACTIVE:
                    return {"error": "Link establishment timeout"}

                link_hash = link.hash.hex() if link.hash else "unknown"
                self.links[link_hash] = link

                # Set up callbacks
                link.set_packet_callback(lambda msg, pkt, l=link: self._on_packet(l, msg, pkt))
                link.set_link_closed_callback(lambda l: self._on_link_closed(l))

                return {
                    "result": {
                        "link_hash": link_hash,
                        "status": str(link.status),
                    }
                }

            except Exception as e:
                return {"error": f"Failed to create link: {str(e)}"}

        elif method == "send_on_link":
            # Send data on an existing link
            link_hash = params.get("link_hash")
            data = params.get("data")  # hex string

            if not link_hash or not data:
                return {"error": "link_hash and data required"}

            if link_hash not in self.links:
                return {"error": f"Link {link_hash} not found"}

            link = self.links[link_hash]
            data_bytes = bytes.fromhex(data)

            try:
                packet = RNS.Packet(link, data_bytes)
                packet.send()
                return {"result": "sent"}
            except Exception as e:
                return {"error": f"Send failed: {str(e)}"}

        elif method == "add_client_interface":
            # Connect this daemon to another daemon's TCPServerInterface
            target_ip = params.get("target_ip", "127.0.0.1")
            target_port = params.get("target_port")
            name = params.get("name")

            if not target_port:
                return {"error": "target_port is required"}

            if not name:
                name = f"TCPClient_{target_ip}_{target_port}"

            try:
                # Create TCPClientInterface using configuration dict
                # The new RNS API expects a configuration object
                config = {
                    "name": name,
                    "target_host": target_ip,
                    "target_port": target_port,
                }

                client_iface = TCPClientInterface(
                    RNS.Transport,
                    config,
                )

                # Register with Transport
                RNS.Transport.interfaces.append(client_iface)

                # Store reference
                self.client_interfaces[name] = client_iface

                # Wait briefly for connection
                time.sleep(0.5)

                return {
                    "result": {
                        "name": name,
                        "online": getattr(client_iface, 'online', False),
                        "target_ip": target_ip,
                        "target_port": target_port,
                    }
                }

            except Exception as e:
                return {"error": f"Failed to create client interface: {str(e)}"}

        elif method == "get_transport_status":
            # Get transport/routing status
            try:
                result = {
                    "enabled": RNS.Reticulum.transport_enabled(),
                    "identity_hash": Transport.identity.hash.hex() if Transport.identity else None,
                    "path_table_size": len(Transport.path_table),
                    "link_table_size": len(Transport.link_table) if hasattr(Transport, 'link_table') else 0,
                    "announce_table_size": len(Transport.announce_table),
                    "interface_count": len(Transport.interfaces),
                }
                return {"result": result}
            except Exception as e:
                return {"error": f"Failed to get transport status: {str(e)}"}

        elif method == "get_link_table":
            # Get link table for relay verification
            try:
                link_table = {}
                if hasattr(Transport, 'link_table'):
                    for link_id, entry in Transport.link_table.items():
                        # link_table entry format: [timestamp, next_hop, outbound_interface, remaining_hops, ...]
                        link_table[link_id.hex()] = {
                            "timestamp": entry[0] if len(entry) > 0 else None,
                            "interface": str(entry[2]) if len(entry) > 2 else None,
                            "hops": entry[3] if len(entry) > 3 else None,
                        }
                return {"result": link_table}
            except Exception as e:
                return {"error": f"Failed to get link table: {str(e)}"}

        elif method == "rotate_ratchet":
            # Force ratchet rotation for a destination
            dest_hash = params.get("hash")

            if dest_hash not in self.destinations:
                return {"error": f"Destination {dest_hash} not registered"}

            _, dest = self.destinations[dest_hash]

            # Check if ratchets are enabled
            if not hasattr(dest, 'ratchets') or dest.ratchets is None:
                return {"error": "Ratchets not enabled for this destination"}

            try:
                # Rotate ratchet - this generates a new ratchet key pair
                dest.rotate_ratchets()

                # Get new state
                ratchet_count = len(dest.ratchets) if hasattr(dest.ratchets, '__len__') else 0
                latest_id = dest.latest_ratchet_id.hex() if hasattr(dest, 'latest_ratchet_id') and dest.latest_ratchet_id else None

                return {
                    "result": {
                        "rotated": True,
                        "ratchet_count": ratchet_count,
                        "new_ratchet_id": latest_id,
                    }
                }
            except Exception as e:
                return {"error": f"Failed to rotate ratchet: {str(e)}"}

        elif method == "close_link":
            # Gracefully close a link by its hash
            link_hash = params.get("link_hash")
            if not link_hash:
                return {"error": "link_hash is required"}

            if link_hash not in self.links:
                return {"error": f"Link {link_hash} not found", "status": "not_found"}

            link = self.links[link_hash]
            try:
                link.teardown()
                return {"result": {"status": "closed", "link_hash": link_hash}}
            except Exception as e:
                return {"error": f"Failed to close link: {str(e)}"}

        elif method == "get_link_status":
            # Get detailed status of a link
            link_hash = params.get("link_hash")
            if not link_hash:
                return {"error": "link_hash is required"}

            if link_hash not in self.links:
                return {"result": {"status": "not_found", "link_hash": link_hash}}

            link = self.links[link_hash]
            return {
                "result": {
                    "status": "found",
                    "link_hash": link_hash,
                    "state": str(link.status),
                    "is_initiator": getattr(link, 'initiator', None),
                    "rtt": getattr(link, 'rtt', None),
                    "established_at": getattr(link, 'activated_at', None),
                    "last_inbound": getattr(link, 'last_inbound', None),
                    "last_outbound": getattr(link, 'last_outbound', None),
                }
            }

        elif method == "wait_for_link_state":
            # Wait for a link to reach a specific state
            link_hash = params.get("link_hash")
            expected_state = params.get("state")
            timeout_secs = params.get("timeout", 10)

            if not link_hash or not expected_state:
                return {"error": "link_hash and state are required"}

            deadline = time.time() + timeout_secs

            while time.time() < deadline:
                if link_hash in self.links:
                    link = self.links[link_hash]
                    current_state = str(link.status)
                    if current_state == expected_state:
                        return {"result": {"status": "reached", "state": expected_state}}
                    # Also check for CLOSED state (link may be removed from dict)
                    if link.status == RNS.Link.CLOSED and expected_state == "CLOSED":
                        return {"result": {"status": "reached", "state": expected_state}}
                else:
                    # Link removed from dict means it's closed
                    if expected_state == "CLOSED":
                        return {"result": {"status": "reached", "state": expected_state}}

                time.sleep(0.1)

            # Timeout - return current state if available
            current = None
            if link_hash in self.links:
                current = str(self.links[link_hash].status)

            return {
                "result": {
                    "status": "timeout",
                    "expected": expected_state,
                    "current": current
                }
            }

        elif method == "set_proof_strategy":
            # Set proof strategy for a destination
            dest_hash = params.get("hash")
            strategy = params.get("strategy")

            if dest_hash not in self.destinations:
                return {"error": f"Destination {dest_hash} not registered"}

            _, dest = self.destinations[dest_hash]

            strategy_map = {
                "PROVE_NONE": RNS.Destination.PROVE_NONE,
                "PROVE_APP": RNS.Destination.PROVE_APP,
                "PROVE_ALL": RNS.Destination.PROVE_ALL,
            }

            if strategy not in strategy_map:
                return {"error": f"Unknown strategy: {strategy}. Use PROVE_NONE, PROVE_APP, or PROVE_ALL"}

            try:
                dest.set_proof_strategy(strategy_map[strategy])
                return {"result": {"strategy": strategy, "dest_hash": dest_hash}}
            except Exception as e:
                return {"error": f"Failed to set proof strategy: {str(e)}"}

        elif method == "get_proof_strategy":
            # Get proof strategy for a destination
            dest_hash = params.get("hash")

            if dest_hash not in self.destinations:
                return {"error": f"Destination {dest_hash} not registered"}

            _, dest = self.destinations[dest_hash]

            strategy_names = {
                RNS.Destination.PROVE_NONE: "PROVE_NONE",
                RNS.Destination.PROVE_APP: "PROVE_APP",
                RNS.Destination.PROVE_ALL: "PROVE_ALL",
            }

            return {"result": {
                "strategy": strategy_names.get(dest.proof_strategy, "unknown"),
                "strategy_value": dest.proof_strategy,
            }}

        elif method == "shutdown":
            self.running = False
            return {"result": "shutting_down"}

        else:
            return {"error": f"Unknown method: {method}"}

    def _on_link_established(self, link, dest):
        """Called when a link is established to one of our destinations."""
        if self.verbose:
            print(f"Link established: {link.hash.hex() if link.hash else 'unknown'}")

        link_hash = link.hash.hex() if link.hash else "unknown"
        self.links[link_hash] = link

        link.set_packet_callback(lambda msg, pkt: self._on_packet(link, msg, pkt))
        link.set_link_closed_callback(lambda l: self._on_link_closed(l))

    def _on_packet(self, link, message, packet):
        """Called when a packet is received over a link."""
        if self.verbose:
            print(f"Packet received: {message}")

        self.received_packets.append((time.time(), link, message))

        # Echo back
        if isinstance(message, str):
            message = message.encode('utf-8')
        RNS.Packet(link, message).send()

    def _on_link_closed(self, link):
        """Called when a link is closed."""
        if self.verbose:
            print(f"Link closed: {link.hash.hex() if link.hash else 'unknown'}")

        link_hash = link.hash.hex() if link.hash else None
        if link_hash and link_hash in self.links:
            del self.links[link_hash]

    def run(self):
        """Run the daemon until shutdown."""
        # Signal readiness by printing to stdout
        print(f"READY {self.rns_port} {self.cmd_port}", flush=True)

        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()

    def _cleanup(self):
        """Clean up resources."""
        self.running = False
        try:
            self.cmd_socket.close()
        except:
            pass

        # Clean up temp directory
        try:
            import shutil
            shutil.rmtree(self.config_dir, ignore_errors=True)
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="RNS test daemon for Rust interop")
    parser.add_argument("--rns-port", type=int, required=True,
                        help="Port for Reticulum TCP interface")
    parser.add_argument("--cmd-port", type=int, required=True,
                        help="Port for JSON-RPC command interface")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()

    daemon = TestDaemon(
        rns_port=args.rns_port,
        cmd_port=args.cmd_port,
        verbose=args.verbose
    )
    daemon.run()


if __name__ == "__main__":
    main()
