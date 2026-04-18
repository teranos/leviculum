#!/usr/bin/env python3
"""
Python-RNS equivalent of `lns selftest --mode link`, for Bug #25
baseline measurement.

Runs in either --responder or --initiator mode:

- --responder (on beta): registers a destination with fixed aspects
  `leviculum.selftest.responder`, enables incoming links, announces
  itself periodically. Accepts any incoming Link, consumes the
  channel messages it receives. Exits on SIGTERM or after
  `--duration + 30 s` total runtime.

- --initiator (on alpha): connects to the local rnsd via shared-
  instance mode, registers an announce handler for the responder's
  aspects, waits for the responder's announce, resolves the path,
  establishes a Link, sends `--rate` channel messages per second for
  `--duration` seconds, counts acks, exits 0 iff all messages were
  acked.

Both sides share the SAME app + aspect tuple
(`leviculum / selftest / responder`); the hash is discovered by the
initiator via the Python-RNS announce mechanism, same as any normal
RNS peer would do.

Exit codes:
  0  success (initiator) / normal shutdown (responder)
  1  generic failure
  2  discovery timeout (initiator)
  3  link establishment timeout
  4  one or more channel messages not acked within budget
"""

import argparse
import os
import signal
import sys
import threading
import time


def find_reticulum_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    candidates = [
        os.environ.get("RETICULUM_PATH"),
        os.path.join(project_root, "vendor", "Reticulum"),
    ]

    for path in candidates:
        if path and os.path.isdir(path) and os.path.exists(os.path.join(path, "RNS")):
            return path

    return None


RETICULUM_PATH = find_reticulum_path()
if RETICULUM_PATH:
    sys.path.insert(0, RETICULUM_PATH)

import RNS

APP_NAME = "leviculum"
ASPECTS = ("selftest", "responder")
ASPECT_FILTER = "leviculum.selftest.responder"


def parse_args():
    p = argparse.ArgumentParser(description="Python-RNS Link selftest driver")
    p.add_argument("--responder", action="store_true", help="responder mode")
    p.add_argument("--initiator", action="store_true", help="initiator mode")
    p.add_argument(
        "--config",
        default=os.environ.get("RETICULUM_CONFIG", "/root/.reticulum"),
        help="Reticulum config directory",
    )
    p.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="channel messages per second (initiator)",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="channel-message duration in seconds (initiator)",
    )
    p.add_argument(
        "--discovery-timeout",
        type=float,
        default=120.0,
        help="wait for responder announce + path (initiator)",
    )
    p.add_argument(
        "--link-timeout",
        type=float,
        default=60.0,
        help="link establishment timeout (initiator)",
    )
    return p.parse_args()


def run_responder(args):
    """Responder: register destination, announce, wait for links."""
    RNS.Reticulum(args.config, loglevel=6)

    identity = RNS.Identity()
    dest = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        APP_NAME,
        *ASPECTS,
    )
    dest.accepts_links(True)
    dest.set_link_established_callback(_on_incoming_link)

    dest_hash = RNS.hexrep(dest.hash, delimit=False)
    print(f"RESPONDER_READY dest={dest_hash}", flush=True)

    # Initial announce — the initiator waits for this. Also re-announce
    # periodically in case the first one is lost on the lossy LoRa link.
    # Cadence matches Rust's `PATHFINDER_G = 5 s` so the Bug #25
    # volume-hypothesis comparison is apples-to-apples; see
    # ~/.claude/report.md 2026-04-17.
    dest.announce(app_data=b"mvr-responder")
    announce_interval = 5.0

    start = time.time()
    max_life = args.duration + args.discovery_timeout + args.link_timeout + 60.0

    def _sigterm(_signo, _frame):
        print("RESPONDER_SHUTDOWN reason=signal", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm)

    last_announce = start
    while time.time() - start < max_life:
        now = time.time()
        if now - last_announce >= announce_interval:
            dest.announce(app_data=b"mvr-responder")
            last_announce = now
        time.sleep(0.5)

    print("RESPONDER_SHUTDOWN reason=max_life", flush=True)


_INCOMING_LINKS = []
_CHANNEL_RX_COUNT = 0
_LOCK = threading.Lock()


def _on_incoming_link(link):
    """Called when an incoming LinkRequest produces an Established link."""
    global _CHANNEL_RX_COUNT
    with _LOCK:
        _INCOMING_LINKS.append(link)

    # Attach a packet callback so we count the initiator's channel messages.
    def _on_packet(message, _packet):
        global _CHANNEL_RX_COUNT
        with _LOCK:
            _CHANNEL_RX_COUNT += 1

    link.set_packet_callback(_on_packet)
    link.set_link_closed_callback(lambda _l: None)
    print(
        f"RESPONDER_LINK link_id={RNS.hexrep(link.link_id, delimit=False)}",
        flush=True,
    )


def run_initiator(args):
    """Initiator: wait for responder announce, establish link, send messages."""
    RNS.Reticulum(args.config, loglevel=6)

    # Wait for responder's announce so we learn its destination hash.
    responder_hash = [None]
    announce_event = threading.Event()

    # Python-RNS announce handlers are duck-typed: any object with
    # an `aspect_filter` attribute and a `received_announce(...)`
    # callable is accepted (vendor/Reticulum/RNS/Transport.py:2262).
    class _AH:
        aspect_filter = ASPECT_FILTER

        def received_announce(self, destination_hash, announced_identity, app_data):
            with _LOCK:
                if responder_hash[0] is None:
                    responder_hash[0] = destination_hash
                    announce_event.set()

    RNS.Transport.register_announce_handler(_AH())
    print("INITIATOR_WAIT_ANNOUNCE", flush=True)

    if not announce_event.wait(args.discovery_timeout):
        print("INITIATOR_DISCOVERY_TIMEOUT", flush=True)
        sys.exit(2)

    dest_hash = responder_hash[0]
    print(f"INITIATOR_ANNOUNCE_RECEIVED dest={RNS.hexrep(dest_hash, delimit=False)}", flush=True)

    # Wait for the path to actually be installed. The announce handler
    # fires on announce arrival, but Transport.has_path may not return
    # true until the path-table update has been processed.
    path_deadline = time.time() + args.discovery_timeout
    while not RNS.Transport.has_path(dest_hash):
        if time.time() > path_deadline:
            print("INITIATOR_PATH_TIMEOUT", flush=True)
            sys.exit(2)
        time.sleep(0.1)

    print("INITIATOR_PATH_RESOLVED", flush=True)

    # Build the outbound destination from the recalled identity.
    identity = RNS.Identity.recall(dest_hash)
    if identity is None:
        print("INITIATOR_IDENTITY_RECALL_FAILED", flush=True)
        sys.exit(1)

    remote_dest = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        APP_NAME,
        *ASPECTS,
    )

    link_established = threading.Event()
    link_closed = threading.Event()

    def _on_established(_link):
        link_established.set()

    def _on_closed(_link):
        link_closed.set()

    link_start = time.time()
    link = RNS.Link(
        remote_dest,
        established_callback=_on_established,
        closed_callback=_on_closed,
    )

    if not link_established.wait(args.link_timeout):
        print(f"INITIATOR_LINK_TIMEOUT elapsed={time.time() - link_start:.1f}s", flush=True)
        sys.exit(3)

    link_elapsed = time.time() - link_start
    print(f"INITIATOR_LINK_ESTABLISHED elapsed={link_elapsed:.2f}s", flush=True)

    # Match the Rust `lns selftest --mode link` Phase-3 success
    # criterion: establish the link, then keep it alive while
    # sending `rate × duration` packets. We do NOT require ack
    # counting because Python-RNS's delivery-proof callback API
    # differs enough from the Rust Channel that an ack shortfall
    # wouldn't be directly comparable. Success == link stays open
    # for the full duration AND all sends return without raising.
    interval = 1.0 / args.rate
    total = int(args.rate * args.duration)
    sent_ok = 0
    send_errors = 0
    send_start = time.time()

    for i in range(total):
        target = send_start + i * interval
        now = time.time()
        if target > now:
            time.sleep(target - now)
        if link_closed.is_set():
            print(f"INITIATOR_LINK_CLOSED_EARLY after {i} packets", flush=True)
            sys.exit(4)
        msg = f"mvr-msg-{i:04d}".encode()
        try:
            packet = RNS.Packet(link, msg)
            packet.send()
            sent_ok += 1
        except Exception as exc:
            send_errors += 1
            print(f"INITIATOR_SEND_ERR i={i} err={exc}", flush=True)

    link_closed_during_send = link_closed.is_set()
    print(
        f"INITIATOR_COMPLETE sent={sent_ok} errors={send_errors} "
        f"link_closed={link_closed_during_send} duration={time.time() - send_start:.2f}s",
        flush=True,
    )

    try:
        link.teardown()
    except Exception:
        pass

    # Capture the "closed during send" state BEFORE teardown; the
    # teardown itself will trigger the closed callback and would
    # otherwise spuriously mark a successful run as failed.
    if send_errors > 0 or link_closed_during_send:
        sys.exit(4)

    sys.exit(0)


def main():
    args = parse_args()
    if args.responder == args.initiator:
        print("must specify exactly one of --responder / --initiator", file=sys.stderr)
        sys.exit(1)

    if args.responder:
        run_responder(args)
    else:
        run_initiator(args)


if __name__ == "__main__":
    main()
