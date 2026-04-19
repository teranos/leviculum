# Project Policy for AI Assistants

## Priorities

**Priority 1 (both clauses, neither subordinate):**

1. Robust, fault-tolerant mesh operation — maximum packet
   delivery, correct behaviour under load, graceful failure
   handling.
2. Compatibility with Python-Reticulum nodes in the same mesh
   — wire format, semantics, and on-the-air behaviour must
   interoperate cleanly with Python-RNS peers.

**Priority 2:** Speed.

**NOT a priority:** Strict Python-RNS *implementation* parity
(same algorithms, same retry timings, same state-machine
internals). Compatibility means our stacks interoperate at the
wire and semantic level; parity means our internals mirror
Python's. We need the first, not the second — though in
practice they often align.

Compatibility here extends beyond the radio: **`lnsd` and
Python-RNS `rnsd` share the shared-instance IPC and config-
file format**, so client tools (`lns selftest`, `rnstatus`,
`rnprobe`, `rncp`) drive either daemon transparently. This
drop-in property is a design goal, not incidental. In
comparison tests between the two stacks, exploit it: the
test harness points the same driver at either daemon, never
a parallel per-stack driver.

### Deviation rule

A deviation from Python-RNS implementation is acceptable iff
all three hold:

1. Wire-format compatibility is preserved.
2. Semantic compatibility is preserved (behaviours Python
   peers expect from a neighbour are still delivered).
3. The deviation measurably improves Priority 1.

"Because Python does it differently" is not a counter-argument
on its own; only "this breaks wire or semantic compatibility"
is. Docs under `docs/src/architecture-*-python-parity.md` are
historical reference material — not commitments to maintain
exact internal parity.

## Architecture: interface isolation

**Only the interface has awareness of the quirks of its carrier
medium, and adapts its behaviour accordingly. The core, the
transport, and the daemon are media-agnostic.**

A half-duplex LoRa interface knows it cannot simultaneously TX
and RX, knows its RadioSettings (bandwidth, spreading factor,
coding rate), knows the per-packet airtime budget. It holds
packets back, spaces TX events, does its own randomised pre-TX
jitter on top of the RNode firmware's CSMA. A TCP/IP interface
has none of that; it just writes bytes.

The core and transport pass packets to interfaces without
caring what medium they're on. An announce, a LinkRequest, a
data packet, a resource chunk — all just bytes at the interface
boundary. A packet is a packet. **No type-awareness in
collision-avoidance logic.**

**How this binds you when writing a fix:** if a proposed fix
for a collision / contention / duplex problem introduces an
awareness flag or counter in `transport.rs`, `node/`, or the
daemon ("is a link in flight?", "am I forwarding a
LinkRequest?"), **it is at the wrong layer — redirect it to the
interface**. Interface implementations can diverge from Python-
Reticulum's thin-serial-writer style where the divergence
satisfies the deviation rule above.

## Test discipline

After every task, run all tests that fit a ~15 minute time
budget (unit + interop + integration, excluding LoRa hardware).
LoRa hardware tests run nightly.

**Zero tolerance for flaky tests.** A test failure is a real
bug. Re-running until green is forbidden. Every failure must
be root-caused, fixed at the root, and verified to address the
cause rather than mask it.

**"Pre-existing fail" is not an excuse.** Tests red before this
task still have to be diagnosed and fixed. We do not accumulate
broken tests as "known issues".

Do not commit a task while tests are red.

## Debugging discipline

When fixing a bug whose mechanism is not obvious on sight,
write a minimal reproducing test first, then the fix. Default
is minimal-test-first; skipping requires a justified reason.

1. **Default: minimal reproducing test before fix.** A minimal
   test reproduces exactly the failure mode and nothing more.
   Canonical home: `reticulum-std/tests/mvr/`. An existing
   test reliably made red for this bug also counts. Write it
   before the fix; writing the fix first lets you stop at
   "seems to work".

2. **When skipping is acceptable.** Trivial fixes (typo,
   obvious null deref, vacuous off-by-one) do not need a
   dedicated test. An equivalent reproducer already in the
   suite counts as the minimal test. **"I already know the
   fix" is NOT a valid skip reason** — that is precisely where
   a test prevents wishful thinking.

3. **Green minimal test alone is not closure.** Close the bug
   only when BOTH (a) the minimal test is green AND (b) the
   full end-to-end scenario is also green. Isolation
   characterises one mechanism; real context may contain more.
   Past sessions showed this directly: isolated tests went
   green while hardware stayed red.

4. **Hypotheses get tested, not implemented.** Suspect X?
   Write the test that would confirm or refute X. If refuted,
   try the next hypothesis. Do not ship a fix for a hypothesis
   not first shown by measurement to be the actual cause.

5. **Reference-first for compatibility-bound bugs.** When
   failing behaviour is something we match to a reference
   (Python-RNS for protocol mechanics, RNode firmware for LoRa
   CSMA), measure the reference on the same failing scenario
   BEFORE committing to a fix direction.

   **"Same scenario" is strict: all inputs equal except the
   stack under test.** Exploit the `lnsd`/`rnsd` drop-in
   compatibility — the test harness must be literally the
   same client code (e.g. `lns selftest`) pointed at either
   daemon, never a parallel per-stack driver. A parallel
   driver vitiates the A/B contract by smuggling config
   differences (cadences, phases, timeouts) into what claims
   to be a stack comparison. **Before interpreting any A/B
   result, count event volumes on both sides.** If volumes
   differ by more than a few percent, the comparison is
   invalid and any downstream timing analysis is meaningless
   — fix the test, not the hypothesis.

## Protocol debugging discipline

Mesh-protocol bugs (packet loss, path-discovery failures, link
timeouts, relay misbehaviour, announce propagation) add
requirements on top of §Debugging discipline. The observation
surface is wide (6+ stack layers, multiple nodes) and the
noise floor is high (timers, RF, scheduler jitter).

The general minimal-test-first and green-minimal-alone-is-not-
closure rules apply with these specifics:

- **mvr constraints for protocol bugs:** 1-2 nodes,
  deterministic, < 5 seconds, single named failure mode, full
  structured event logs from all sides.
- **Acceptance bar at closure:** minimal test green AND full
  scenario green at 20 × N.

Additional mandatory rules:

1. **Read the bug ledger first.** Every actively-investigated
   protocol bug has a context file at `~/.claude/bugs/<N>.md`.
   Read it before any debug work. Schema at
   `~/.claude/bugs/README.md`.

2. **Baseline-before-debug.** Every "X is broken"
   investigation opens with a HEAD~N run to establish where
   the break happened. Without it, regression-vs-pre-existing
   is unknowable.

3. **No environmental variance, no statistical noise.** Any
   lab benchmark below 100 % PDR is a bug. Any flake is a
   deterministic bug with a flaky symptom. These framings are
   not valid closing diagnoses in the controlled lab.

4. **One hypothesis at a time.** The ledger's CURRENT field
   holds exactly one hypothesis. Multiple in parallel = under-
   scoped bug, split into sub-bugs with their own ledger
   files.

5. **Null-hypothesis before external hypothesis.** When an
   unexpected entity appears in logs — unknown hash, packet
   from an unplaceable source, unexpected state — first check
   "is this us from a different angle?" Compare the mysterious
   identifier against every known identity of every node in
   the scenario. The `b2a8bea1`-as-T114's-own-transport-hash
   episode (2026-04-15/16) cost two days that five minutes of
   self-check would have prevented.

### Structured event-log format

Protocol events should be emitted as:

```
EVENT_NAME key1=val1 key2=val2 t=<ms>
```

One event per line, stable keys, scalar values. Grep and awk
become debug tools. Multi-node tests produce a unified
timeline merging all nodes' events in timestamp order.
