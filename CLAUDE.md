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
internals).

### Compatibility is not parity

- **Compatibility:** Leviculum and Python-RNS nodes in the
  same mesh interoperate. Bytes on the radio are parseable by
  both sides; behaviour each side expects from a neighbour is
  delivered by the other.
- **Parity:** Leviculum's internal implementation mirrors
  Python's — same algorithms, same retry cadence, same
  scheduler internals.

We need the first. We do not need the second. In practice they
often align — doing it the Python way is frequently the
fastest path to compatibility — but they are distinct.

### Deviation rule

A deviation from Python-RNS implementation is acceptable iff
all three hold:

1. Wire-format compatibility is preserved (packets we emit are
   parseable by Python-RNS; and vice versa).
2. Semantic compatibility is preserved (behaviours Python
   neighbours expect from us are still delivered; behaviours
   we expect from Python neighbours are still accepted).
3. The deviation measurably improves Priority 1.

"Because Python does it differently" is not a counter-argument
on its own; only "this breaks wire or semantic compatibility"
is.

`docs/src/architecture-broadcast-python-parity.md` and similar
documents are historical reference material cataloguing what
Python does. They are useful for engineers implementing
compatibility; they are NOT policy commitments to maintain
exact internal parity.

## Test discipline

After every task, run all tests that fit a ~15 minute time budget:
- Unit tests
- Interop tests
- Integration tests (excluding LoRa hardware scenarios)

LoRa hardware tests run nightly because they take hours.

**Zero tolerance for flaky tests.** If a test fails, it is a real bug.
Re-running a test until it passes is forbidden. "Flaky" is not an
acceptable diagnosis or status. Every failure must be:

1. Root-caused — understand the underlying problem completely
2. Fixed at the root, not worked around
3. Verified the fix actually addresses the cause, not just masks it

**"Pre-existing fail" is not an excuse for not fixing.** Tests that
were red before this task still have to be diagnosed and fixed. We do
not accumulate broken tests as "known issues" — they hide regressions
and erode trust in the test suite.

Do not commit a task while tests are red.

## Why

Test discipline was neglected during one development sprint, leading
to bug accumulation that took multiple debugging sessions to resolve.
Tests are the early-warning system; if they don't run, regressions
slip in unnoticed.

## Protocol debugging discipline

Mesh-protocol bugs — packet loss, path-discovery failures, link
establishment timeouts, relay misbehaviour, announce propagation
issues — require stricter discipline than ordinary bugs. The
observation surface is wide (6+ stack layers, multiple nodes) and
the noise floor is high (timers, RF, scheduler jitter). Past
sessions have burned multi-day work on pattern-matched fixes that
missed the real cause. The rules below are mandatory when touching
any protocol-level behaviour.

1. **Read the bug ledger first.** Every actively-investigated
   protocol bug has a per-bug context file at `~/.claude/bugs/<N>.md`.
   Before any debug work on bug N, read that file. It carries the
   current hypothesis, what has been tried, what the next
   distinguishing experiment is. See `~/.claude/bugs/README.md`
   for the schema.

2. **mvr-test-first rule.** Before investigating a multi-node
   protocol failure, the first step is a minimum viable
   reproduction: 1-2 nodes, deterministic, < 5 seconds, a single
   named failure mode, full structured event logs from all sides.
   If an mvr test does not yet exist for the failure, **build it
   first**. Do not debug in the full Tier-3 scenario — the
   signal-to-noise ratio is too low to make progress.

3. **Baseline-before-debug.** Every "X is broken" investigation
   opens with a HEAD~N run to establish where the break happened.
   Without it, "regression vs pre-existing" is unknowable.

4. **No environmental variance, no statistical noise.** Any lab
   benchmark run below 100 % PDR is a bug. Any test flake is a
   deterministic bug with a flaky symptom. "Environmental
   variance" and "statistical noise" are not valid closing
   diagnoses in the controlled lab. See the local roadmap Bug #24
   umbrella.

5. **No inferential closure.** A protocol bug is closed only
   when (a) its mvr test passes at 100 %, and (b) the
   full-scenario test passes at the acceptance bar (usually
   20 × N green). "Mechanism X would explain the symptom" is a
   hypothesis, not a closure.

6. **One hypothesis at a time.** The ledger's CURRENT field
   holds exactly one hypothesis. Multiple hypotheses pursued in
   parallel means the bug is under-scoped; split it into
   sub-bugs with their own ledger files.

### Structured event-log format

Protocol-stack events should be emitted in a parseable form:

```
EVENT_NAME key1=val1 key2=val2 t=<ms>
```

One event per line, stable identifiers as keys, scalar values.
Grep and awk become debug tools. Tests spanning multiple nodes
should produce a unified timeline file merging all nodes' events
in timestamp order. This format is a work-in-progress: use it for
new instrumentation; when debugging, correlate event timestamps
across nodes.

### Why

Past session failure modes this discipline is designed to prevent,
all observed in 2026-04:

- A "mystery relay" `b2a8bea1…` was chased for two days as
  external RF contamination before being identified as the T114
  receiver's own transport hash under MIXED topology.
- The broadcast-parity investigation required six iterations
  because each pass inferred a plausible cause without measurement;
  only the fifth pass discovered Python's `ingress_control` as the
  real mechanism.
- The interop-test suite carried a latent TOCTOU port-allocation
  race for weeks, masked as sporadic `249/250 passed` runs.

The rules above are the structural response: isolation before
analysis, deterministic repro before hypothesis, ledger before
debug session.

Note also: rule 4 ("no flaky") and rule 5 ("no inferential
closure") express Priority 1 concretely. A test that succeeds
99 % of the time is a mesh that delivers 99 % of packets — one in
a hundred lost. For Priority 1 that is not success, it is a bug
under investigation.
