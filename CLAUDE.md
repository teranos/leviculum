# Project Policy for AI Assistants

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
