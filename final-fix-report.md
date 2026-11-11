# Final fix report

- Durable-outcome correction base HEAD: `67c9be6` (the original round-2 base was
  `d0eff60`).
- Administrative mutation protocol: both the generated bootstrap and the
  self-contained verifier reload state under the stable session lock and reject any
  unresolved intent. Immediately before each destructive syscall, the verifier
  writes and rereads an exact `admin_apply` intent bound to the batch, target, and
  immutable operation digest. A crash before the result checkpoint leaves that
  intent authoritative and reporting remains accounting-unknown.
- Administrative resolution: only a matching result import (including CLI
  `verify`) may validate the immutable binding, verified result record, and target
  absence; publish the per-target apply outcome; and clear that exact intent last.
  Publication failure or a nonmatching/direct intent leaves the session blocked.
- Multi-target administrative batches advance one accounted target per run.
  Verified targets are checksum-validated no-ops on the next run, while remaining
  approved targets retain authorization. Regeneration, report guidance, accumulated
  result checkpoints, and per-target outcome publication remain consistent across
  rounds.
- Atomic persistence: JSON and report-text writers set and validate owner/mode and
  fsync temporary files before replacement; no fallible destination chmod remains.
  Directory fsync follows replacement. Intent clearing rereads authoritative state
  while the current lock is still asserted: a committed null intent is accepted,
  while a present intent or pre-replace failure remains blocked.
- State migration: newly written state uses strict schema v2. Strict legacy v1 state
  without `mutation_intent` is accepted, migrated once under the session lock to v2
  with a null intent, and preserves timestamps, manifests, targets, events, issues,
  critical stops, and administrative bindings. Concurrent loads converge; committed
  post-replace errors are reconciled, while pre-commit failures preserve v1.
- Durable diagnostics: mutation intent schema v1 now carries canonical
  `primary_issue` plus the optional exact administrative operation binding. Recovery
  checkpoints the original diagnostic before latch/outcome publication. Issue
  persistence and reports canonically deduplicate equivalent failures, so repeated
  path-safety failures retain one exact `executor.symlink-or-outside` critical rather
  than degrading to an outcome-publication error.
- Lock and schema audit: current/legacy version fields reject booleans and non-integer
  aliases; administrative intents must match the durable operation digest; bootstrap,
  verifier, migration reconciliation, outcome publication, and final intent clear all
  retain current-lock assertions at their authority boundaries.
- Durable outcome boundary: outcome schema v2 binds every record to a unique stable
  operation id. Mutation-backed apply/import uses the exact durable intent id; ordinary
  verification uses a canonical deterministic id. Exact retries return the same
  revalidated receipt, conflicting reuse fails closed, and post-replacement write
  errors are reconciled by rereading the strict artifact under the current lock.
  Legacy outcome schema v1 migrates deterministically and atomically under that lock.
- Receipt-gated intent resolution: direct apply and administrative import independently
  verify the recorder's receipt against the current `outcomes.json` record before
  clearing an intent. A missing/no-op/forged recorder result, a pre-replacement error,
  or `outcome_recorder=None` cannot clear it. The administrative reviewer reproduction
  (post-replace directory-fsync error followed by retry) records removed bytes exactly
  once and clears only after the durable receipt is proven.

## Verification

- Full suite after all changes: `python3 -m unittest discover -s tests` — 185 tests
  passed.
- Integration suite: `python3 -m unittest tests.test_integration` — 2 tests passed.
- Python compilation: every tracked Python file passed `py_compile`.
- `git diff --check`: passed.
- No dependency was installed and no skill installation was performed.
- `.superpowers/sdd/2026-10-08-mac-cleanup-mvp/progress.md` was not modified.

## Self-review

No remaining critical, important, or minor finding was identified in the round-2
diff.
