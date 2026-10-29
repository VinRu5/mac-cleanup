# Final fix report

- Base HEAD: `73ae5d5`
- Final review findings addressed: session-directory and lock ingress hardening;
  interrupted-removal accounting; unavailable cache-root detection; minimal
  installation handoff allowlist.
- Session safety: canonical descriptor-relative traversal rejects aliases and
  symlinks before state mutation; existing session directories and lock objects are
  never chmodded; lock owner, mode, link count, device, and inode are validated and
  revalidated after `flock` while stable-inode retry, reentrancy, and fork cleanup
  remain covered.
- Accounting: interrupted exact removal persists an unknown aggregate plus explicit
  uncertain target ids and issue; known successful target counts remain available;
  strict durable validation and report rendering reject forged exact-zero records.
- Post-removal checkpointing: failures while persisting `applied`, `verified`, or the
  resulting critical stop are converted to a critical suspended outcome. The current
  target remains accounting-unknown, completed earlier target counts are preserved,
  and no speculative lifecycle transition or deletion retry is attempted.
- Durable mutation/accounting protocol: authoritative `state.json` now records a
  strict, operation/batch/target-bound intent immediately before the first exact
  deletion. It survives deletion, lifecycle, free-space, outcome-publication, latch,
  and final-checkpoint failures. Apply, verify, administrative paths, and reporting
  check this authority before outcome reads or mutation, return the critical stop,
  never retry or credit the uncertain target, and require a fresh session/rescan.
- Two-phase completion: the CLI supplies the executor a narrow durable-outcome
  callback. The intent is cleared only after that callback returns and the final
  state checkpoint succeeds. Direct executor callers leave the intent unresolved by
  default; a successful outcome write followed by a failed clear remains blocked and
  is reported conservatively.
- Conservative reporting: an unresolved intent takes precedence over missing,
  malformed, or even successfully written outcome history. Removed logical bytes and
  free-space recovery remain unknown, while the report names the uncertain target and
  the required fresh-session recovery action.
- Discovery: present but inaccessible cache roots remain detected and yield one
  `user-caches.cache-root-unavailable` warning; absent roots remain undetected.
- Installation handoff: only `SKILL.md`, `agents/`, `references/`, `scripts/`, and
  required package files are allowlisted. Git metadata, `.superpowers`, reports,
  bytecode caches, and session artifacts are excluded. No installation was performed.

## Verification

- Targeted final-finding suite: 84 tests passed before the final lock self-review.
- Post-review focused suite: session, executor, CLI, reporting, administrative, and
  integration paths — 120 tests passed.
- Full suite after all changes: `python3 -m unittest discover -s tests` — 160 tests
  passed.
- Integration suite: 2 tests passed.
- Python compilation: all tracked Python files passed `py_compile`.
- `git diff --check`: passed.
- `quick_validate.py`: not runnable in the current interpreter because `PyYAML` is
  unavailable (`ModuleNotFoundError: yaml`); no dependency was installed.
- Untracked `__pycache__` directories were removed.
- `.superpowers/sdd/2026-10-08-mac-cleanup-mvp/progress.md` was not modified.

## Self-review

No remaining critical, important, or minor finding was identified in the final diff.
