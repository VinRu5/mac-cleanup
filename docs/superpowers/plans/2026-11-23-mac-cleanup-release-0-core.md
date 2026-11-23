# Mac Cleanup Release 0 Core Generalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generalize the engine for static built-in modules while preserving the exact `user-caches` behavior and making no new cleanup target executable.

**Architecture:** Add immutable descriptors and typed actions to the fixed registry. Resolve trusted roots from trusted account context plus descriptor rules. Bind module, action, batch, and root capability into versioned targets/manifests and approval digests. Migrate legacy sessions strictly and deterministically.

**Tech Stack:** Python 3 standard library, immutable dataclasses, `unittest`, JSON session artifacts.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- No new module or executable target in this release.
- No dynamic imports, shell strings, manifest-supplied argv, or target-derived roots.
- Existing v1 sessions remain resumable; migration is atomic, idempotent, lock-protected, and never reinterprets an old target as a new action.
- Administrative fallback supports only `filesystem.remove_exact`.
- Every commit leaves the full suite green.

## Required interfaces

```python
@dataclass(frozen=True)
class TrustedRootSpec:
    id: str
    home_components: tuple[str, ...]

@dataclass(frozen=True)
class BatchSpec:
    boundary: str
    risk: Risk
    action_kind: str

@dataclass(frozen=True)
class ModuleDescriptor:
    id: str
    trusted_roots: tuple[TrustedRootSpec, ...]
    batches: tuple[BatchSpec, ...]
    supported_action_kinds: tuple[str, ...]

@dataclass(frozen=True)
class TargetAction:
    kind: str
    root_capability: str
    parameters: tuple[tuple[str, str], ...] = ()
```

The registry returns immutable `(ModuleDescriptor, CleanupModule)` entries. The
dispatcher accepts a registered `TargetAction` plus the approved target and resolved
trusted capability; it never accepts shell text or caller-supplied argv.

---

### Task 1: Correct advertised scope

**Files:** Modify `SKILL.md`; modify `tests/test_integration.py`.

- [ ] Add a failing test asserting discovery metadata names only shipped `user-caches` cleanup while the body lists developer modules as deferred.
- [ ] Run `python3 -m unittest tests.test_integration -v`; expect the new assertion to fail.
- [ ] Narrow the frontmatter description to cache auditing/cleanup and resuming existing sessions; retain the explicit deferred list.
- [ ] Re-run the test and commit: `docs: align skill metadata with shipped scope`.

### Task 2: Define immutable module and action contracts

**Files:** Create `scripts/mac_cleanup/modules/descriptors.py`; modify `scripts/mac_cleanup/modules/base.py`, `scripts/mac_cleanup/modules/registry.py`, `scripts/mac_cleanup/models.py`; create `tests/test_module_contracts.py`; modify `tests/test_models.py`.

- [ ] Add failing tests for deterministic descriptor order, duplicate module/root/batch rejection, unsupported action rejection, and canonical serialization.
- [ ] Define `TrustedRootSpec`, `BatchSpec`, `ModuleDescriptor`, and `TargetAction` exactly as the required interfaces above, with strict non-empty IDs and deterministic tuple ordering.
- [ ] Define typed `TargetAction` with only `filesystem.remove_exact` or a registered static handler ID; reject arbitrary argv, shell source, and unknown parameters.
- [ ] Add explicit `module_id` and `action` to the current target contract without yet changing persisted schema.
- [ ] Make `registered_modules()` return fixed descriptor/discovery pairs and reject duplicate IDs at construction.
- [ ] Run `python3 -m unittest tests.test_module_contracts tests.test_models -v`; commit: `feat: add static module and action contracts`.

### Task 3: Version schemas and migrate legacy sessions

**Files:** Modify `scripts/mac_cleanup/models.py`, `scripts/mac_cleanup/sessions.py`, `scripts/mac_cleanup/jsonio.py`; modify `tests/test_models.py`, `tests/test_sessions.py`; add fixtures under `tests/fixtures/sessions/`.

- [ ] Add failing tests loading frozen v1 inventory/manifest/state records and asserting one exact v2 representation: `module_id=user-caches`, `filesystem.remove_exact`, and the legacy cache-root capability.
- [ ] Cover golden v1 sessions in scanned, planned, approved, dry-run, partially applied, unresolved-intent, verified, outcome-history, and generated-admin-artifact states.
- [ ] Add failures for unknown versions, extra fields, action mismatch, concurrent migration, interruption before replace, and interruption after replace.
- [ ] Implement explicit v2 inventory/target/action/manifest/state records and a single strict v1-to-v2 migration path under the session lock.
- [ ] Persist migration by atomic same-directory replace; ensure repeated load produces byte-equivalent canonical JSON.
- [ ] Never infer a module/action from an arbitrary v1 path; accept only the known legacy `user-caches:<name>` shape under the trusted cache root.
- [ ] Preserve a legacy manifest, batch ID, approval digest, intent, outcome, and admin binding as legacy records until that session finishes. Never regenerate, promote, or reinterpret a legacy approval under v2 semantics.
- [ ] Run `python3 -m unittest tests.test_models tests.test_sessions -v`; commit: `feat: migrate sessions to typed module actions`.

### Task 4: Build manifests from descriptors

**Files:** Modify `scripts/mac_cleanup/manifests.py`, `scripts/mac_cleanup/models.py`, `scripts/mac_cleanup/modules/registry.py`; modify `tests/test_manifests.py`, `tests/test_module_contracts.py`.

- [ ] Add failing tests for batch IDs `<module-id>:<risk>:<boundary>`, action inclusion in the digest, stable ordering, and rejection of cross-module batch/action/root reuse.
- [ ] Fix and test the only batch-token mapping: `safe_regenerable -> safe`, `review_required -> review`; `never_automatic` has no batch token because it cannot enter a batch.
- [ ] Replace the `user-caches` constants and target-ID parsing with descriptor lookup by explicit `module_id`.
- [ ] Select a batch only when target risk, action kind, boundary, and descriptor all match; keep `never_automatic` out of executable batches.
- [ ] Version policy independently, accept only registered enabled module IDs, and preserve the explicit `allow_review_required` gate.
- [ ] Prove a changed action or root capability changes the approval digest.
- [ ] Run `python3 -m unittest tests.test_manifests tests.test_module_contracts -v`; commit: `refactor: build approval batches from descriptors`.

### Task 5: Centralize trusted roots and typed dispatch

**Files:** Create `scripts/mac_cleanup/trusted_roots.py`, `scripts/mac_cleanup/actions.py`; modify `scripts/mac_cleanup/executor.py`, `scripts/mac_cleanup/paths.py`; modify `tests/test_executor.py`, `tests/test_paths.py`; create `tests/test_actions.py`.

- [ ] Add failing tests proving roots cannot come from target paths, manifests, environment variables, or custom configuration.
- [ ] Implement trusted-root resolution from canonical trusted home and static `TrustedRootSpec` components; validate ownership, containment, root markers, and symlink-free components.
- [ ] Implement a closed action dispatcher. Route `filesystem.remove_exact` to the existing descriptor-relative remover; reject all other handlers until separately registered.
- [ ] Bind preflight, durable mutation intent, verification, and accounting to module ID, action, root capability, target fingerprint, and manifest digest.
- [ ] Add TOCTOU tests for root/target replacement and cross-module capability substitution.
- [ ] Run `python3 -m unittest tests.test_actions tests.test_executor tests.test_paths -v`; commit: `refactor: dispatch typed actions within trusted roots`.

### Task 6: Generalize CLI, admin fallback, and reporting

**Files:** Modify `scripts/mac_cleanup/cli.py`, `scripts/mac_cleanup/admin_script.py`, `scripts/mac_cleanup/admin_verifier.py`, `scripts/mac_cleanup/reporting.py`; modify `tests/test_cli.py`, `tests/test_admin_script.py`, `tests/test_reporting.py`.

- [ ] Add failing tests for descriptor-driven scan aggregation and root resolution, generic batch names, action display, and rejection of vendor actions in admin fallback.
- [ ] Remove `_trusted_cache_root` and `user-caches` branches in favor of registry/root-capability lookup.
- [ ] Keep generated admin scripts limited to exact filesystem targets and bind their validation records to module, action, root capability, manifest digest, UID, and lock identity.
- [ ] Render per-module logical bytes, action kind, risk, exclusions, observed free-space delta, regeneration, and uncertainty without calling logical bytes “recovered space.”
- [ ] Run `python3 -m unittest tests.test_cli tests.test_admin_script tests.test_reporting -v`; commit: `refactor: generalize orchestration and reports`.

### Task 7: Preserve the MVP end to end

**Files:** Modify `scripts/mac_cleanup/modules/user_caches.py`, `references/module-behavior.md`, `references/risk-policy.md`, `tests/test_user_caches.py`, `tests/test_integration.py`, `tests/fixtures/expected_report.md`.

- [ ] Convert `UserCachesModule` to the descriptor contract without changing candidates or risk decisions.
- [ ] Add an E2E fixture for `scan -> plan -> approve -> dry-run -> apply -> verify -> reload -> report` and assert only the approved fixture target disappears.
- [ ] Add interruption-after-removal, unresolved-intent, corrupt-history, retry, and concurrent-reload cases against the generalized path.
- [ ] Update references to document descriptors, typed actions, deterministic batch IDs, and the still-single-module scope.
- [ ] Run `python3 -m unittest discover -s tests -v`; expect all tests to pass.
- [ ] Run the repository skill validator; expect success.
- [ ] Commit: `test: prove generalized engine preserves user cache safety`.

### Task 8: Read-only release validation

**Files:** Create `docs/validation/release-0-read-only-smoke.md` containing commands and redacted results only.

- [ ] Create a private temporary session and capture a process baseline.
- [ ] Run only `scan`, `plan`, and `report`; assert every target stays pending and no external mutating argv appears.
- [ ] Compare process state and prove no application or daemon started.
- [ ] Remove only the temporary session after recording evidence; do not approve, dry-run apply, apply, verify, or invoke admin fallback.
- [ ] Run the full suite again and obtain independent security review.
- [ ] Commit: `docs: record release 0 read-only validation`.
