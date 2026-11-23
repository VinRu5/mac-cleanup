# Mac Cleanup Release 1 Xcode and CoreSimulator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conservative Xcode/CoreSimulator inventory and cleanup for positively identified regenerable artifacts while preserving archives, signing material, active simulators, and simulator data.

**Architecture:** A static descriptor exposes separate root capabilities and authorization boundaries. Initial executable filesystem batches cover canonical DerivedData and fixed cache roots. Device support and runtime artifacts are inventory-only because markers and inactivity do not prove future obsolescence.

**Tech Stack:** Python standard library, fixture trees, mocked `ProcessRunner`, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0.
- Never mutate `Archives`, projects, provisioning profiles, keychains, signing assets, `CoreSimulator/Devices`, or active runtime/data.
- Discovery must not launch Xcode or start CoreSimulator services. An unavailable or ambiguous activity check disables the affected executable batch.

---

### Task 1: Encode fixture taxonomy and descriptor

**Files:** Create `tests/fixtures/xcode/` marker trees; create `scripts/mac_cleanup/modules/xcode.py`; modify `scripts/mac_cleanup/modules/registry.py`; create `tests/test_xcode.py`.

- [ ] Add fixtures for DerivedData, archives, device support, caches, runtimes, simulator devices/user data, symlinks, wrong ownership, and active-process evidence.
- [ ] Add failing descriptor/detect tests for canonical roots below `~/Library/Developer/Xcode` and `~/Library/Developer/CoreSimulator`.
- [ ] Register executable boundaries `derived-data` and `xcode-cache`; register `device-support` and `simulator-runtime` as no-action inventory boundaries.
- [ ] Run `python3 -m unittest tests.test_xcode -v`; commit: `feat: describe xcode cleanup capabilities`.

### Task 2: Implement bounded scan and risk classification

**Files:** Modify `scripts/mac_cleanup/modules/xcode.py`, `tests/test_xcode.py`.

- [ ] Add failing tests for non-recursive fast scan, selected-only deep scan, stable IDs, fingerprints, threshold boundaries, and deterministic issues.
- [ ] Emit DerivedData/fixed cache targets as `safe_regenerable`; emit all device support/runtime candidates with no action, annotated by recognized identity and active state without claiming obsolescence.
- [ ] Emit archives, simulator devices/data, active or ambiguous runtimes, and signing-related paths as `never_automatic` with no action.
- [ ] Reject symlinked components, non-user ownership, root paths, and unexpected layouts.
- [ ] Run `python3 -m unittest tests.test_xcode -v`; commit: `feat: scan xcode artifacts conservatively`.

### Task 3: Integrate batches, execution, and verification

**Files:** Modify `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_integration.py`; update module code only if a contract defect is exposed.

- [ ] Add failing tests for `xcode:safe:derived-data`, separate safe cache batches, and proof that device-support/runtime observations cannot enter a batch.
- [ ] Prove action/root substitution, fingerprint change, active-state change, and target replacement suspend or critically stop before mutation as classified by policy.
- [ ] Run the fixture E2E sequence and assert only the approved exact target is removed; archives and simulator data remain byte-identical.
- [ ] Run `python3 -m unittest tests.test_manifests tests.test_executor tests.test_integration -v`; commit: `test: integrate xcode approval boundaries`.

### Task 4: Document and validate read-only behavior

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-1-xcode-read-only-smoke.md`.

- [ ] Expand metadata only to Xcode/CoreSimulator after tests pass; list exact exclusions.
- [ ] Run the full suite and skill validator.
- [ ] Run only real `scan`, `plan`, and `report`; record argv and prove no Xcode/CoreSimulator service was started and all targets remain pending.
- [ ] Remove the temporary session and obtain independent security review.
- [ ] Commit: `docs: release xcode module with read-only evidence`.
