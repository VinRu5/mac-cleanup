# Mac Cleanup Release 6 Homebrew Dry-Run Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic Homebrew cleanup inventory from recognized vendor dry-run output without authorizing a cleanup command that could widen beyond the observed candidates.

**Architecture:** Trust only a recognized Homebrew executable at a static supported location with ownership/marker validation. Discovery records version and parses `brew cleanup --dry-run` through a versioned parser. Targets have no action and cannot enter a batch: Homebrew does not provide an atomic operation bound to the exact artifact set observed by the dry-run, so a generic cleanup could widen after approval.

**Tech Stack:** Python standard library, recorded Homebrew output fixtures, mocked `ProcessRunner`, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0.
- Only vendor output may identify candidates; never recursively delete the Homebrew prefix.
- Preserve installed formulae/casks, taps, pins, configuration, services, and user data.
- Unsupported versions, locale/output drift, timeout, active mutation, or parser ambiguity fail closed.
- No approval, apply handler, administrative fallback, or executable Homebrew batch in this release.

---

### Task 1: Define capability and versioned parser fixtures

**Files:** Create `scripts/mac_cleanup/modules/homebrew.py`, `scripts/mac_cleanup/vendor/homebrew.py`, `tests/test_homebrew.py`, `tests/fixtures/homebrew/`; modify `scripts/mac_cleanup/modules/registry.py`.

- [ ] Record supported empty/non-empty dry-run output plus pinned items, unsupported version, unknown line, localized/malformed output, timeout, and executable substitution fixtures.
- [ ] Add failing tests for static executable locations, marker/ownership checks, exact supported versions, normalized parser records, and rejection of unknown output.
- [ ] Register inventory boundary `vendor-cleanup` with no supported action kind.
- [ ] Run `python3 -m unittest tests.test_homebrew -v`; commit: `feat: parse homebrew cleanup capability`.

### Task 2: Emit deterministic vendor targets

**Files:** Modify `scripts/mac_cleanup/modules/homebrew.py`, `scripts/mac_cleanup/vendor/homebrew.py`, `tests/test_homebrew.py`.

- [ ] Test deterministic IDs, logical-byte estimates explicitly labeled vendor estimates, normalized-output digest, and read-only command allowlist.
- [ ] Emit only parser-recognized cleanup artifacts as review-required observations with no action; preserve pins and all installed/configured objects.
- [ ] Make empty/unsupported/ambiguous results informational and prove no Homebrew manifest batch is possible.
- [ ] Run `python3 -m unittest tests.test_homebrew -v`; commit: `feat: inventory homebrew vendor cleanup`.

### Task 3: Prove inventory cannot become authorization

**Files:** Modify `scripts/mac_cleanup/reporting.py`, `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_admin_script.py`, `tests/test_reporting.py`, `tests/test_integration.py`.

- [ ] Add failing tests that Homebrew observations cannot enter a manifest, receive approval, dispatch an action, or generate an admin script.
- [ ] Render vendor-estimated logical bytes and exact dry-run observations as inventory, clearly stating that no cleanup action is available.
- [ ] Add timeout, output drift, executable replacement, unknown version/output, and cross-module action-injection tests.
- [ ] Run `python3 -m unittest tests.test_homebrew tests.test_manifests tests.test_executor tests.test_admin_script tests.test_reporting tests.test_integration -v`; commit: `test: keep homebrew inventory non executable`.

### Task 4: Release gate

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-6-homebrew-read-only-smoke.md`.

- [ ] Document supported versions/output and inventory-only status; do not advertise Homebrew cleanup.
- [ ] Real-machine smoke may run only read-only capability/version and cleanup dry-run commands through `scan`, then `plan` and `report`; never run actual `brew cleanup`.
- [ ] Prove no service/package state changed, remove session, obtain security review.
- [ ] Commit: `docs: release homebrew dry-run inventory`.
