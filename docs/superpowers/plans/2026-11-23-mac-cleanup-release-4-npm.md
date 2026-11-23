# Mac Cleanup Release 4 npm Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean only positively identified npm content-addressed cache data at the default trusted location, without scanning projects or exposing npm configuration and credentials.

**Architecture:** A static filesystem module recognizes the default `~/.npm/_cacache` layout and uses `filesystem.remove_exact`. npm configuration output may be recorded as capability evidence but never promotes a custom path. Logs, `_npx`, projects, `node_modules`, lockfiles, and `.npmrc` stay outside executable scope.

**Tech Stack:** Python standard library, npm cache fixture layouts, mocked process output, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0.
- Do not run `npm cache clean`, `npm cache verify`, install commands, or network operations during scan/dry-run.
- Never scan arbitrary `node_modules`; pnpm and Yarn require separate future designs.

---

### Task 1: Add descriptor and cache fixtures

**Files:** Create `scripts/mac_cleanup/modules/npm.py`, `tests/test_npm.py`, `tests/fixtures/npm/`; modify `scripts/mac_cleanup/modules/registry.py`.

- [ ] Fixture valid `_cacache`, corrupt/partial layout, logs, `_npx`, `.npmrc`, tokens, project trees, custom cache output, symlinks, and wrong ownership.
- [ ] Add failing tests for one static default root capability and boundary `content-cache`.
- [ ] Implement strict marker/layout validation and register only `filesystem.remove_exact` for the cache target.
- [ ] Run `python3 -m unittest tests.test_npm -v`; commit: `feat: describe npm cache capability`.

### Task 2: Implement bounded cache scan

**Files:** Modify `scripts/mac_cleanup/modules/npm.py`, `tests/test_npm.py`.

- [ ] Test deterministic IDs/fingerprints, deep-scan selection, unreadable/corrupt layouts, timeout, and custom-cache observation.
- [ ] Classify only valid default `_cacache` as safe-regenerable; classify everything else no-action.
- [ ] Prove logs, `_npx`, `.npmrc`, credentials, projects, lockfiles, and `node_modules` never become targets with actions.
- [ ] Run `python3 -m unittest tests.test_npm -v`; commit: `feat: scan npm content cache conservatively`.

### Task 3: Integrate approval and execution

**Files:** Modify `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_admin_script.py`, `tests/test_reporting.py`, `tests/test_integration.py`.

- [ ] Test `npm:safe:content-cache`, exact digest binding, root/action substitution rejection, and admin fallback limited to the exact cache target.
- [ ] Exercise full fixture lifecycle and prove all excluded fixture content remains byte-identical.
- [ ] Test fingerprint drift, symlink replacement, interrupted apply, reload, and idempotent verify/report.
- [ ] Run `python3 -m unittest tests.test_manifests tests.test_executor tests.test_admin_script tests.test_reporting tests.test_integration -v`, then `python3 -m unittest discover -s tests -v`; commit: `test: integrate npm cache lifecycle`.

### Task 4: Release gate

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-4-npm-read-only-smoke.md`.

- [ ] Document `_cacache`-only scope and exclusions; expand metadata only after tests.
- [ ] Run validator and real `scan`, `plan`, `report`; prove no npm mutation/network command ran.
- [ ] Remove session, obtain security review, commit: `docs: release npm module with read-only evidence`.
