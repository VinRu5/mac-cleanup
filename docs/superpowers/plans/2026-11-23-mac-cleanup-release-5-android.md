# Mac Cleanup Release 5 Android SDK, NDK, System Images, and AVD Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inventory Android SDK components by version and permit explicitly approved inactive component cleanup without claiming knowledge of arbitrary project references; keep AVD definitions and user data inventory-only.

**Architecture:** A static descriptor recognizes the default `~/Library/Android/sdk` component roots and `~/.android/avd` only as a no-action inventory root. Component markers produce stable version targets. A closed `android.sdkmanager-uninstall` handler accepts one normalized package ID, resolves the SDK-owned `sdkmanager`, and internally constructs the uninstall argv. Active emulator/ADB checks fail closed; possible future project downloads are represented by `review_required`, not by an unbounded reference scan.

**Tech Stack:** Python standard library, Android SDK/AVD fixture trees, mocked bounded process checks, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0; concepts may reuse accepted Release 3 primitives without coupling approvals.
- `ANDROID_HOME`, `ANDROID_SDK_ROOT`, and custom SDK paths are informational only.
- Never start or stop ADB/emulators, mutate AVDs, delete AVD user data, or execute `sdkmanager` during scan/dry-run.
- If active emulator/ADB state is active or ambiguous, affected targets have no executable action.

---

### Task 1: Define component and AVD fixture taxonomy

**Files:** Create `scripts/mac_cleanup/modules/android.py`, `tests/test_android.py`, `tests/fixtures/android/`; modify `scripts/mac_cleanup/modules/registry.py`.

- [ ] Fixture platforms, build-tools, NDKs, system images, package metadata, AVD definitions/data, active emulator evidence, custom roots, malformed components, symlinks, and wrong ownership.
- [ ] Add failing descriptor tests for default SDK component boundaries `platform`, `build-tools`, `ndk`, and `system-image`; define AVD as no-action inventory.
- [ ] Implement static descriptor and strict marker parsing.
- [ ] Run `python3 -m unittest tests.test_android -v`; commit: `feat: describe android component capabilities`.

### Task 2: Implement read-only discovery and classification

**Files:** Modify `scripts/mac_cleanup/modules/android.py`, `tests/test_android.py`.

- [ ] Test bounded fast/deep scans, stable component/version IDs, fingerprints, package metadata validation, deterministic issues, and no ADB/emulator start.
- [ ] Mark conclusively inactive, valid components review-required and explain that uninstall can require a later download. Keep active, ambiguous, malformed, custom-root, and every AVD target never-automatic; do not scan arbitrary projects or claim absence of references.
- [ ] Fail closed on tool timeout, incomplete activity evidence, active emulator, ownership change, and unexpected symlink.
- [ ] Run `python3 -m unittest tests.test_android -v`; commit: `feat: inventory android components without daemon starts`.

### Task 3: Add the typed SDK Manager action

**Files:** Create `scripts/mac_cleanup/vendor/android.py`, `tests/test_android_action.py`; modify `scripts/mac_cleanup/actions.py`, `scripts/mac_cleanup/executor.py`, `scripts/mac_cleanup/modules/android.py`, `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_integration.py`.

- [ ] Add failing tests that the handler accepts one normalized package ID obtained from validated package metadata and rejects paths, whitespace variants, shell text, arbitrary argv, and package/root mismatches.
- [ ] Resolve `sdkmanager` only inside the canonical default SDK capability, verify executable identity, and construct the uninstall argv internally; dry-run validates and reports that argv without executing it.
- [ ] Re-read package metadata, component fingerprint, emulator/ADB activity state, and executable identity immediately before apply. Record durable intent before invoking the vendor process and report conservative uncertainty when completion cannot be proven.
- [ ] Test separate `android:review:<component-boundary>` batches, digest/action binding, activity recheck, timeout, malformed output, and cross-component substitution.
- [ ] Run the fixture E2E in `tests.test_integration` for every executable boundary; assert AVD definitions/data and non-approved versions remain byte-identical.
- [ ] Run `python3 -m unittest tests.test_android_action tests.test_manifests tests.test_executor tests.test_integration -v`; commit: `feat: uninstall exact android component packages`.

### Task 4: Release gate

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-5-android-read-only-smoke.md`.

- [ ] Document separately which component classes are executable and which are inventory-only; never advertise an inventory-only class as cleanup.
- [ ] Run `python3 -m unittest discover -s tests -v` and the repository skill validator.
- [ ] Run real `scan`, `plan`, `report`; record argv/process state and prove no ADB server or emulator was started.
- [ ] Remove session, obtain security review, commit: `docs: release android inventory with read-only evidence`.
