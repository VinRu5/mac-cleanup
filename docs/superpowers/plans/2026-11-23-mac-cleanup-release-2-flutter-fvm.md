# Mac Cleanup Release 2 Flutter and FVM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean positively identified downloadable Flutter artifacts and inventory FVM SDK versions without claiming that arbitrary project references are known.

**Architecture:** Treat SDK versions and artifact caches as distinct boundaries. Resolve only canonical default roots from trusted home. Artifact caches may use exact filesystem removal. SDK versions are inventory-only because proving absence of references would require scanning arbitrary projects. Read-only fixed metadata and process checks annotate selected/active versions; custom FVM locations are informational.

**Tech Stack:** Python standard library, fixture projects and SDK layouts, mocked `ProcessRunner`, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0.
- Never delete projects, `.fvm` project links/config, `pubspec.yaml`, lockfiles, credentials, the selected SDK, an active SDK, or a project-referenced version.
- No network access, SDK install, Flutter command that warms caches, or custom root promotion during scan.

---

### Task 1: Add descriptor and representative fixtures

**Files:** Create `scripts/mac_cleanup/modules/flutter_fvm.py`, `tests/test_flutter_fvm.py`, fixture trees under `tests/fixtures/flutter_fvm/`; modify `scripts/mac_cleanup/modules/registry.py`.

- [ ] Fixture multiple installed versions, global selection, bounded reference metadata, active process evidence, SDK/artifact markers, broken/safe symlinks, and custom-root observations.
- [ ] Add failing tests for static default roots, deterministic boundaries `artifact-cache` and `sdk-version`, and custom roots reported without action.
- [ ] Implement descriptor registration and strict marker validation.
- [ ] Run `python3 -m unittest tests.test_flutter_fvm -v`; commit: `feat: describe flutter and fvm capabilities`.

### Task 2: Implement reference-aware scanning

**Files:** Modify `scripts/mac_cleanup/modules/flutter_fvm.py`, `tests/test_flutter_fvm.py`.

- [ ] Add failing tests for bounded fast scan, selected-only deep scan, stable IDs/fingerprints, and deterministic reference resolution from fixed fixture inputs.
- [ ] Mark positively identified regenerable artifacts safe; emit every SDK version with no action, annotating selected, active, bounded-reference, ambiguous, or malformed state without inferring anything from projects outside fixed roots.
- [ ] Fail closed on timeout, unreadable references, unexpected symlinks, and ownership mismatch.
- [ ] Run `python3 -m unittest tests.test_flutter_fvm -v`; commit: `feat: classify flutter fvm artifacts by use`.

### Task 3: Integrate approval and lifecycle

**Files:** Modify `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_integration.py`.

- [ ] Add batch and digest tests for `flutter-fvm:safe:artifact-cache` and prove no `sdk-version` batch can be built.
- [ ] Add preflight rechecks for artifact fingerprint and active tool state.
- [ ] Exercise the full fixture lifecycle; assert selected/referenced SDKs and project files remain unchanged.
- [ ] Run `python3 -m unittest tests.test_manifests tests.test_executor tests.test_integration -v`, then `python3 -m unittest discover -s tests -v`; commit: `test: integrate flutter fvm lifecycle`.

### Task 4: Release gate

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-2-flutter-fvm-read-only-smoke.md`.

- [ ] Document supported default locations, artifact-only cleanup, and inventory-only SDK versions; expand metadata only now.
- [ ] Validate the skill and run real `scan`, `plan`, `report` only, proving no Flutter/FVM command mutated or downloaded anything.
- [ ] Remove the temporary session and obtain security review.
- [ ] Commit: `docs: release flutter fvm module with read-only evidence`.
