# Mac Cleanup Release 3 Gradle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean reconstructible Gradle download caches and eligible inactive distributions without touching projects, configuration, credentials, or signing material.

**Architecture:** The module recognizes fixed subtrees below the default trusted `~/.gradle` root and emits separate cache/distribution boundaries. Downloaded distributions are regenerable even when a project wrapper references them, so project-reference absence is not claimed; inactive distributions are review-required because deletion can trigger a later download. Ambiguous activity prevents execution.

**Tech Stack:** Python standard library, fixture cache/distribution layouts, mocked process checks, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0.
- Preserve `gradle.properties`, init scripts, credentials, wrapper files, keystores, project trees, and project-local `.gradle` state.
- `GRADLE_USER_HOME` and other custom roots are informational only.

---

### Task 1: Add descriptor, fixtures, and exclusions

**Files:** Create `scripts/mac_cleanup/modules/gradle.py`, `tests/test_gradle.py`, `tests/fixtures/gradle/`; modify `scripts/mac_cleanup/modules/registry.py`.

- [ ] Fixture download cache, wrapper distributions, configuration, credentials, keystores, project wrappers, custom root, active processes, symlinks, and malformed layouts.
- [ ] Add failing descriptor tests for only default `~/.gradle/caches` and `~/.gradle/wrapper/dists` capabilities.
- [ ] Register boundaries `download-cache` and `distribution`; encode all preserved paths as no-action.
- [ ] Run `python3 -m unittest tests.test_gradle -v`; commit: `feat: describe gradle cleanup capabilities`.

### Task 2: Implement bounded scan and active/reference checks

**Files:** Modify `scripts/mac_cleanup/modules/gradle.py`, `tests/test_gradle.py`.

- [ ] Test fast/deep bounds, deterministic IDs, fingerprints, cache marker validation, distribution version parsing, and active-use timeout/ambiguity.
- [ ] Classify reconstructible download cache safe and conclusively inactive distributions review-required; report that a wrapper may require a later re-download.
- [ ] Keep active, malformed, custom-root, and protected configuration targets never-automatic. Do not scan arbitrary projects or claim a distribution is unreferenced.
- [ ] Run `python3 -m unittest tests.test_gradle -v`; commit: `feat: scan gradle cache and distributions safely`.

### Task 3: Integrate and prove lifecycle safety

**Files:** Modify `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_integration.py`.

- [ ] Test `gradle:safe:download-cache` and `gradle:review:distribution`, policy omission, digest stability, and preflight rechecks.
- [ ] Test symlink replacement, active-process change, and interrupted/resumed apply.
- [ ] Run E2E fixture and assert projects/config/keystores remain byte-identical.
- [ ] Run `python3 -m unittest tests.test_manifests tests.test_executor tests.test_integration -v`, then `python3 -m unittest discover -s tests -v`; commit: `test: integrate gradle approval boundaries`.

### Task 4: Release gate

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-3-gradle-read-only-smoke.md`.

- [ ] Document default-root scope and exclusions; expand metadata only after validation.
- [ ] Run skill validator and real read-only smoke; prove no Gradle daemon starts and no existing daemon is contacted in a mutating way.
- [ ] Remove session, obtain security review, commit: `docs: release gradle module with read-only evidence`.
