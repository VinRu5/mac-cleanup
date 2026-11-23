# Mac Cleanup Release 7 Conservative Docker Desktop Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inventory Docker-related disk usage conservatively and clean only the exact immediate Docker Desktop cache child when Docker is conclusively inactive.

**Architecture:** The trusted root capability is module-scoped `~/Library/Caches`; its only allowed target is the exact immediate child `com.docker.docker`. A broad denylist covers user/container state. The module does not claim Docker is uninstalled: inactive installed and post-uninstall cases use the same regenerable cache rule. Docker build cache remains report-only because inspecting it would require daemon contact.

**Tech Stack:** Python standard library, Docker Desktop residue fixture trees, mocked process evidence, `unittest`.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Global Constraints

- Depends on accepted Release 0.
- If Docker, containerd, virtualization, Kubernetes, or related processes are active or activity state is ambiguous, emit no executable Docker batch.
- Always exclude volumes, containers, named images, contexts, credentials, Kubernetes state, settings, VM disks, and `Docker.raw`.
- Never start/contact the Docker daemon and never run prune commands.

---

### Task 1: Encode cache allowlist and state denylist

**Files:** Create `scripts/mac_cleanup/modules/docker.py`, `tests/test_docker.py`, `tests/fixtures/docker/`; modify `scripts/mac_cleanup/modules/registry.py`.

- [ ] Fixture active/inactive process evidence, the fixed Docker Desktop cache, full Docker Desktop state, `Docker.raw`, volumes, images, containers, contexts, credentials, Kubernetes data, symlinks, and custom locations.
- [ ] Add failing descriptor tests proving the trusted root is `~/Library/Caches`, the only allowed immediate target name is `com.docker.docker`, and the root itself can never be removed; encode all state roots as no-action exclusions.
- [ ] Register boundary `desktop-cache`; model build-cache observations with no action.
- [ ] Run `python3 -m unittest tests.test_docker -v`; commit: `feat: describe conservative docker residue scope`.

### Task 2: Implement inactive-only scan

**Files:** Modify `scripts/mac_cleanup/modules/docker.py`, `tests/test_docker.py`.

- [ ] Test deterministic process/activity evaluation, timeout/ambiguity, fixed cache marker validation, bounded fast/deep scan, IDs/fingerprints, and custom-root observations.
- [ ] Emit the fixed cache as safe-regenerable only when Docker is conclusively inactive; make no inference from application absence or uninstall receipts.
- [ ] Emit build cache as informational only; emit every state/VM/user-data class as never-automatic.
- [ ] Prove scan makes no Docker CLI/socket/daemon call.
- [ ] Run `python3 -m unittest tests.test_docker -v`; commit: `feat: inventory inactive docker cache safely`.

### Task 3: Integrate exact residue cleanup

**Files:** Modify `tests/test_manifests.py`, `tests/test_executor.py`, `tests/test_admin_script.py`, `tests/test_reporting.py`, `tests/test_integration.py`.

- [ ] Test `docker:safe:desktop-cache`, exact root/action/digest binding, and absence of any build-cache executable batch.
- [ ] Recheck inactive/uninstalled state and fingerprint immediately before mutation; active-state drift suspends without deletion.
- [ ] Exercise E2E fixture and assert `Docker.raw`, volumes, images, containers, credentials, contexts, Kubernetes state, and settings remain byte-identical.
- [ ] Add symlink replacement, ownership drift, interruption, retry, and cross-module root tests.
- [ ] Run `python3 -m unittest tests.test_manifests tests.test_executor tests.test_admin_script tests.test_reporting tests.test_integration -v`, then `python3 -m unittest discover -s tests -v`; commit: `test: integrate docker cache lifecycle`.

### Task 4: Release gate and explicit go/no-go statement

**Files:** Modify `SKILL.md`, `references/module-behavior.md`, `references/risk-policy.md`; create `docs/validation/release-7-docker-read-only-smoke.md`.

- [ ] Document that executable scope is the inactive Docker Desktop cache only; build cache and all Docker state remain report-only or excluded.
- [ ] Run validator and real `scan`, `plan`, `report`; prove no Docker-related process/socket/daemon was started or contacted and all targets remain pending.
- [ ] If the machine is active or state is ambiguous, record the expected no-batch result rather than changing the gate.
- [ ] Remove session, obtain security review, commit: `docs: release conservative docker residue module`.
