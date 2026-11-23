# Mac Cleanup Modular Expansion Roadmap

**Goal:** Ship the developer-cleanup scope as eight independently reviewable releases without weakening the existing approval, trusted-root, durable-intent, dry-run, verification, or reporting contracts.

**Spec:** `docs/plans/2026-11-23-mac-cleanup-modular-expansion-design.md`

## Current discrepancy

The `SKILL.md` discovery description advertises developer-tool cleanup although the executable registry contains only `user-caches`. Release 0 narrows that metadata first. A later release may name a tool only after its module passes every gate below.

## Release train

| Release | Deliverable | Depends on | Maximum executable risk |
|---|---|---|---|
| 0 | Generic descriptor, action, trusted-root, batch, and schema engine | Current MVP | Existing behavior only |
| 1 | Xcode/CoreSimulator | 0 | `safe_regenerable`; DeviceSupport/runtimes inventory-only |
| 2 | Flutter/FVM | 0 | `safe_regenerable` artifacts; SDK versions inventory-only |
| 3 | Gradle | 0 | `review_required` |
| 4 | npm | 0 | `safe_regenerable` |
| 5 | Android SDK/NDK/system images; AVD inventory only | 0, reuses concepts from 3 | `review_required` |
| 6 | Homebrew vendor dry-run inventory | 0 | Inventory-only until exact candidate selection is provable |
| 7 | Conservative inactive Docker Desktop cache | 0 | `safe_regenerable`; build cache report-only |

Release dependencies permit reuse of code primitives only. They never permit reuse of approvals, manifests, batches, trusted roots, action bindings, or mutation intents.

## Plans

- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-0-core.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-1-xcode.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-2-flutter-fvm.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-3-gradle.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-4-npm.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-5-android.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-6-homebrew.md`
- `docs/superpowers/plans/2026-11-23-mac-cleanup-release-7-docker.md`

## Gate applied to every release

- [ ] Work starts from a clean branch created from the last accepted release.
- [ ] New behavior is fixture-driven and begins with a failing test.
- [ ] Scan, plan, report, and dry-run are proven read-only.
- [ ] Manifest and approval digests are deterministic across reloads.
- [ ] Symlink, ownership, fingerprint, timeout, malformed-output, interruption, retry, and cross-module capability tests relevant to the release pass.
- [ ] `python3 -m unittest discover -s tests -v` passes.
- [ ] Skill validation passes and documentation describes only shipped scope.
- [ ] Independent security review finds no capability widening.
- [ ] A private real-machine session runs only `scan`, `plan`, and `report`; no approval, apply, admin script, daemon/app start, or real cleanup occurs.
- [ ] Real-machine evidence confirms all targets remain pending and custom/ambiguous roots are informational.
- [ ] The temporary smoke session is removed after evidence capture.

## Release discipline

Each release gets its own branch, pull request, fixture evidence, security review, and merge decision. A failed or deferred release cannot block or alter earlier shipped modules. A real `apply` trial is outside these plans and requires a new explicit human approval for one small `safe_regenerable` batch.
