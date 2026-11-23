# Mac Cleanup Modular Expansion Design

## Objective

Extend `mac-cleanup` through independent, progressive releases while preserving the
deterministic approval, trusted-root, durable-intent, locking, verification, and
reporting guarantees established by the `user-caches` MVP.

The expansion covers, in order:

1. engine generalization;
2. Xcode and CoreSimulator;
3. Flutter and FVM;
4. Gradle;
5. npm;
6. Android SDK, NDK, system images, and AVD inventory;
7. Homebrew;
8. conservative Docker cleanup.

Future large-residue support must use explicit built-in modules. The product will not
gain a generic large-directory scanner or treat size as deletion authorization.

## Current-state discrepancy

The skill description advertises developer-tool cleanup, but the current executable
scope contains only `user-caches`. `SKILL.md` correctly explains that limitation in
its body, while the discovery metadata is broader than the implementation.

Release 0 must narrow discovery metadata to the shipped scope. Each later release may
expand the description only after its module passes its independent release gate.

## Architectural decision

Use a generalized static module contract. Do not add more `user-caches` conditionals
to the engine and do not introduce dynamically loaded plugins.

The fixed registry remains deterministic and code-owned. Each built-in module
provides a descriptor, discovery implementation, and typed actions. The engine alone
owns authorization and execution.

```text
ModuleDescriptor
|- id
|- trusted_root_specs
|- batch_specs
|- supported_action_kinds
`- discovery implementation
```

### Module responsibilities

A module may:

- detect fixed capabilities and roots without mutation;
- perform bounded fast and deep scans;
- emit deterministic targets, issues, and typed actions;
- classify targets using the shared risk model;
- validate module-specific markers and active-use conditions.

A module may not:

- approve targets or construct approval digests;
- derive a deletion capability from a manifest path;
- mutate files during scan or dry-run;
- execute arbitrary shell text;
- transition session state;
- clear durable mutation intents;
- widen from a selected target to siblings or parent roots.

### Engine responsibilities

The engine remains the only authority for:

- manifest schemas, immutable digests, and per-batch approval;
- trusted-root resolution from built-in module semantics;
- preflight, fingerprints, and TOCTOU defenses;
- durable mutation and accounting intents;
- locks, recovery, retries, and state migration;
- typed action dispatch;
- dry-run, apply, verify, outcome publication, and reporting;
- administrative fallback for supported action kinds.

## Trusted roots

Trusted roots are resolved from the trusted account context and static module rules,
never from candidate paths, manifests, environment variables, or user-provided
strings.

Initial module releases support only canonical default locations. A custom tool
location may be reported as informational, but it cannot become executable until a
future design defines marker validation, ownership, containment, and an explicit
capability rule.

Examples such as `ANDROID_HOME`, `GRADLE_USER_HOME`, npm configuration, FVM config,
Docker contexts, and Homebrew prefixes are observations rather than automatic trust
anchors.

## Target and action schema

Approval-eligible targets explicitly bind:

```text
module_id
target_id
canonical_path
risk
fingerprint
logical_bytes
action
```

The action is included in the immutable manifest and approval digest. Supported
action classes are:

- `filesystem.remove_exact`, using the existing descriptor-relative remover;
- a static vendor handler such as `android.sdkmanager-uninstall`, with typed parameters and an
  internally constructed argv;
- no action for informational or `never_automatic` targets.

No manifest may carry shell source or arbitrary argv. Each action must match the
module descriptor, risk, batch, and trusted-root capability.

## Batch model

Batch identifiers are deterministic:

```text
<module-id>:<risk>:<authorization-boundary>
```

The serialized risk token mapping is fixed: `safe_regenerable` becomes `safe`,
`review_required` becomes `review`, and `never_automatic` has no token because it
cannot enter an executable batch.

Examples:

- `xcode:safe:derived-data`;
- `xcode:safe:xcode-cache`;
- `gradle:safe:download-cache`;
- `npm:safe:content-cache`.

Targets with different risks, action handlers, privilege requirements, active-use
checks, or regeneration costs cannot share a batch. Approval is always for one exact
batch digest.

## Schema compatibility

Inventory, target, action, manifest, policy, and report schemas will receive explicit
new versions. Existing `user-caches` sessions remain readable and resumable through
strict deterministic migration. Old records are not reinterpreted as new module
actions.

Legacy approvals, manifests, intents, outcome histories, and administrative
bindings retain their legacy schema and digest semantics until their session
finishes. Migration never regenerates or promotes an existing approval digest.

Migration must be atomic, idempotent, lock-protected, and covered by concurrency and
post-replace failure tests.

## Progressive releases

### Release 0: engine generalization

- Introduce module descriptors, trusted-root specs, batch specs, and typed actions.
- Remove `user-caches` assumptions from manifest construction, executor root
  validation, administrative validation, CLI orchestration, and reporting.
- Migrate schemas while preserving current sessions.
- Correct skill discovery metadata to the actual shipped scope.

No new cleanup target ships in this release.

### Release 1: Xcode and CoreSimulator

Safe targets include canonical DerivedData and positively identified regenerable
Xcode caches. Device support and simulator runtimes remain inventory-only because
identity and inactivity do not prove future obsolescence.

Projects, archives, signing assets, provisioning profiles, keychains, active
simulators, and simulator user data are `never_automatic`.

### Release 2: Flutter and FVM

Separate downloadable Flutter artifacts from installed FVM SDK versions. Artifact
caches may be executable; SDK versions are inventory-only because absence of
references cannot be proved without scanning arbitrary projects. Project
directories, `pubspec.yaml`, lockfiles, credentials, and active SDKs are excluded.

### Release 3: Gradle

Cover reconstructible download caches and eligible inactive distributions. A
distribution may be referenced by an unscanned project wrapper, so the module does
not claim otherwise; it remains review-required because removal can force a later
download. Preserve wrapper files, project `.gradle` state unless specifically
designed later, configuration, credentials, signing material, and keystores.

This release establishes reusable active-process checks needed by Android.

### Release 4: npm

Limit scope to the package-manager cache identified through read-only capability
checks. Never scan or delete arbitrary `node_modules`, projects, lockfiles, `.npmrc`,
tokens, or registry configuration. pnpm and Yarn require later independent modules.

### Release 5: Android SDK, NDK, system images, and AVD inventory

Treat SDK platforms, NDKs, build tools, and system images as component/version
targets. Inactive components require review and use a typed exact-package SDK
Manager handler; the module does not scan projects or claim components are
unreferenced. AVD definitions and user data remain `never_automatic`; active emulator
or ADB-related uncertainty blocks the batch. Discovery must not start ADB or an
emulator.

### Release 6: Homebrew

Use vendor read-only commands and `brew cleanup --dry-run` output. Artifacts Homebrew
identifies remain inventory-only: a generic cleanup command is not atomically bound
to the exact dry-run artifact set and could widen after approval. Installed formulae,
casks, taps, pins, and configuration remain preserved.

Unrecognized output or unsupported Homebrew versions fail closed.

### Release 7: conservative Docker

Use a module-scoped `~/Library/Caches` capability and include only its exact immediate
`com.docker.docker` child when Docker is conclusively inactive; never remove the
trusted root itself. Do not infer an uninstall from application absence or receipts. Build
cache remains report-only because discovery must not contact or start the daemon. If
Docker or related processes are active, the module produces no executable batch.

Always exclude volumes, containers, named images, contexts, credentials, Kubernetes
state, and `Docker.raw`. The module must not start the Docker daemon to inspect it.

## Testing strategy

Every release must add the following layers.

### Generic contract tests

- Static deterministic registry and descriptor order.
- Deterministic target IDs, batch IDs, manifests, and digests.
- Trusted roots independent of targets and manifests.
- Rejection of unregistered action kinds and cross-module action/root reuse.
- Read-only scan and dry-run.
- Strict schema migration and concurrent reload.

### Module fixtures

- Xcode/CoreSimulator: DerivedData, archives, device support, runtimes, active
  simulator, and simulator user data.
- Flutter/FVM: installed versions, selected version, symlinks, bounded metadata,
  and downloaded artifacts.
- Gradle: downloads, distributions, wrappers, configuration, credentials, and
  keystores.
- npm: cache, corrupt cache, projects, `node_modules`, lockfiles, and `.npmrc`.
- Android: SDK/NDK/system-image versions, AVDs, user data, and mocked active emulator.
- Homebrew: recorded dry-run output, pinned formulae, unsupported output, and timeout.
- Docker: active/inactive process state, build cache, fixed user cache, volumes,
  images, containers, and `Docker.raw` exclusions.

### Adversarial tests

- Symlinks, ownership changes, and path replacement races.
- Fingerprint changes after approval.
- Missing tools, timeout, malformed vendor output, and unsupported versions.
- Interruption after mutation but before lifecycle or outcome checkpoints.
- Unresolved intent, corrupt outcome history, and concurrent retry.
- One module attempting to use another module's root, batch, or action handler.

### End-to-end fixture

Each module must exercise:

```text
scan -> plan -> approve digest -> dry-run -> apply -> verify -> reload -> report
```

Only the approved fixture target may disappear. Resume must not repeat mutation.

## Real-machine validation

Before release, create a private temporary session and run only `scan`, `plan`, and
`report` against the actual account. Do not approve, apply, verify administrative
results, or execute generated scripts.

Record every external argv and prove no application, daemon, ADB server, emulator, or
Docker service starts. All targets remain pending. Ambiguous and custom roots remain
informational. Remove the temporary session after evidence capture.

A real `apply` trial is a separate later phase. It is limited to one small
`safe_regenerable` batch and requires new explicit human approval.

## Release gate

A module release requires:

- all previous tests passing;
- new module, manifest, executor, reporting, and integration tests passing;
- independent security review;
- skill validator success;
- read-only real-machine smoke evidence;
- documentation matching the exact released scope;
- no real cleanup during implementation or validation.

Each release is independently shippable and may be stopped without blocking prior
modules. Dependencies permit reuse of primitives, never reuse of approvals, batches,
trusted roots, or mutation intents.
