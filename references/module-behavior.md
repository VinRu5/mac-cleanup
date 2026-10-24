# Module behavior

Implement modules as fixed, read-only inventory providers. The MVP registry contains only `UserCachesModule` with ID `user-caches`; all developer-tool modules are deferred.

## Contract

```python
class CleanupModule(Protocol):
    id: str
    def detect(self, context: ScanContext) -> bool: ...
    def fast_scan(self, context: ScanContext) -> ScanResult: ...
    def deep_scan(
        self, context: ScanContext, candidate_ids: tuple[str, ...]
    ) -> ScanResult: ...
```

`ScanContext` is immutable and contains an absolute `home`, `uid`, `ProcessRunner`, deep-scan threshold, and timeout. `ScanResult` is immutable and contains sorted `targets`, `issues`, and `executable_target_ids`; only deep-scanned, fingerprinted executable targets can reach manifest approval.

Use a stable built-in registry sorted by module ID. Never dynamically load modules or accept a filesystem path as a module. Create deterministic target IDs as `<module-id>:<approved-immediate-name>`; the user-cache implementation uses `user-caches:<name>`, sorted by ID. IDs are selectors, not paths.

## Scope and side effects

- Make `detect`, `fast_scan`, and `deep_scan` read-only. Use `ProcessRunner` only for bounded, argv-only, non-mutating diagnostics; never start apps, daemons, ADB, or package cleanup during discovery.
- Make fast scan inspect only fixed immediate entries. Make deep scan re-inspect only supplied valid IDs and never widen to siblings or arbitrary paths.
- Have a module propose candidates; do not delete, approve, transition sessions, create manifests, generate administrative scripts, or derive allowed roots.
- Let the engine independently derive trusted allowed roots from the canonical trusted home and fixed module semantics, not from manifest target paths. For `user-caches`, candidates must be immediate children of `<trusted-home>/Library/Caches`; the engine independently uses that cache root and rejects other module IDs.
- Reject relative paths, root paths, allowed roots themselves, symlinks, unsafe components, inaccessible entries, and entries not owned by the scanning UID. Preserve canonical paths and deep fingerprints for executable targets.

## Required tests

Add fixture-only `unittest` coverage for deterministic registry order and IDs, detect/fast/deep behavior, threshold boundaries, exclusions, symlink and ownership defenses, unreadable roots, and proof that fast scan does not recurse. Test that deep scan accepts only selected IDs and executable IDs have fingerprints. Add manifest/executor coverage proving the new module cannot widen trusted roots, bypass approval, or mutate during scan/dry-run. Never test a module against personal or production files.
