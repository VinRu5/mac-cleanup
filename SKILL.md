---
name: mac-cleanup
description: Audit reclaimable disk space and perform guided, risk-based macOS cleanup in approved batches. Use for Mac disk-space analysis, safe cache cleanup, developer-tool cleanup, or resuming a prior cleanup session; do not use for generic application uninstallation or arbitrary personal-file deletion.
---

# Mac Cleanup

Use the bundled engine; do not replace it with shell cleanup, `rm`, package-manager cleanup, ad-hoc path discovery, or a copied administrative script. The MVP has one real module: `user-caches`. Xcode, Android, Flutter/FVM, Gradle, npm, Homebrew, Docker, logs, and application uninstall cleanup are deferred.

## Guided workflow

1. Create or resume a durable session directory. Run `python3 scripts/mac_cleanup.py scan --session <session>`; scanning is read-only. Then run `python3 scripts/mac_cleanup.py plan --session <session>`.
2. Present the engine's exact batch IDs, target IDs and paths, risk class, exclusions/issues, privileges, and estimated **logical** bytes. Never describe that estimate as recovered disk space.
3. Ask the human to approve one exact batch by its displayed SHA-256 digest. Do not infer approval from a general request to clean space. Run `python3 scripts/mac_cleanup.py approve --session <session> --batch <id> --digest <digest>` only after that approval.
4. Run `python3 scripts/mac_cleanup.py apply --session <session> --batch <id> --dry-run` for that same approved batch and show the result. Apply only that unchanged batch with `python3 scripts/mac_cleanup.py apply --session <session> --batch <id>` after the human confirms proceeding. Never add paths, merge batches, or reuse a digest for a changed manifest.
5. Treat a batch error as a suspension of that batch; independent batches remain available. Stop all mutation on a critical issue. Run `python3 scripts/mac_cleanup.py verify --session <session> --batch <id>`, then `python3 scripts/mac_cleanup.py report --session <session>`; use the persisted session to resume rather than repeating completed work.

The commands return `0` for success, `2` for invalid input (including a bad digest), `3` for a suspended batch, and `4` for a critical safety failure. Inspect the persisted report/state and resolve the recorded condition; do not bypass it.

## Non-negotiable boundaries

- Let the engine own manifests, digest checks, trusted allowed roots, preflight, mutation, transitions, verification, and reporting. Do not derive an allowed root from a target, run arbitrary shell cleanup, or alter personal files.
- Never mutate anything absent from the approved manifest. Keep scan and dry-run read-only.
- If the engine generates an administrative fallback, require the human to confirm the exact engine-validated script path and checksum before they execute it. Do not run a replacement or copied script. Engine validation is read-only and does not close the manual validation-to-execution gap against a malicious same-UID actor.
- Use the report's separated logical removal, observed free-space delta, and regenerated-byte values; do not equate logical size with recovered APFS space.

Read [references/risk-policy.md](references/risk-policy.md) before resolving a classification or exclusion dispute. Read [references/module-behavior.md](references/module-behavior.md) before developing a module or changing scan behavior.
