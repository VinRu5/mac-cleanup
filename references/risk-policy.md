# Risk policy

Apply this policy only through the engine's immutable manifest and per-batch approval.

## Classes

| Class | Meaning | MVP handling | Examples |
|---|---|---|---|
| `safe_regenerable` | Positively identified, user-owned artifact the owner can recreate without losing user state. | May enter `safe-user-caches`; still require its exact digest approval. | An ordinary immediate child of `~/Library/Caches`, such as `com.example.app`. |
| `review_required` | Regenerable-looking artifact with a meaningful workflow or telemetry cost. | Keep separate in `review-user-caches`; it is omitted unless policy explicitly allows it, and still needs its own digest approval. | `Codex`, `io.sentry`, and `io.sentry.*` cache children. |
| `never_automatic` | Personal data, state, configuration, credentials, or an ambiguous/protected item. | Never include in an executable batch. Report it or require a separate future module and explicit design. | Projects, source trees, documents, media, mail, messages, backups, `.env`, keychains, tokens, signing material, keystores, application state/configuration, active toolchains, simulator/emulator data. |

The current module also excludes its cache root itself, `com.apple.*`, symlinks, inaccessible entries, non-user-owned entries, paths outside the trusted root, and unknown/path-like candidate IDs. Do not reinterpret an exclusion as permission to delete it.

## Severity behavior

| Severity | Meaning | Required behavior |
|---|---|---|
| `informational` | Idempotent or expected observation, such as an already absent target or recreated cache. | Record and continue; an absent target verifies successfully. |
| `warning` | Noncritical incomplete observation, such as an optional tool or unreadable candidate. | Record and continue only when safety is unchanged. |
| `batch_error` | A target changed, is in use, lacks permission, or fails a noncritical postcondition. | Suspend the affected batch; do not mutate its remaining targets. Other batches may be considered independently. |
| `critical` | A symlink/noncanonical/outside target, unapproved target, personal-data risk, or integrity failure. | Stop all mutation and return exit code `4`; start a new safe session only after resolving the condition. |

Examples do not widen scope: a missing `zsh` is a warning; a fingerprint change is a batch error; a cache path replaced by a symlink is critical. Administrative fallback is only for engine-detected permission denial in an already approved batch, never a way to promote an excluded target.
