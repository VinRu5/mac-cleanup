"""Deterministic approval manifests built only from deep-scan identities."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

from .jsonio import canonical_bytes
from .models import Batch, Manifest, Risk, Target
from .modules.base import ScanResult
from .sessions import Session


POLICY_SCHEMA_VERSION = 1
_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "enabled_modules",
        "preserve_target_ids",
        "allow_review_required",
        "deep_scan_threshold_bytes",
    }
)
_USER_CACHES_MODULE = "user-caches"
_SAFE_USER_CACHES_BATCH = "safe-user-caches"
_REVIEW_USER_CACHES_BATCH = "review-user-caches"


def build_manifest(inventory: ScanResult, policy: Mapping[str, object]) -> Manifest:
    """Build an immutable manifest from approval-eligible deep scan targets only."""
    if not isinstance(inventory, ScanResult):
        raise TypeError("inventory must be a ScanResult")
    normalized_policy = _validate_policy(policy)
    inventory_digest = _inventory_digest(inventory)
    executable_ids = set(inventory.executable_target_ids)
    executable_targets = inventory.executable_targets
    _validate_executable_targets(executable_targets, executable_ids)

    enabled_modules = set(normalized_policy["enabled_modules"])
    preserve_target_ids = set(normalized_policy["preserve_target_ids"])
    allow_review_required = normalized_policy["allow_review_required"]
    safe_targets: list[Target] = []
    review_targets: list[Target] = []

    for target in executable_targets:
        if target.id in preserve_target_ids or _module_id(target) not in enabled_modules:
            continue
        if _module_id(target) != _USER_CACHES_MODULE:
            continue
        if target.risk is Risk.SAFE_REGENERABLE:
            safe_targets.append(target)
        elif target.risk is Risk.REVIEW_REQUIRED and allow_review_required:
            review_targets.append(target)

    batches: list[Batch] = []
    if safe_targets:
        batches.append(Batch(_SAFE_USER_CACHES_BATCH, tuple(safe_targets)))
    if review_targets:
        batches.append(Batch(_REVIEW_USER_CACHES_BATCH, tuple(review_targets)))
    return Manifest(
        batches=tuple(batches),
        issues=tuple(sorted(inventory.issues, key=_issue_key)),
        inventory_digest=inventory_digest,
    )


def approval_digest(manifest: Manifest, batch_id: str) -> str:
    """Return the exact digest required to approve one immutable batch."""
    batch = _batch(manifest, batch_id)
    value = {
        "batch": batch.to_dict(),
        "inventory_digest": manifest.inventory_digest,
        "manifest_schema_version": manifest.schema_version,
    }
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def approve_batch(session: Session, batch_id: str, digest: str) -> None:
    """Approve exactly one pending batch when its supplied digest matches."""
    if not isinstance(batch_id, str) or not batch_id:
        raise ValueError("batch id must be non-empty text")
    if not isinstance(digest, str) or not digest:
        raise ValueError("approval digest must be non-empty text")
    manifest = session.read_manifest()
    # Recheck the on-disk artifact against the durable session record before
    # accepting a digest derived from it.
    session.write_manifest(manifest)
    batch = _batch(manifest, batch_id)
    expected = approval_digest(manifest, batch_id)
    if not hmac.compare_digest(digest, expected):
        raise ValueError("approval digest does not match the requested batch")
    for target in batch.targets:
        if session.status(target.id) != "pending":
            raise ValueError(f"target is not pending: {target.id}")
    for target in batch.targets:
        session.transition(target.id, "approved")


def _validate_policy(policy: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be an object")
    if set(policy) != _POLICY_KEYS:
        raise ValueError("policy fields do not match schema version 1")
    if policy["schema_version"] != POLICY_SCHEMA_VERSION:
        raise ValueError("policy schema_version must be 1")
    enabled_modules = _string_list(policy["enabled_modules"], "enabled_modules")
    preserve_target_ids = _string_list(policy["preserve_target_ids"], "preserve_target_ids")
    allow_review_required = policy["allow_review_required"]
    if type(allow_review_required) is not bool:
        raise ValueError("policy allow_review_required must be boolean")
    threshold = policy["deep_scan_threshold_bytes"]
    if type(threshold) is not int or threshold < 0:
        raise ValueError("policy deep_scan_threshold_bytes must be a non-negative integer")
    return {
        "enabled_modules": tuple(sorted(set(enabled_modules))),
        "preserve_target_ids": tuple(sorted(set(preserve_target_ids))),
        "allow_review_required": allow_review_required,
    }


def _string_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"policy {name} must be a list of non-empty text values")
    return tuple(value)


def _validate_executable_targets(targets: tuple[Target, ...], executable_ids: set[str]) -> None:
    observed_ids: set[str] = set()
    for target in targets:
        if target.id not in executable_ids:
            raise ValueError(f"target is absent from executable target ids: {target.id}")
        if not target.fingerprint:
            raise ValueError(f"executable target lacks a deep fingerprint: {target.id}")
        if target.id in observed_ids:
            raise ValueError(f"duplicate executable target id: {target.id}")
        observed_ids.add(target.id)


def _inventory_digest(inventory: ScanResult) -> str:
    targets = sorted(inventory.targets, key=lambda target: (target.id, target.canonical))
    value = {
        "executable_target_ids": list(inventory.executable_target_ids),
        "issues": [issue.to_dict() for issue in sorted(inventory.issues, key=_issue_key)],
        "targets": [target.to_dict() for target in targets],
    }
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _module_id(target: Target) -> str:
    return target.id.partition(":")[0]


def _batch(manifest: Manifest, batch_id: str) -> Batch:
    if not isinstance(manifest, Manifest):
        raise TypeError("manifest must be a Manifest")
    for batch in manifest.batches:
        if batch.id == batch_id:
            return batch
    raise ValueError(f"unknown manifest batch: {batch_id}")


def _issue_key(issue: object) -> tuple[str, str, str, str]:
    code = getattr(issue, "code")
    severity = getattr(issue, "severity").value
    message = getattr(issue, "message")
    target_id = getattr(issue, "target_id") or ""
    return code, severity, message, target_id
