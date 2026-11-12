"""Durable outcome publication receipts shared by mutation workflows."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from typing import TYPE_CHECKING, Any

from .jsonio import canonical_bytes
from .models import Manifest
from .sessions import Session

if TYPE_CHECKING:
    from .executor import BatchOutcome


@dataclass(frozen=True)
class OutcomePublicationReceipt:
    """A claim that can only be trusted after rereading the outcome artifact."""

    operation_id: str
    sequence: int
    record_digest: str


def validate_outcome_membership(manifest: Manifest, outcome: BatchOutcome) -> None:
    """Ensure a candidate outcome only accounts for its immutable batch targets."""
    batches = {batch.id: batch for batch in manifest.batches}
    batch = batches.get(outcome.batch_id)
    if batch is None:
        raise ValueError("outcome names an unknown manifest batch")
    target_ids = {target.id for target in batch.targets}
    referenced = {
        target_id for target_id, _ in outcome.logical_bytes_removed_by_target
    } | set(outcome.regenerated_target_ids) | set(outcome.uncertain_target_ids) | {
        issue.target_id for issue in outcome.issues if issue.target_id is not None
    }
    if not referenced.issubset(target_ids):
        raise ValueError("outcome names a target outside its manifest batch")
    if (
        outcome.logical_bytes_removed is not None
        and sum(count for _, count in outcome.logical_bytes_removed_by_target)
        != outcome.logical_bytes_removed
    ):
        raise ValueError("outcome target removals do not equal its batch total")


def validate_operations_membership(
    manifest: Manifest, operations: list[Mapping[str, Any]]
) -> None:
    """Validate every persisted operation against the current immutable manifest."""
    batches = {batch.id: batch for batch in manifest.batches}
    for operation in operations:
        batch = batches.get(operation["batch_id"])
        if batch is None:
            raise ValueError("recorded outcome names an unknown manifest batch")
        target_ids = {target.id for target in batch.targets}
        removed = operation["logical_bytes_removed_by_target"]
        referenced = {item["target_id"] for item in removed}
        referenced.update(operation["regenerated_target_ids"])
        referenced.update(operation["uncertain_target_ids"])
        referenced.update(
            issue["target_id"]
            for issue in operation["issues"]
            if isinstance(issue.get("target_id"), str)
        )
        if not referenced.issubset(target_ids):
            raise ValueError("recorded outcome names a target outside its manifest batch")
        if (
            operation["logical_bytes_removed"] is not None
            and sum(item["logical_bytes_removed"] for item in removed)
            != operation["logical_bytes_removed"]
        ):
            raise ValueError("recorded target removals do not equal the batch total")


def outcome_operation_id(operation: str, outcome: BatchOutcome) -> str:
    """Return a stable identity for an outcome not backed by a mutation intent."""
    from .reporting import _outcome_value

    value = _outcome_value(1, operation, outcome, operation_id="0" * 64)
    value.pop("sequence")
    value.pop("operation_id")
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def receipt_for_record(record: dict[str, object]) -> OutcomePublicationReceipt:
    return OutcomePublicationReceipt(
        operation_id=str(record["operation_id"]),
        sequence=int(record["sequence"]),
        record_digest=hashlib.sha256(canonical_bytes(record)).hexdigest(),
    )


def verify_outcome_receipt(
    session: Session,
    receipt: object,
    *,
    operation: str,
    outcome: BatchOutcome,
    operation_id: str | None,
) -> OutcomePublicationReceipt:
    """Revalidate a claimed receipt against the strict authoritative artifact."""
    from .reporting import (
        _outcome_value,
        _read_outcome_document,
    )

    if not isinstance(receipt, OutcomePublicationReceipt):
        raise ValueError("outcome recorder did not return a durable receipt")
    expected_id = (
        operation_id
        if operation_id is not None
        else outcome_operation_id(operation, outcome)
    )
    if receipt.operation_id != expected_id:
        raise ValueError("outcome receipt names a different operation")
    with session.operation_lock():
        manifest = session.read_manifest()
        validate_outcome_membership(manifest, outcome)
        document = _read_outcome_document(session)
        operations = document["operations"]
        assert isinstance(operations, list)
        validate_operations_membership(manifest, operations)
        matches = [
            item
            for item in operations
            if item.get("operation_id") == expected_id
        ]
        if len(matches) != 1:
            raise ValueError("outcome receipt has no unique durable operation")
        persisted = matches[0]
        expected = _outcome_value(
            int(persisted["sequence"]),
            operation,
            outcome,
            operation_id=expected_id,
        )
        expected_receipt = receipt_for_record(expected)
        if persisted != expected or receipt != expected_receipt:
            raise ValueError("outcome receipt does not match durable accounting")
        return expected_receipt
