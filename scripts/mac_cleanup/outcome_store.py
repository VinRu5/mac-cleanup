"""Durable outcome publication receipts shared by mutation workflows."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import TYPE_CHECKING

from .jsonio import canonical_bytes
from .sessions import Session

if TYPE_CHECKING:
    from .executor import BatchOutcome


@dataclass(frozen=True)
class OutcomePublicationReceipt:
    """A claim that can only be trusted after rereading the outcome artifact."""

    operation_id: str
    sequence: int
    record_digest: str


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
        _validate_outcome_membership,
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
        _validate_outcome_membership(manifest, outcome)
        document = _read_outcome_document(session)
        operations = document["operations"]
        assert isinstance(operations, list)
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
