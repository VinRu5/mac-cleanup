"""Immutable data contracts used by the cleanup engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class Risk(str, Enum):
    SAFE_REGENERABLE = "safe_regenerable"
    REVIEW_REQUIRED = "review_required"
    NEVER_AUTOMATIC = "never_automatic"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    WARNING = "warning"
    BATCH_ERROR = "batch_error"
    CRITICAL = "critical"


class TargetStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    SKIPPED = "skipped"
    APPLIED = "applied"
    VERIFIED = "verified"
    SUSPENDED = "suspended"
    FAILED = "failed"


def _enum(value: Any, enum_type: type[Enum]) -> Any:
    return value if isinstance(value, enum_type) else enum_type(value)


@dataclass(frozen=True)
class Target:
    id: str
    path: str
    kind: str
    risk: Risk
    status: TargetStatus = TargetStatus.PENDING
    fingerprint: str = ""
    logical_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "risk", _enum(self.risk, Risk))
        object.__setattr__(self, "status", _enum(self.status, TargetStatus))

    @property
    def target_id(self) -> str:
        return self.id

    @property
    def canonical(self) -> str:
        return self.path

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "path": self.path, "kind": self.kind,
            "risk": self.risk.value, "status": self.status.value,
            "fingerprint": self.fingerprint, "logical_bytes": self.logical_bytes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Target":
        target_id = value["id"] if "id" in value else value["target_id"]
        path = value["path"] if "path" in value else value.get("canonical", value["canonical_path"] if "canonical_path" in value else None)
        if path is None:
            raise KeyError("path")
        return cls(
            id=str(target_id), path=str(path),
            kind=str(value["kind"]), risk=value["risk"], status=value.get("status", TargetStatus.PENDING),
            fingerprint=str(value.get("fingerprint", "")), logical_bytes=int(value.get("logical_bytes", 0)),
        )


@dataclass(frozen=True)
class Batch:
    id: str
    targets: tuple[Target, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "targets", tuple(sorted(self.targets, key=lambda target: target.id)))

    @property
    def batch_id(self) -> str:
        return self.id

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, "targets": [target.to_dict() for target in self.targets]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Batch":
        batch_id = value["id"] if "id" in value else value["batch_id"]
        return cls(str(batch_id), tuple(Target.from_dict(item) for item in value.get("targets", ())))


@dataclass(frozen=True)
class Issue:
    code: str
    severity: Severity
    message: str
    target_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", _enum(self.severity, Severity))

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"code": self.code, "severity": self.severity.value, "message": self.message}
        if self.target_id is not None:
            result["target_id"] = self.target_id
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Issue":
        return cls(str(value["code"]), value["severity"], str(value["message"]), value.get("target_id"))


@dataclass(frozen=True)
class Manifest:
    schema_version: int = 1
    batches: tuple[Batch, ...] = field(default_factory=tuple)
    issues: tuple[Issue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "batches", tuple(sorted(self.batches, key=lambda batch: batch.id)))
        object.__setattr__(self, "issues", tuple(self.issues))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "batches": [batch.to_dict() for batch in self.batches],
            "issues": [issue.to_dict() for issue in self.issues],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Manifest":
        return cls(
            schema_version=int(value.get("schema_version", 1)),
            batches=tuple(Batch.from_dict(item) for item in value.get("batches", ())),
            issues=tuple(Issue.from_dict(item) for item in value.get("issues", ())),
        )
