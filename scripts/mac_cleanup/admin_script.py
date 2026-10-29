"""Static, checksummed administrative fallback generation and result import."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tempfile
from typing import Mapping

from .executor import _preflight_target
from .jsonio import canonical_bytes, read_json
from .models import Batch, Issue, Risk, Severity
from .sessions import Session


RESULT_SCHEMA_VERSION = 1
_SUPPORTED_BATCH_RISKS = {
    "safe-user-caches": Risk.SAFE_REGENERABLE,
    "review-user-caches": Risk.REVIEW_REQUIRED,
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERIFIER_BYTES = Path(__file__).with_name("admin_verifier.py").read_bytes()
_VERIFIER_SOURCE = _VERIFIER_BYTES.decode("utf-8")
_BOOTSTRAP_SOURCE = r'''import fcntl,hashlib,hmac,json,os,stat,sys
LIMIT=16777216
KEYS={"allowed_root","batch","batch_id","checksum","manifest_digest","operation_digest","output_path","result_path","session_gid","session_path","session_uid","snapshot_digest","snapshot_path","target_ids"}
def fail(message):
    raise RuntimeError(message)
def digest(value):
    return hashlib.sha256(value).hexdigest()
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def sha(value):
    return isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def same(first,second):
    return (first.st_dev,first.st_ino,stat.S_IFMT(first.st_mode),first.st_uid,first.st_gid,first.st_mtime_ns,first.st_size)==(second.st_dev,second.st_ino,stat.S_IFMT(second.st_mode),second.st_uid,second.st_gid,second.st_mtime_ns,second.st_size)
def absolute_directory(path):
    if not isinstance(path,str) or not os.path.isabs(path) or os.path.normpath(path)!=path or "\0" in path:
        fail("session path is not canonical")
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.split("/")[1:]:
            if part:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd)
                fd=child
        return fd
    except BaseException:
        os.close(fd)
        raise
def artifact_name(path,session,label):
    if not isinstance(path,str) or not os.path.isabs(path) or os.path.normpath(path)!=path or os.path.dirname(path)!=session or os.path.basename(path) in {"",".",".."} or "\0" in path:
        fail(label+" path is outside session")
    return os.path.basename(path)
def read_regular_at(directory,name,label,uid,gid,mode):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_gid!=gid or stat.S_IMODE(before.st_mode)!=mode or before.st_size>LIMIT:
            fail(label+" metadata is unsafe")
        chunks=[]
        remaining=before.st_size
        while remaining:
            chunk=os.read(fd,min(remaining,1048576))
            if not chunk:
                fail(label+" was truncated")
            chunks.append(chunk)
            remaining-=len(chunk)
        if os.read(fd,1) or not same(before,os.fstat(fd)):
            fail(label+" changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)
def current_lock(directory,fd):
    try:
        named=os.stat(".session.lock",dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError:
        return False
    locked=os.fstat(fd)
    return (named.st_dev,named.st_ino)==(locked.st_dev,locked.st_ino)
def stable_lock(directory,uid,gid):
    for unused in range(8):
        fd=os.open(".session.lock",os.O_RDWR|os.O_NOFOLLOW,dir_fd=directory)
        try:
            value=os.fstat(fd)
            if not stat.S_ISREG(value.st_mode) or value.st_uid!=uid or value.st_gid!=gid or stat.S_IMODE(value.st_mode)!=0o600:
                fail("session lock metadata is unsafe")
            fcntl.flock(fd,fcntl.LOCK_EX)
            if current_lock(directory,fd):
                return fd
            fcntl.flock(fd,fcntl.LOCK_UN)
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
    fail("session lock pathname did not stabilize")
if len(sys.argv)!=4:
    sys.exit(64)
session_path,batch_id,target_id=sys.argv[1:]
session_fd=absolute_directory(session_path)
lock_fd=-1
try:
    session_stat=os.fstat(session_fd)
    if not stat.S_ISDIR(session_stat.st_mode) or stat.S_IMODE(session_stat.st_mode)!=0o700:
        fail("session directory metadata is unsafe")
    uid,gid=session_stat.st_uid,session_stat.st_gid
    lock_fd=stable_lock(session_fd,uid,gid)
    try:
        state=json.loads(read_regular_at(session_fd,"state.json","state",uid,gid,0o600).decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError):
        fail("state is not JSON")
    if not isinstance(state,dict) or set(state)!={"schema_version","created_at","admin_scripts","critical_stop","events","issues","manifest","mutation_intent","targets"} or state.get("schema_version")!=1:
        fail("state schema is invalid")
    if not isinstance(state.get("created_at"),str) or not isinstance(state.get("events"),list) or not isinstance(state.get("issues"),list):
        fail("state fields are invalid")
    if state.get("critical_stop") is not None or state.get("mutation_intent") is not None or not isinstance(state.get("targets"),dict) or state["targets"].get(target_id)!="approved":
        fail("target is not currently approved")
    if any(not isinstance(key,str) or value not in {"pending","approved","applied","verified","suspended","skipped","failed"} for key,value in state["targets"].items()):
        fail("target states are invalid")
    scripts=state.get("admin_scripts")
    binding=scripts.get(batch_id) if isinstance(scripts,dict) else None
    if not isinstance(binding,dict) or set(binding)!=KEYS:
        fail("administrative binding schema is invalid")
    text_keys=KEYS-{"batch","session_gid","session_uid","target_ids"}
    if any(not isinstance(binding[key],str) for key in text_keys) or not isinstance(binding["batch"],dict) or type(binding["session_uid"]) is not int or type(binding["session_gid"]) is not int or not isinstance(binding["target_ids"],list) or not all(isinstance(item,str) for item in binding["target_ids"]):
        fail("administrative binding fields are invalid")
    if binding["batch_id"]!=batch_id or binding["session_path"]!=session_path or binding["session_uid"]!=uid or binding["session_gid"]!=gid:
        fail("administrative session binding changed")
    for key in ("checksum","manifest_digest","operation_digest","snapshot_digest"):
        if not sha(binding.get(key)):
            fail("administrative digest is invalid")
    output_name=artifact_name(binding["output_path"],session_path,"script")
    result_name=artifact_name(binding["result_path"],session_path,"result")
    snapshot_name=artifact_name(binding["snapshot_path"],session_path,"snapshot")
    if len({output_name,result_name,snapshot_name})!=3:
        fail("administrative artifacts overlap")
    manifest=state.get("manifest")
    if not isinstance(manifest,dict) or set(manifest)!={"digest","target_ids","value"} or not isinstance(manifest.get("value"),dict) or not isinstance(manifest.get("target_ids"),list) or not all(isinstance(item,str) for item in manifest["target_ids"]) or manifest["target_ids"]!=sorted(manifest["target_ids"]) or not sha(manifest.get("digest")) or manifest["digest"]!=binding["manifest_digest"] or not hmac.compare_digest(digest(canonical(manifest["value"])),manifest["digest"]):
        fail("manifest binding is invalid")
    batches=manifest["value"].get("batches")
    matches=[item for item in batches if isinstance(item,dict) and item.get("id")==batch_id] if isinstance(batches,list) else []
    if len(matches)!=1 or matches[0]!=binding.get("batch"):
        fail("batch binding changed")
    members=matches[0].get("targets")
    target_matches=[item for item in members if isinstance(item,dict) and item.get("id")==target_id] if isinstance(members,list) else []
    target_ids=[item.get("id") for item in members if isinstance(item,dict)] if isinstance(members,list) else []
    if len(target_matches)!=1 or binding.get("target_ids")!=target_ids or len(target_ids)!=len(set(target_ids)):
        fail("target binding changed")
    discovered=[item.get("id") for batch in batches if isinstance(batch,dict) and isinstance(batch.get("targets"),list) for item in batch["targets"] if isinstance(item,dict)]
    if sorted(discovered)!=manifest["target_ids"] or len(discovered)!=len(set(discovered)) or set(state["targets"])!=set(manifest["target_ids"]):
        fail("manifest target identities changed")
    operation={key:binding[key] for key in ("allowed_root","batch","checksum","manifest_digest","output_path","result_path","session_gid","session_path","session_uid","snapshot_digest","snapshot_path")}
    if not hmac.compare_digest(digest(canonical(operation)),binding["operation_digest"]):
        fail("operation binding changed")
    script_bytes=read_regular_at(session_fd,output_name,"script",uid,gid,0o700)
    if not hmac.compare_digest(digest(script_bytes),binding["checksum"]):
        fail("script checksum changed")
    snapshot_bytes=read_regular_at(session_fd,snapshot_name,"snapshot",uid,gid,0o600)
    if not hmac.compare_digest(digest(snapshot_bytes),binding["snapshot_digest"]):
        fail("snapshot digest changed")
    snapshot_path=binding["snapshot_path"]
    target=target_matches[0]
    verifier_arguments=[session_path,snapshot_path,binding["snapshot_digest"],binding["output_path"],binding["result_path"],binding["operation_digest"],batch_id,canonical(target).decode("utf-8"),binding["allowed_root"],str(uid),str(gid),binding["manifest_digest"],target_id,target["path"],target["fingerprint"]]
finally:
    if lock_fd>=0:
        fcntl.flock(lock_fd,fcntl.LOCK_UN)
        os.close(lock_fd)
    os.close(session_fd)
sys.argv=[snapshot_path]+verifier_arguments
namespace={"__name__":"__main__","__file__":snapshot_path}
exec(compile(snapshot_bytes,snapshot_path,"exec"),namespace,namespace)
'''
_BOOTSTRAP = "exec(compile(" + repr(_BOOTSTRAP_SOURCE) + ",'<admin-bootstrap>','exec'))"


@dataclass(frozen=True)
class AdminArtifactValidation:
    """Exact engine-validated identity a human must confirm before execution."""

    batch_id: str
    checksum: str
    manifest_digest: str
    operation_digest: str
    script_path: Path
    snapshot_digest: str
    snapshot_path: Path
    target_ids: tuple[str, ...]


def quote_zsh_literal(value: str) -> str:
    """Return one static zsh single-quoted word without interpolation."""
    if not isinstance(value, str):
        raise TypeError("zsh literal must be text")
    if any(character in value for character in ("\0", "\n", "\r")):
        raise ValueError("zsh literal must not contain control line separators")
    return "'" + value.replace("'", "'\\''") + "'"


def generate_admin_script(
    batch: Batch,
    output_path: str | os.PathLike[str],
    result_path: str | os.PathLike[str],
    *,
    trusted_home: Path | None = None,
) -> str:
    """Generate, bind, and engine-validate one static administrative script.

    The plan's three positional arguments are preserved.  The trusted session is
    deliberately derived from ``result_path.parent`` so a free-standing or forged
    batch cannot become executable.  ``trusted_home`` is a keyword-only fixture
    seam; production derives the account home from the account database.  The
    returned checksum is the exact value the human must confirm before executing
    the script.  Executing a different, wholly replaced shell program is arbitrary
    local-code execution and is outside the cooperative local-user threat model.
    """
    if not isinstance(batch, Batch):
        raise TypeError("batch must be a Batch")
    output = _session_artifact_path(output_path, "script")
    result = _session_artifact_path(result_path, "result")
    snapshot = _session_artifact_path(
        output.with_name(f".{output.name}.verifier.py"), "verifier snapshot"
    )
    if output.parent != result.parent or len({output, result, snapshot}) != 3:
        raise ValueError("administrative artifacts must be distinct session files")
    session = Session.load(result.parent)
    home = _trusted_home(trusted_home)
    allowed_root = _trusted_cache_root(home)

    with session.operation_lock():
        if session.mutation_intent() is not None:
            raise ValueError("session has an unresolved mutation intent")
        if session.critical_issue() is not None:
            raise ValueError("session has a critical safety stop")
        persisted = _approved_session_batch(session, batch)
        _validate_batch_location(persisted, allowed_root)
        manifest_digest = _manifest_digest(session)
        session_stat = session.path.stat()
        if not stat.S_ISDIR(session_stat.st_mode):
            raise ValueError("session path must be a directory")
        session_uid = session_stat.st_uid
        session_gid = session_stat.st_gid
        snapshot_digest = hashlib.sha256(_VERIFIER_BYTES).hexdigest()
        script = _render_script(persisted, session.path)
        payload = script.encode("utf-8")
        checksum = hashlib.sha256(payload).hexdigest()
        operation_digest = _operation_digest(
            persisted,
            checksum,
            manifest_digest,
            session.path,
            output,
            result,
            snapshot,
            snapshot_digest,
            allowed_root,
            session_uid,
            session_gid,
        )
        initial_results = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "batch_id": persisted.id,
            "operation_digest": operation_digest,
            "target_ids": [target.id for target in persisted.targets],
            "targets": {},
        }
        binding = {
            "allowed_root": str(allowed_root),
            "batch": persisted.to_dict(),
            "batch_id": persisted.id,
            "checksum": checksum,
            "manifest_digest": manifest_digest,
            "operation_digest": operation_digest,
            "output_path": str(output),
            "result_path": str(result),
            "session_path": str(session.path),
            "session_gid": session_gid,
            "session_uid": session_uid,
            "snapshot_digest": snapshot_digest,
            "snapshot_path": str(snapshot),
            "target_ids": [target.id for target in persisted.targets],
        }
        existing = session.admin_script_binding(persisted.id)
        if existing is not None and existing != binding:
            raise ValueError("administrative script binding is immutable")
        _atomic_write_bytes_owned(
            snapshot, _VERIFIER_BYTES, session_uid, session_gid, 0o600
        )
        _atomic_write_bytes_owned(output, payload, session_uid, session_gid, 0o700)
        if os.path.lexists(result):
            _require_owned_regular_file(
                result, "administrative result", session_uid, session_gid, 0o600
            )
            _validate_result_binding(read_json(result), initial_results)
        else:
            _atomic_write_bytes_owned(
                result,
                canonical_bytes(initial_results),
                session_uid,
                session_gid,
                0o600,
            )
        session.bind_admin_script(persisted.id, binding)
        validation = validate_admin_artifacts(
            session,
            persisted.id,
            trusted_home=trusted_home,
        )
        return validation.checksum


def validate_admin_artifacts(
    session: Session,
    batch_id: str,
    *,
    trusted_home: Path | None = None,
    require_approved: bool = True,
) -> AdminArtifactValidation:
    """Validate the exact authorized artifacts immediately before manual use.

    This read-only engine check holds the stable session lock while validating the
    durable binding, current script and snapshot bytes, metadata, manifest, batch,
    lifecycle authorization, trusted root, and critical latch.  The default mode
    requires every target to remain approved before manual use.  Reporting passes
    ``require_approved=False`` to audit integrity after later lifecycle transitions;
    that read-only mode does not authorize execution.  The caller must present and
    the human must confirm ``checksum`` and execute that exact script.  This check
    does not close the later manual-execution time gap against a malicious same-UID
    actor.
    """
    if not isinstance(session, Session):
        raise TypeError("session must be a Session")
    if not isinstance(batch_id, str) or not batch_id:
        raise ValueError("administrative batch id must be non-empty text")
    if type(require_approved) is not bool:
        raise TypeError("require_approved must be boolean")
    allowed_root = _trusted_cache_root(_trusted_home(trusted_home))

    with session.operation_lock():
        if session.mutation_intent() is not None:
            raise ValueError("session has an unresolved mutation intent")
        if session.critical_issue() is not None:
            raise ValueError("session has a critical safety stop")
        binding = session.admin_script_binding(batch_id)
        if binding is None:
            raise ValueError("administrative batch has no durable binding")
        _validate_binding(binding)
        if binding["batch_id"] != batch_id:
            raise ValueError("administrative binding targets a different batch")
        if binding["session_path"] != str(session.path):
            raise ValueError("administrative binding targets a different session")

        session_stat = session.path.stat()
        if (
            not stat.S_ISDIR(session_stat.st_mode)
            or stat.S_IMODE(session_stat.st_mode) != 0o700
            or session_stat.st_uid != binding["session_uid"]
            or session_stat.st_gid != binding["session_gid"]
        ):
            raise ValueError("session owner or mode differs from its binding")
        script_path = _bound_session_artifact(
            session, binding["output_path"], "script"
        )
        result_path = _bound_session_artifact(
            session, binding["result_path"], "result"
        )
        snapshot_path = _bound_session_artifact(
            session, binding["snapshot_path"], "verifier snapshot"
        )
        if len({script_path, result_path, snapshot_path}) != 3:
            raise ValueError("administrative artifacts must be distinct")

        script_bytes = _read_owned_regular_bytes(
            script_path,
            "administrative script",
            binding["session_uid"],
            binding["session_gid"],
            0o700,
        )
        actual_checksum = hashlib.sha256(script_bytes).hexdigest()
        if not hmac.compare_digest(actual_checksum, binding["checksum"]):
            raise ValueError("administrative script differs from durable checksum")
        snapshot_bytes = _read_owned_regular_bytes(
            snapshot_path,
            "administrative verifier snapshot",
            binding["session_uid"],
            binding["session_gid"],
            0o600,
        )
        actual_snapshot_digest = hashlib.sha256(snapshot_bytes).hexdigest()
        if not hmac.compare_digest(
            actual_snapshot_digest, binding["snapshot_digest"]
        ):
            raise ValueError("administrative verifier differs from durable binding")
        _require_owned_regular_file(
            result_path,
            "administrative result",
            binding["session_uid"],
            binding["session_gid"],
            0o600,
        )

        named = _named_batch(session, batch_id)
        persisted = (
            _approved_session_batch(session, named)
            if require_approved
            else named
        )
        _validate_batch_location(persisted, allowed_root)
        manifest_digest = _manifest_digest(session)
        expected_operation = _operation_digest(
            persisted,
            actual_checksum,
            manifest_digest,
            session.path,
            script_path,
            result_path,
            snapshot_path,
            actual_snapshot_digest,
            allowed_root,
            binding["session_uid"],
            binding["session_gid"],
        )
        expected_ids = [target.id for target in persisted.targets]
        if (
            binding["manifest_digest"] != manifest_digest
            or binding["allowed_root"] != str(allowed_root)
            or binding["batch"] != persisted.to_dict()
            or binding["target_ids"] != expected_ids
            or binding["operation_digest"] != expected_operation
        ):
            raise ValueError("administrative binding is inconsistent")
        return AdminArtifactValidation(
            batch_id=batch_id,
            checksum=actual_checksum,
            manifest_digest=manifest_digest,
            operation_digest=expected_operation,
            script_path=script_path,
            snapshot_digest=actual_snapshot_digest,
            snapshot_path=snapshot_path,
            target_ids=tuple(expected_ids),
        )


def import_admin_results(
    session: Session,
    result_path: str | os.PathLike[str],
    expected_checksum: str,
    *,
    trusted_home: Path | None = None,
) -> None:
    """Post-validate artifacts/results and import verified filesystem outcomes."""
    if not isinstance(session, Session):
        raise TypeError("session must be a Session")
    if not isinstance(expected_checksum, str) or not _SHA256.fullmatch(
        expected_checksum
    ):
        raise ValueError("expected checksum must be a SHA-256 hex digest")
    result = _session_artifact_path(result_path, "result")
    if result.parent != session.path:
        raise ValueError("result path must belong to the supplied session")
    home = _trusted_home(trusted_home)
    allowed_root = _trusted_cache_root(home)

    with session.operation_lock():
        if session.mutation_intent() is not None:
            raise ValueError("session has an unresolved mutation intent")
        if session.critical_issue() is not None:
            raise ValueError("session has a critical safety stop")
        bindings = _admin_bindings(session)
        matches = tuple(
            binding
            for binding in bindings.values()
            if binding.get("result_path") == str(result)
        )
        if len(matches) != 1:
            raise ValueError("result path has no unique administrative binding")
        binding = matches[0]
        _validate_binding(binding)
        if binding["session_path"] != str(session.path):
            raise ValueError("administrative binding targets a different session")
        if not hmac.compare_digest(binding["checksum"], expected_checksum):
            raise ValueError("administrative checksum differs from durable state")
        script_path = Path(binding["output_path"])
        snapshot_path = Path(binding["snapshot_path"])
        _require_owned_regular_file(
            script_path,
            "administrative script",
            binding["session_uid"],
            binding["session_gid"],
            0o700,
        )
        actual_checksum = hashlib.sha256(script_path.read_bytes()).hexdigest()
        if not hmac.compare_digest(actual_checksum, expected_checksum):
            raise ValueError("administrative script differs from its checksum")
        _require_owned_regular_file(
            snapshot_path,
            "administrative verifier snapshot",
            binding["session_uid"],
            binding["session_gid"],
            0o600,
        )
        snapshot_digest = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
        if not hmac.compare_digest(snapshot_digest, binding["snapshot_digest"]):
            raise ValueError("administrative verifier differs from its binding")
        batch = _named_batch(session, binding["batch_id"])
        persisted = _approved_or_resumable_batch(session, batch)
        _validate_batch_location(persisted, allowed_root)
        manifest_digest = _manifest_digest(session)
        expected_operation = _operation_digest(
            persisted,
            binding["checksum"],
            manifest_digest,
            session.path,
            script_path,
            result,
            snapshot_path,
            binding["snapshot_digest"],
            allowed_root,
            binding["session_uid"],
            binding["session_gid"],
        )
        if binding["manifest_digest"] != manifest_digest:
            raise ValueError("administrative binding targets a different manifest")
        if binding["allowed_root"] != str(allowed_root):
            raise ValueError("administrative binding targets a different module root")
        if binding["batch"] != persisted.to_dict():
            raise ValueError("administrative binding targets a different batch")
        if binding["operation_digest"] != expected_operation:
            raise ValueError("administrative binding is inconsistent")
        if not os.path.lexists(result):
            _suspend_missing_result_file(session, persisted, result)
            return
        _require_owned_regular_file(
            result,
            "administrative result",
            binding["session_uid"],
            binding["session_gid"],
            0o600,
        )
        results = read_json(result)
        expected_result = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "batch_id": persisted.id,
            "operation_digest": expected_operation,
            "target_ids": [target.id for target in persisted.targets],
            "targets": {},
        }
        records = _validate_result_binding(results, expected_result)
        _import_target_records(session, persisted, records, allowed_root)


def _render_script(
    batch: Batch,
    session_path: Path,
) -> str:
    executable = str(Path(sys.executable).resolve(strict=True))
    lines = ["#!/bin/zsh", "set -eu"]
    for target in batch.targets:
        arguments = (
            executable,
            "-I",
            "-S",
            "-c",
            _BOOTSTRAP,
            str(session_path),
            batch.id,
            target.id,
        )
        lines.append(" ".join(quote_zsh_literal(argument) for argument in arguments))
    return "\n".join(lines) + "\n"


def _import_target_records(
    session: Session,
    batch: Batch,
    records: Mapping[str, Mapping[str, object]],
    allowed_root: Path,
) -> None:
    divergence = False
    critical: Issue | None = None
    for target in batch.targets:
        if divergence:
            continue
        record = records.get(target.id)
        if record is None:
            issue = Issue(
                "admin.missing-result",
                Severity.BATCH_ERROR,
                f"Administrative result is missing for target: {target.path}",
                target.id,
            )
            session.add_issue(issue)
            divergence = True
            continue
        preflight = _preflight_target(target, (allowed_root,))
        absent = any(
            issue.code == "executor.target-absent" for issue in preflight.issues
        )
        if record["status"] == "verified" and absent:
            for issue in preflight.issues:
                session.add_issue(issue)
            _transition_verified(session, target.id)
            continue
        issues = tuple(preflight.issues)
        if not issues:
            issues = (
                Issue(
                    "executor.postcondition-failed",
                    Severity.BATCH_ERROR,
                    f"Target remains present after administrative apply: {target.path}",
                    target.id,
                ),
            )
        for issue in issues:
            if issue.severity is not Severity.CRITICAL:
                session.add_issue(issue)
        critical = next(
            (issue for issue in issues if issue.severity is Severity.CRITICAL), None
        )
        divergence = True

    if critical is not None:
        session.latch_critical(critical)
        return
    if divergence:
        mutable = tuple(
            target.id
            for target in batch.targets
            if session.status(target.id) in {"approved", "applied"}
        )
        if mutable:
            session.transition_batch(mutable, "suspended")


def _transition_verified(session: Session, target_id: str) -> None:
    status = session.status(target_id)
    if status == "approved":
        session.transition(target_id, "applied")
        status = "applied"
    if status == "applied":
        session.transition(target_id, "verified")
    elif status != "verified":
        raise ValueError(f"administrative result cannot revive target: {target_id}")


def _approved_session_batch(session: Session, supplied: Batch) -> Batch:
    persisted = _named_batch(session, supplied.id)
    if persisted != supplied:
        raise ValueError("batch must exactly match the immutable session manifest")
    for target in persisted.targets:
        if session.status(target.id) != "approved":
            raise ValueError(f"administrative target is not approved: {target.id}")
    return persisted


def _approved_or_resumable_batch(session: Session, batch: Batch) -> Batch:
    for target in batch.targets:
        if session.status(target.id) not in {
            "approved",
            "applied",
            "verified",
            "suspended",
        }:
            raise ValueError(f"administrative target is not resumable: {target.id}")
    return batch


def _named_batch(session: Session, batch_id: str) -> Batch:
    matches = tuple(
        batch for batch in session.read_manifest().batches if batch.id == batch_id
    )
    if len(matches) != 1:
        raise ValueError(f"unknown manifest batch: {batch_id}")
    return matches[0]


def _validate_batch_location(batch: Batch, allowed_root: Path) -> None:
    expected_risk = _SUPPORTED_BATCH_RISKS.get(batch.id)
    if expected_risk is None or not batch.targets:
        raise ValueError("administrative batch is not a supported module batch")
    root = _canonical_existing_directory(allowed_root, "allowed root")
    for target in batch.targets:
        prefix, separator, name = target.id.partition(":")
        path = Path(target.path)
        if (
            prefix != "user-caches"
            or not separator
            or not name
            or target.risk is not expected_risk
            or not _SHA256.fullmatch(target.fingerprint)
            or path != root / name
            or path.parent != root
        ):
            raise ValueError("target is outside the trusted user-cache module root")


def _trusted_home(injected: Path | None) -> Path:
    home = injected if injected is not None else Path(pwd.getpwuid(os.getuid()).pw_dir)
    return _canonical_existing_directory(home, "trusted home")


def _trusted_cache_root(home: Path) -> Path:
    return _canonical_existing_directory(home / "Library" / "Caches", "cache root")


def _canonical_existing_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be absolute and canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ValueError(f"{label} must not contain symlinks")
    canonical = path.resolve(strict=True)
    if canonical != path or not canonical.is_dir():
        raise ValueError(f"{label} must be an existing canonical directory")
    return canonical


def _session_artifact_path(
    path: str | os.PathLike[str], label: str
) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"administrative {label} path must be absolute")
    parent = candidate.parent.resolve(strict=True)
    if parent != candidate.parent:
        raise ValueError(f"administrative {label} parent must be canonical")
    if any(character in str(candidate) for character in ("\0", "\n", "\r")):
        raise ValueError(f"administrative {label} path is not auditable")
    return candidate


def _operation_digest(
    batch: Batch,
    script_checksum: str,
    manifest_digest: str,
    session_path: Path,
    output_path: Path,
    result_path: Path,
    snapshot_path: Path,
    snapshot_digest: str,
    allowed_root: Path,
    session_uid: int,
    session_gid: int,
) -> str:
    value = {
        "allowed_root": str(allowed_root),
        "batch": batch.to_dict(),
        "checksum": script_checksum,
        "manifest_digest": manifest_digest,
        "output_path": str(output_path),
        "result_path": str(result_path),
        "session_path": str(session_path),
        "session_gid": session_gid,
        "session_uid": session_uid,
        "snapshot_digest": snapshot_digest,
        "snapshot_path": str(snapshot_path),
    }
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _manifest_digest(session: Session) -> str:
    state = session.state
    record = state.get("manifest")
    if not isinstance(record, Mapping) or not isinstance(record.get("digest"), str):
        raise ValueError("session has no immutable manifest digest")
    digest = record["digest"]
    if not _SHA256.fullmatch(digest):
        raise ValueError("session manifest digest is invalid")
    return digest


def _admin_bindings(session: Session) -> dict[str, Mapping[str, object]]:
    state = session.state
    value = state.get("admin_scripts", {})
    if not isinstance(value, Mapping):
        raise ValueError("session administrative bindings are malformed")
    result: dict[str, Mapping[str, object]] = {}
    for batch_id, binding in value.items():
        if not isinstance(batch_id, str) or not isinstance(binding, Mapping):
            raise ValueError("session administrative binding is malformed")
        result[batch_id] = binding
    return result


def _validate_binding(binding: Mapping[str, object]) -> None:
    keys = {
        "allowed_root",
        "batch",
        "batch_id",
        "checksum",
        "manifest_digest",
        "operation_digest",
        "output_path",
        "result_path",
        "session_path",
        "session_gid",
        "session_uid",
        "snapshot_digest",
        "snapshot_path",
        "target_ids",
    }
    if set(binding) != keys:
        raise ValueError("administrative binding fields do not match schema")
    text_keys = keys - {"batch", "session_gid", "session_uid", "target_ids"}
    for key in text_keys:
        if not isinstance(binding[key], str):
            raise ValueError("administrative binding text field is invalid")
    if not isinstance(binding["batch"], Mapping):
        raise ValueError("administrative binding batch is invalid")
    for key in ("session_gid", "session_uid"):
        if type(binding[key]) is not int or binding[key] < 0:
            raise ValueError("administrative binding owner is invalid")
    target_ids = binding["target_ids"]
    if not isinstance(target_ids, list) or not all(
        isinstance(target_id, str) for target_id in target_ids
    ):
        raise ValueError("administrative binding target ids are invalid")
    for key in (
        "checksum",
        "manifest_digest",
        "operation_digest",
        "snapshot_digest",
    ):
        if not _SHA256.fullmatch(binding[key]):
            raise ValueError("administrative binding digest is invalid")


def _validate_result_binding(
    value: Mapping[str, object], expected: Mapping[str, object]
) -> dict[str, Mapping[str, object]]:
    """Validate the exact result schema and immutable batch binding."""
    keys = {"schema_version", "batch_id", "operation_digest", "target_ids", "targets"}
    if set(value) != keys or value.get("schema_version") != RESULT_SCHEMA_VERSION:
        raise ValueError("administrative result fields do not match schema")
    for key in ("batch_id", "operation_digest", "target_ids"):
        if value.get(key) != expected.get(key):
            raise ValueError("administrative result binding differs from state")
    target_ids = value["target_ids"]
    if (
        not isinstance(target_ids, list)
        or not all(isinstance(item, str) for item in target_ids)
        or len(target_ids) != len(set(target_ids))
    ):
        raise ValueError("administrative result target ids are invalid")
    targets = value["targets"]
    if not isinstance(targets, Mapping) or not set(targets).issubset(set(target_ids)):
        raise ValueError("administrative result contains an unknown target id")
    validated: dict[str, Mapping[str, object]] = {}
    for target_id, record in targets.items():
        if not isinstance(target_id, str) or not isinstance(record, Mapping):
            raise ValueError("administrative target result is malformed")
        if set(record) != {"issues", "logical_bytes_removed", "status"}:
            raise ValueError("administrative target result fields do not match schema")
        if record["status"] not in {"verified", "suspended"}:
            raise ValueError("administrative target result status is invalid")
        removed = record["logical_bytes_removed"]
        if type(removed) is not int or removed < 0:
            raise ValueError("administrative removed byte count is invalid")
        issues = record["issues"]
        if not isinstance(issues, list):
            raise ValueError("administrative target result issues are invalid")
        for issue in issues:
            if not isinstance(issue, Mapping) or Issue.from_dict(issue).to_dict() != issue:
                raise ValueError("administrative target result issue is invalid")
        validated[target_id] = record
    return validated


def _bound_session_artifact(
    session: Session, value: object, label: str
) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"administrative {label} path is invalid")
    path = _session_artifact_path(value, label)
    if path.parent != session.path:
        raise ValueError(f"administrative {label} is outside the bound session")
    return path


def _read_owned_regular_bytes(
    path: Path,
    label: str,
    owner_uid: object,
    owner_gid: object,
    mode: int,
) -> bytes:
    if type(owner_uid) is not int or type(owner_gid) is not int:
        raise ValueError(f"{label} owner binding is invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or before.st_gid != owner_gid
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size > 16 * 1024 * 1024
        ):
            raise ValueError(f"{label} owner, mode, type, or size is unsafe")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"{label} was truncated while validating")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} grew while validating")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_mtime_ns,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_mtime_ns,
            after.st_size,
        ):
            raise ValueError(f"{label} changed while validating")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_owned_regular_file(
    path: Path, label: str, owner_uid: int, owner_gid: int, mode: int
) -> None:
    path_stat = path.lstat()
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or not stat.S_ISREG(path_stat.st_mode)
        or path_stat.st_uid != owner_uid
        or path_stat.st_gid != owner_gid
        or stat.S_IMODE(path_stat.st_mode) != mode
    ):
        raise ValueError(f"{label} owner, mode, or type is unsafe")


def _suspend_missing_result_file(
    session: Session, batch: Batch, result_path: Path
) -> None:
    issue = Issue(
        "admin.missing-results-file",
        Severity.BATCH_ERROR,
        f"Administrative result file is missing: {result_path}",
    )
    session.add_issue(issue)
    mutable = tuple(
        target.id
        for target in batch.targets
        if session.status(target.id) in {"approved", "applied"}
    )
    if mutable:
        session.transition_batch(mutable, "suspended")


def _atomic_write_bytes_owned(
    path: Path, payload: bytes, owner_uid: int, owner_gid: int, mode: int
) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.geteuid() == 0:
            os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, mode)
        current = os.fstat(descriptor)
        if (
            current.st_uid != owner_uid
            or current.st_gid != owner_gid
            or stat.S_IMODE(current.st_mode) != mode
        ):
            raise ValueError("administrative artifact owner or mode is unsafe")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        final = path.lstat()
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != owner_uid
            or final.st_gid != owner_gid
            or stat.S_IMODE(final.st_mode) != mode
        ):
            raise ValueError("published administrative artifact is unsafe")
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
