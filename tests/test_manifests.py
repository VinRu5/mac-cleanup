import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.jsonio import atomic_write_json, canonical_bytes, read_json
from scripts.mac_cleanup.manifests import approval_digest, approve_batch, build_manifest
from scripts.mac_cleanup.models import Batch, Manifest, Risk, Target
from scripts.mac_cleanup.modules.base import ScanResult
from scripts.mac_cleanup.sessions import Session


def target(target_id: str, risk: Risk, path: str | None = None, fingerprint: str = "deep") -> Target:
    return Target(
        id=target_id,
        path=path or f"/private/tmp/{target_id}",
        kind="directory",
        risk=risk,
        fingerprint=fingerprint,
        logical_bytes=42,
    )


def policy(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "enabled_modules": ["user-caches"],
        "preserve_target_ids": [],
        "allow_review_required": False,
        "deep_scan_threshold_bytes": 1_073_741_824,
    }
    value.update(overrides)
    return value


class ManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.safe = target("user-caches:example", Risk.SAFE_REGENERABLE)
        self.review = target("user-caches:Codex", Risk.REVIEW_REQUIRED)
        self.never = target("user-caches:private", Risk.NEVER_AUTOMATIC)

    def test_manifest_and_approval_digest_are_deterministic(self) -> None:
        first = ScanResult(
            targets=(self.review, self.never, self.safe),
            executable_target_ids=(self.review.id, self.never.id, self.safe.id),
        )
        second = ScanResult(
            targets=(self.safe, self.never, self.review),
            executable_target_ids=(self.safe.id, self.review.id, self.never.id),
        )

        first_manifest = build_manifest(first, policy(allow_review_required=True))
        second_manifest = build_manifest(second, policy(allow_review_required=True))

        self.assertEqual(canonical_bytes(first_manifest.to_dict()), canonical_bytes(second_manifest.to_dict()))
        self.assertEqual(
            approval_digest(first_manifest, "safe-user-caches"),
            approval_digest(second_manifest, "safe-user-caches"),
        )
        self.assertEqual(
            approval_digest(first_manifest, "safe-user-caches"),
            hashlib.sha256(
                canonical_bytes(
                    {
                        "batch": next(
                            batch.to_dict()
                            for batch in first_manifest.batches
                            if batch.id == "safe-user-caches"
                        ),
                        "inventory_digest": first_manifest.inventory_digest,
                        "manifest_schema_version": 1,
                    }
                )
            ).hexdigest(),
        )
        self.assertEqual(
            [(batch.id, [item.id for item in batch.targets])
            for batch in first_manifest.batches],
            [
                ("review-user-caches", ["user-caches:Codex"]),
                ("safe-user-caches", ["user-caches:example"]),
            ],
        )

    def test_review_and_never_automatic_targets_are_not_safe_batch_members(self) -> None:
        inventory = ScanResult(
            targets=(self.safe, self.review, self.never),
            executable_target_ids=(self.safe.id, self.review.id, self.never.id),
        )

        manifest = build_manifest(inventory, policy())

        self.assertEqual([(batch.id, [item.id for item in batch.targets]) for batch in manifest.batches], [
            ("safe-user-caches", [self.safe.id]),
        ])

    def test_fast_scan_target_cannot_enter_an_executable_or_approvable_batch(self) -> None:
        shallow = Target(
            id="user-caches:shallow",
            path="/private/tmp/shallow",
            kind="directory",
            risk=Risk.SAFE_REGENERABLE,
            logical_bytes=1,
        )
        inventory = ScanResult(targets=(shallow,))

        manifest = build_manifest(inventory, policy())

        self.assertEqual(manifest.batches, ())
        with tempfile.TemporaryDirectory() as directory:
            session = Session.create(Path(directory) / "session")
            session.write_manifest(manifest)
            with self.assertRaises(ValueError):
                approve_batch(session, "safe-user-caches", "not-a-real-digest")
            self.assertEqual(session.state["targets"], {})

    def test_executable_target_requires_non_empty_deep_fingerprint(self) -> None:
        incomplete = target("user-caches:incomplete", Risk.SAFE_REGENERABLE, fingerprint="")
        inventory = ScanResult(targets=(incomplete,), executable_target_ids=(incomplete.id,))

        with self.assertRaisesRegex(ValueError, "fingerprint"):
            build_manifest(inventory, policy())

    def test_exact_approval_changes_only_requested_batch(self) -> None:
        inventory = ScanResult(
            targets=(self.safe, self.review),
            executable_target_ids=(self.safe.id, self.review.id),
        )
        manifest = build_manifest(inventory, policy(allow_review_required=True))
        with tempfile.TemporaryDirectory() as directory:
            session = Session.create(Path(directory) / "session")
            session.write_manifest(manifest)

            approve_batch(session, "safe-user-caches", approval_digest(manifest, "safe-user-caches"))

            self.assertEqual(session.status(self.safe.id), "approved")
            self.assertEqual(session.status(self.review.id), "pending")

    def test_digest_mismatch_leaves_state_unchanged(self) -> None:
        inventory = ScanResult(targets=(self.safe,), executable_target_ids=(self.safe.id,))
        manifest = build_manifest(inventory, policy())
        with tempfile.TemporaryDirectory() as directory:
            session = Session.create(Path(directory) / "session")
            session.write_manifest(manifest)

            with self.assertRaises(ValueError):
                approve_batch(session, "safe-user-caches", "wrong")

            self.assertEqual(session.status(self.safe.id), "pending")
            self.assertEqual(session.state["events"], [])

    def test_approval_rejects_a_manifest_artifact_changed_after_persistence(self) -> None:
        inventory = ScanResult(targets=(self.safe,), executable_target_ids=(self.safe.id,))
        manifest = build_manifest(inventory, policy())
        with tempfile.TemporaryDirectory() as directory:
            session = Session.create(Path(directory) / "session")
            session.write_manifest(manifest)
            changed = read_json(session.manifest_path)
            changed["batches"][0]["targets"][0]["fingerprint"] = "changed"  # type: ignore[index]
            atomic_write_json(session.manifest_path, changed)

            with self.assertRaises(ValueError):
                approve_batch(session, "safe-user-caches", approval_digest(manifest, "safe-user-caches"))

            self.assertEqual(session.status(self.safe.id), "pending")

    def test_approval_rejects_hand_persisted_unsafe_manifests_with_matching_digests(self) -> None:
        cases = (
            (
                "empty-fingerprint",
                Manifest(
                    inventory_digest="a" * 64,
                    batches=(Batch("safe-user-caches", (target("user-caches:shallow", Risk.SAFE_REGENERABLE, fingerprint=""),)),),
                ),
            ),
            (
                "never-automatic",
                Manifest(
                    inventory_digest="a" * 64,
                    batches=(Batch("safe-user-caches", (self.never,)),),
                ),
            ),
            (
                "batch-risk-mismatch",
                Manifest(
                    inventory_digest="a" * 64,
                    batches=(Batch("safe-user-caches", (self.review,)),),
                ),
            ),
            (
                "empty-inventory-digest",
                Manifest(batches=(Batch("safe-user-caches", (self.safe,)),)),
            ),
        )
        for name, manifest in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                session = Session.create(Path(directory) / "session")
                session.write_manifest(manifest)

                with self.assertRaises(ValueError):
                    approve_batch(session, "safe-user-caches", approval_digest(manifest, "safe-user-caches"))

                self.assertEqual(session.state["events"], [])
                self.assertTrue(all(status == "pending" for status in session.state["targets"].values()))

    def test_approval_rejects_unknown_or_omitted_default_raw_manifest_fields(self) -> None:
        inventory = ScanResult(targets=(self.safe,), executable_target_ids=(self.safe.id,))
        manifest = build_manifest(inventory, policy())
        for name in ("unknown", "omitted-default"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                session = Session.create(Path(directory) / "session")
                session.write_manifest(manifest)
                changed = read_json(session.manifest_path)
                if name == "unknown":
                    changed["unrecognized"] = True
                else:
                    del changed["batches"][0]["targets"][0]["status"]  # type: ignore[index]
                atomic_write_json(session.manifest_path, changed)

                with self.assertRaises(ValueError):
                    approve_batch(session, "safe-user-caches", approval_digest(manifest, "safe-user-caches"))

                self.assertEqual(session.status(self.safe.id), "pending")
                self.assertEqual(session.state["events"], [])


if __name__ == "__main__":
    unittest.main()
