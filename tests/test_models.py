import os
import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.jsonio import atomic_write_json, canonical_bytes, read_json
from scripts.mac_cleanup.models import Batch, Manifest, Risk, Target, TargetStatus


class ModelsTest(unittest.TestCase):
    def test_manifest_serialization_is_stable_and_records_are_frozen(self) -> None:
        target = Target(
            id="target-b", path="/tmp/b", kind="directory",
            risk=Risk.SAFE_REGENERABLE, status=TargetStatus.PENDING,
            fingerprint="b", logical_bytes=2,
        )
        other = Target(
            id="target-a", path="/tmp/a", kind="directory",
            risk=Risk.SAFE_REGENERABLE, status=TargetStatus.PENDING,
            fingerprint="a", logical_bytes=1,
        )
        manifest = Manifest(
            schema_version=1,
            batches=(Batch(id="b", targets=(target, other)),),
        )
        first = canonical_bytes(manifest.to_dict())
        self.assertEqual(first, canonical_bytes(manifest.to_dict()))
        self.assertEqual([t.id for t in manifest.batches[0].targets], ["target-a", "target-b"])
        with self.assertRaises((AttributeError, TypeError)):
            target.path = "/tmp/changed"  # type: ignore[misc]

    def test_atomic_json_round_trip_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "manifest.json"
            atomic_write_json(path, {"unicode": "café", "n": 1})
            self.assertEqual(read_json(path), {"unicode": "café", "n": 1})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
