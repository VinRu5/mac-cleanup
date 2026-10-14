import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.admin_script import (
    generate_admin_script,
    import_admin_results,
    quote_zsh_literal,
)
from scripts.mac_cleanup.models import Batch, Manifest, Risk, Target
from scripts.mac_cleanup.paths import inspect_path
from scripts.mac_cleanup.sessions import Session


class AdminScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.home = self.root / "home"
        self.cache_root = self.home / "Library" / "Caches"
        self.cache_root.mkdir(parents=True)
        self.session = Session.create(self.root / "session")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _target(
        self,
        name: str,
        content: bytes = b"cache",
        risk: Risk = Risk.SAFE_REGENERABLE,
    ) -> Target:
        path = self.cache_root / name
        path.mkdir()
        (path / "entry.bin").write_bytes(content)
        identity = inspect_path(path, (self.cache_root,))
        return Target(
            id=f"user-caches:{name}",
            path=identity.canonical,
            kind=identity.kind,
            risk=risk,
            fingerprint=identity.fingerprint,
            logical_bytes=identity.logical_bytes,
        )

    def _register(self, *batches: Batch) -> None:
        self.session.write_manifest(
            Manifest(batches=batches, inventory_digest="a" * 64)
        )
        for batch in batches:
            self.session.transition_batch(
                tuple(target.id for target in batch.targets), "approved"
            )

    def _paths(self, suffix: str = "") -> tuple[Path, Path]:
        return (
            self.session.path / f"admin{suffix}.zsh",
            self.session.path / f"admin-results{suffix}.json",
        )

    def _generate(self, batch: Batch, suffix: str = "") -> tuple[str, Path, Path]:
        script_path, result_path = self._paths(suffix)
        checksum = generate_admin_script(
            batch,
            script_path,
            result_path,
            trusted_home=self.home,
        )
        return checksum, script_path, result_path

    def test_quote_zsh_literal_handles_an_embedded_single_quote(self) -> None:
        self.assertEqual(quote_zsh_literal("a'b"), "'a'\\''b'")

    def test_generated_script_is_static_auditable_and_checksum_is_stable(self) -> None:
        target = self._target("cache with ' quote")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)

        checksum, script_path, result_path = self._generate(batch)
        first = script_path.read_text(encoding="utf-8")
        repeated = generate_admin_script(
            batch,
            script_path,
            result_path,
            trusted_home=self.home,
        )

        self.assertEqual(checksum, repeated)
        self.assertEqual(first, script_path.read_text(encoding="utf-8"))
        self.assertTrue(first.startswith("#!/bin/zsh\nset -eu\n"))
        self.assertIn(quote_zsh_literal(target.path), first)
        for forbidden in (
            "$HOME",
            "${HOME}",
            "$(",
            "`",
            "eval ",
            "chmod -R",
            "chown -R",
        ):
            self.assertNotIn(forbidden, first)
        self.assertNotIn("*", first)
        binding = self.session.state["admin_scripts"][batch.id]
        self.assertEqual(binding["checksum"], checksum)
        self.assertRegex(binding["engine_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(binding["result_path"], str(result_path))

    def test_script_executes_only_the_approved_fixture_target(self) -> None:
        target = self._target("approved")
        sibling = self.cache_root / "preserved"
        sibling.mkdir()
        (sibling / "keep.txt").write_text("keep", encoding="utf-8")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(Path(target.path).exists())
        self.assertEqual((sibling / "keep.txt").read_text(encoding="utf-8"), "keep")
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"][target.id]["status"], "verified")
        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )
        self.assertEqual(self.session.status(target.id), "verified")

    def test_generation_rejects_a_forged_approved_target_outside_trusted_cache(self) -> None:
        outside_root = self.root / "outside"
        outside_root.mkdir()
        outside = outside_root / "forged"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        identity = inspect_path(outside, (outside_root,))
        forged = Target(
            id="user-caches:forged",
            path=identity.canonical,
            kind=identity.kind,
            risk=Risk.SAFE_REGENERABLE,
            fingerprint=identity.fingerprint,
            logical_bytes=identity.logical_bytes,
        )
        batch = Batch("safe-user-caches", (forged,))
        self._register(batch)

        with self.assertRaises(ValueError):
            self._generate(batch)

        self.assertTrue(outside.exists())

    def test_generation_requires_exact_approved_session_batch(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self.session.write_manifest(
            Manifest(batches=(batch,), inventory_digest="a" * 64)
        )

        with self.assertRaises(ValueError):
            self._generate(batch)

        self.session.transition(target.id, "approved")
        with self.assertRaises(ValueError):
            self._generate(Batch(batch.id, ()))

    def test_changed_identity_stops_script_and_leaves_later_target_untouched(self) -> None:
        changed = self._target("a-changed", b"old")
        later = self._target("b-later")
        batch = Batch("safe-user-caches", (changed, later))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)
        (Path(changed.path) / "entry.bin").write_bytes(b"replacement")

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(changed.path).exists())
        self.assertTrue(Path(later.path).exists())
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"][changed.id]["status"], "suspended")
        self.assertNotIn(later.id, results["targets"])
        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )
        self.assertEqual(self.session.status(changed.id), "suspended")
        self.assertEqual(self.session.status(later.id), "suspended")

    def test_missing_results_suspend_only_that_batch(self) -> None:
        completed_target = self._target("a-completed")
        missing_target = self._target("b-missing")
        independent_target = self._target(
            "independent", risk=Risk.REVIEW_REQUIRED
        )
        first = Batch("safe-user-caches", (completed_target, missing_target))
        second = Batch("review-user-caches", (independent_target,))
        self._register(first, second)
        checksum, script_path, result_path = self._generate(first)
        os.unlink(missing_target.path + "/entry.bin")
        os.rmdir(missing_target.path)
        script_lines = script_path.read_text(encoding="utf-8").splitlines()
        script_path.write_text("\n".join(script_lines[:3]) + "\n", encoding="utf-8")
        os.chmod(script_path, 0o700)
        # Bind the deliberately shortened execution by restoring the original
        # after the first verifier call; import must still use result presence,
        # not assume whole-script success.
        original = "\n".join(script_lines) + "\n"
        subprocess.run((str(script_path),), check=True)
        script_path.write_text(original, encoding="utf-8")
        os.chmod(script_path, 0o700)

        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )

        self.assertEqual(self.session.status(completed_target.id), "verified")
        self.assertEqual(self.session.status(missing_target.id), "suspended")
        self.assertEqual(self.session.status(independent_target.id), "approved")

    def test_unknown_target_id_and_checksum_mismatch_are_rejected_without_transition(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, _, result_path = self._generate(batch)
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results["targets"]["user-caches:unknown"] = {
            "issues": [],
            "logical_bytes_removed": 0,
            "status": "verified",
        }
        result_path.write_text(json.dumps(results), encoding="utf-8")

        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                checksum,
                trusted_home=self.home,
            )
        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                "0" * 64,
                trusted_home=self.home,
            )
        self.assertEqual(self.session.status(target.id), "approved")

    def test_forged_verified_result_cannot_authorize_a_present_target(self) -> None:
        target = self._target("still-present")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, _, result_path = self._generate(batch)
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results["targets"][target.id] = {
            "issues": [],
            "logical_bytes_removed": target.logical_bytes,
            "status": "verified",
        }
        result_path.write_text(json.dumps(results), encoding="utf-8")

        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )

        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "suspended")

    def test_modified_script_blocks_import(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)
        original = script_path.read_text(encoding="utf-8")
        script_path.write_text(original + "# changed\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                checksum,
                trusted_home=self.home,
            )
        self.assertEqual(self.session.status(target.id), "approved")

    def test_missing_result_file_suspends_the_bound_batch(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, _, result_path = self._generate(batch)
        result_path.unlink()

        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )

        self.assertEqual(self.session.status(target.id), "suspended")

    def test_retry_stops_if_a_previously_removed_target_was_regenerated(self) -> None:
        target = self._target("regenerated")
        later = self._target("z-later")
        batch = Batch("safe-user-caches", (target, later))
        self._register(batch)
        _, script_path, result_path = self._generate(batch)
        first_line = script_path.read_text(encoding="utf-8").splitlines()[2]
        one_target = "#!/bin/zsh\nset -eu\n" + first_line + "\n"
        script_path.write_text(one_target, encoding="utf-8")
        os.chmod(script_path, 0o700)
        subprocess.run((str(script_path),), check=True)
        recreated = Path(target.path)
        recreated.mkdir()
        (recreated / "new.bin").write_bytes(b"new")

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(recreated.exists())
        self.assertTrue(Path(later.path).exists())
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"][target.id]["status"], "suspended")

    def test_critical_result_latches_session_and_blocks_independent_import(self) -> None:
        unsafe = self._target("unsafe")
        independent = self._target("independent", risk=Risk.REVIEW_REQUIRED)
        first = Batch("safe-user-caches", (unsafe,))
        second = Batch("review-user-caches", (independent,))
        self._register(first, second)
        first_checksum, first_script, first_result = self._generate(first, "-first")
        second_checksum, _, second_result = self._generate(second, "-second")
        unsafe_path = Path(unsafe.path)
        (unsafe_path / "entry.bin").unlink()
        unsafe_path.rmdir()
        os.symlink(self.root, unsafe_path)

        completed = subprocess.run(
            (str(first_script),), capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 4)
        import_admin_results(
            self.session,
            first_result,
            first_checksum,
            trusted_home=self.home,
        )

        self.assertIsNotNone(self.session.critical_issue())
        self.assertEqual(self.session.status(independent.id), "approved")
        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                second_result,
                second_checksum,
                trusted_home=self.home,
            )
        self.assertTrue(Path(independent.path).exists())


if __name__ == "__main__":
    unittest.main()
