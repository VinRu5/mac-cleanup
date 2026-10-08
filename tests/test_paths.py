import os
import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.paths import (
    PathSafetyError,
    inspect_path,
    remove_tree_exact,
)


class PathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.allowed_root = self.root / "allowed"
        self.allowed_root.mkdir()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_rejects_relative_outside_and_allowed_root_paths(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()

        for candidate in (Path("relative"), outside, self.allowed_root):
            with self.subTest(candidate=candidate):
                with self.assertRaises(PathSafetyError):
                    inspect_path(candidate, (self.allowed_root,))

    def test_rejects_a_symlink_target(self) -> None:
        target = self.allowed_root / "target"
        target.mkdir()
        symlink = self.allowed_root / "link"
        os.symlink(target, symlink)

        with self.assertRaises(PathSafetyError):
            inspect_path(symlink, (self.allowed_root,))

    def test_fingerprint_changes_when_target_changes(self) -> None:
        target = self.allowed_root / "cache.bin"
        target.write_bytes(b"one")
        before = inspect_path(target, (self.allowed_root,))

        target.write_bytes(b"a longer replacement")
        after = inspect_path(target, (self.allowed_root,))

        self.assertNotEqual(before.fingerprint, after.fingerprint)
        self.assertNotEqual(before.logical_bytes, after.logical_bytes)

    def test_remove_tree_deletes_only_the_identified_directory(self) -> None:
        target = self.allowed_root / "remove-me"
        target.mkdir()
        (target / "nested").mkdir()
        (target / "nested" / "cache.bin").write_bytes(b"data")
        sibling = self.allowed_root / "keep-me"
        sibling.mkdir()
        (sibling / "important.txt").write_text("keep", encoding="utf-8")
        identity = inspect_path(target, (self.allowed_root,))

        removed_bytes = remove_tree_exact(identity, (self.allowed_root,))

        self.assertEqual(removed_bytes, identity.logical_bytes)
        self.assertFalse(target.exists())
        self.assertEqual((sibling / "important.txt").read_text(encoding="utf-8"), "keep")

    def test_remove_tree_rejects_a_stale_identity(self) -> None:
        target = self.allowed_root / "cache.bin"
        target.write_bytes(b"old")
        identity = inspect_path(target, (self.allowed_root,))
        target.write_bytes(b"new value")

        with self.assertRaises(PathSafetyError):
            remove_tree_exact(identity, (self.allowed_root,))
        self.assertTrue(target.exists())

    def test_fingerprint_changes_after_equal_size_descendant_edit(self) -> None:
        target = self.allowed_root / "cache"
        target.mkdir()
        child = target / "entry.bin"
        child.write_bytes(b"same")
        before = inspect_path(target, (self.allowed_root,))

        child.write_bytes(b"size")
        after = inspect_path(target, (self.allowed_root,))

        self.assertNotEqual(before.fingerprint, after.fingerprint)

    def test_remove_tree_rejects_a_replaced_target_symlink(self) -> None:
        target = self.allowed_root / "cache"
        target.mkdir()
        (target / "entry.bin").write_bytes(b"cache")
        identity = inspect_path(target, (self.allowed_root,))
        outside = self.root / "outside"
        outside.mkdir()
        protected = outside / "important.txt"
        protected.write_text("keep", encoding="utf-8")

        (target / "entry.bin").unlink()
        target.rmdir()
        os.symlink(outside, target)

        with self.assertRaises(PathSafetyError):
            remove_tree_exact(identity, (self.allowed_root,))
        self.assertEqual(protected.read_text(encoding="utf-8"), "keep")

    def test_remove_tree_rejects_a_replaced_descendant_symlink(self) -> None:
        target = self.allowed_root / "cache"
        target.mkdir()
        child = target / "entry.bin"
        child.write_bytes(b"cache")
        identity = inspect_path(target, (self.allowed_root,))
        outside = self.root / "outside"
        outside.mkdir()
        protected = outside / "important.txt"
        protected.write_text("keep", encoding="utf-8")

        child.unlink()
        os.symlink(outside, child)

        with self.assertRaises(PathSafetyError):
            remove_tree_exact(identity, (self.allowed_root,))
        self.assertEqual(protected.read_text(encoding="utf-8"), "keep")

    def test_remove_tree_rejects_identity_outside_supplied_allowed_roots(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "cache.bin").write_bytes(b"cache")
        forged_identity = inspect_path(outside, (self.root,))

        with self.assertRaises(PathSafetyError):
            remove_tree_exact(forged_identity, (self.allowed_root,))
        self.assertTrue(outside.exists())

    def test_rejects_symlinks_found_inside_a_directory(self) -> None:
        target = self.allowed_root / "cache"
        target.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        os.symlink(outside, target / "nested-link")

        with self.assertRaises(PathSafetyError):
            inspect_path(target, (self.allowed_root,))


if __name__ == "__main__":
    unittest.main()
