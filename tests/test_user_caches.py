import os
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.mac_cleanup.models import Risk
from scripts.mac_cleanup.modules.base import ScanContext
from scripts.mac_cleanup.modules.registry import registered_modules
from scripts.mac_cleanup.modules.user_caches import UserCachesModule
from scripts.mac_cleanup.paths import inspect_path
from scripts.mac_cleanup.process import ProcessRunner
from tests.fixtures import fake_home


class UserCachesModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.home_fixture = fake_home()
        self.home = self.home_fixture.__enter__()
        self.context = ScanContext(
            home=self.home,
            uid=os.getuid(),
            runner=ProcessRunner(),
            deep_scan_threshold=1,
            timeout_seconds=1,
        )
        self.module = UserCachesModule()

    def tearDown(self) -> None:
        self.home_fixture.__exit__(None, None, None)

    def test_fast_scan_proposes_only_immediate_non_apple_cache_children(self) -> None:
        result = self.module.fast_scan(self.context)

        cache_root = self.home / "Library" / "Caches"
        self.assertEqual(
            [target.path for target in result.targets],
            [
                str(cache_root / "Codex"),
                str(cache_root / "com.example.app"),
                str(cache_root / "io.sentry"),
            ],
        )
        self.assertEqual(
            [target.risk for target in result.targets],
            [Risk.REVIEW_REQUIRED, Risk.SAFE_REGENERABLE, Risk.REVIEW_REQUIRED],
        )
        for target in result.targets:
            self.assertEqual(Path(target.path).parent, cache_root)

    def test_deep_scan_revalidates_selected_cache_candidates_only(self) -> None:
        fast = self.module.fast_scan(self.context)
        candidate = next(target for target in fast.targets if target.path.endswith("com.example.app"))

        result = self.module.deep_scan(self.context, (candidate.id,))

        self.assertEqual([target.id for target in result.targets], [candidate.id])
        self.assertEqual([target.path for target in result.targets], [candidate.path])
        proposed_paths = {target.path for target in result.targets}
        self.assertNotIn(str(self.home / "Library" / "Application Support"), proposed_paths)
        self.assertNotIn(str(self.home / ".env"), proposed_paths)
        self.assertNotIn(str(self.home / "project"), proposed_paths)
        self.assertEqual(result.executable_target_ids, (candidate.id,))

    def test_fast_scan_does_not_recursively_inspect_a_problematic_child(self) -> None:
        cache_root = self.home / "Library" / "Caches"
        os.symlink(self.home / "project", cache_root / "com.example.app" / "nested-link")

        with patch(
            "scripts.mac_cleanup.modules.user_caches.inspect_path",
            side_effect=AssertionError("fast scan must not inspect recursively"),
        ):
            result = self.module.fast_scan(self.context)

        candidate = next(target for target in result.targets if target.id == "user-caches:com.example.app")
        self.assertEqual(candidate.logical_bytes, (cache_root / "com.example.app").lstat().st_size)
        self.assertEqual(candidate.fingerprint, "")
        self.assertEqual(result.executable_target_ids, ())

    def test_deep_scan_recursively_inspects_only_selected_candidate_ids(self) -> None:
        fast = self.module.fast_scan(self.context)
        selected = next(target for target in fast.targets if target.id == "user-caches:com.example.app")

        with patch(
            "scripts.mac_cleanup.modules.user_caches.inspect_path", wraps=inspect_path
        ) as inspected:
            result = self.module.deep_scan(self.context, (selected.id,))

        inspected.assert_called_once_with(
            self.home / "Library" / "Caches" / "com.example.app",
            (self.home / "Library" / "Caches",),
        )
        self.assertEqual(result.executable_target_ids, (selected.id,))

    def test_deep_scan_observes_the_threshold_boundary(self) -> None:
        selected = "user-caches:com.example.app"
        at_threshold = replace(self.context, deep_scan_threshold=5)
        above_threshold = replace(self.context, deep_scan_threshold=6)

        self.assertEqual(
            [target.id for target in self.module.deep_scan(at_threshold, (selected,)).targets],
            [selected],
        )
        self.assertEqual(self.module.deep_scan(above_threshold, (selected,)).targets, ())

    def test_root_scandir_failure_is_reported_instead_of_looking_empty(self) -> None:
        with patch(
            "scripts.mac_cleanup.modules.user_caches.os.scandir",
            side_effect=PermissionError("denied"),
        ):
            detected = self.module.detect(self.context)
            result = self.module.fast_scan(self.context)

        self.assertTrue(detected)
        self.assertEqual(result.targets, ())
        self.assertEqual(
            [issue.code for issue in result.issues],
            ["user-caches.cache-root-unavailable"],
        )

    def test_present_but_access_denied_root_is_detected_and_reported(self) -> None:
        with patch(
            "scripts.mac_cleanup.modules.user_caches.os.access", return_value=False
        ):
            detected = self.module.detect(self.context)
            result = self.module.fast_scan(self.context)

        self.assertTrue(detected)
        self.assertEqual(result.targets, ())
        self.assertEqual(
            [issue.code for issue in result.issues],
            ["user-caches.cache-root-unavailable"],
        )

    def test_absent_cache_root_is_not_detected(self) -> None:
        missing_context = replace(self.context, home=self.home / "missing-home")

        self.assertFalse(self.module.detect(missing_context))

    def test_deep_scan_does_not_accept_path_like_or_unknown_candidate_ids(self) -> None:
        result = self.module.deep_scan(
            self.context,
            ("user-caches:../project", "user-caches:missing"),
        )

        self.assertEqual(result.targets, ())

    def test_fast_scan_excludes_apple_caches_and_symlink_entries(self) -> None:
        cache_root = self.home / "Library" / "Caches"
        apple_cache = cache_root / "com.apple.finder"
        apple_cache.mkdir()
        symlink = cache_root / "linked-cache"
        os.symlink(cache_root / "com.example.app", symlink)

        result = self.module.fast_scan(self.context)

        proposed_paths = {target.path for target in result.targets}
        self.assertNotIn(str(apple_cache), proposed_paths)
        self.assertNotIn(str(symlink), proposed_paths)
        self.assertIn("user-caches.candidate-unavailable", {issue.code for issue in result.issues})

    def test_registry_is_a_fixed_deterministic_module_list(self) -> None:
        modules = registered_modules()

        self.assertEqual(tuple(module.id for module in modules), ("user-caches",))
        self.assertTrue(all(isinstance(module, UserCachesModule) for module in modules))


if __name__ == "__main__":
    unittest.main()
