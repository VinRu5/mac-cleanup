import os
import unittest
from pathlib import Path

from scripts.mac_cleanup.models import Risk
from scripts.mac_cleanup.modules.base import ScanContext
from scripts.mac_cleanup.modules.registry import registered_modules
from scripts.mac_cleanup.modules.user_caches import UserCachesModule
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
