"""Vivaldi (Chromium-based) is discovered and scanned like the other Chromium browsers."""

import os
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [os.path.dirname(os.path.dirname(__file__)), os.path.dirname(__file__)]

from test_browser_launch import (BrowserLaunchBase, TEST_DOMAIN,
                                 chromium_history_db, chromium_cookie_db)
from adint_scan.modules import browser
from adint_scan.result import UNKNOWN, PARTIAL, EV_CONTACTED, EV_REFERENCED


class TestVivaldiRoots(unittest.TestCase):
    def roots(self, platform, **env):
        with patch.object(browser.sys, "platform", platform), \
                patch.object(browser, "LOCAL", env.get("local", "")), \
                patch.object(browser.os.path, "expanduser", lambda p: "/home/u"):
            return dict(browser._chromium_roots())

    def test_windows(self):
        roots = self.roots("win32", local="C:\\L")
        self.assertIn("vivaldi", roots)
        self.assertEqual(roots["vivaldi"], os.path.join("C:\\L", "Vivaldi", "User Data"))

    def test_macos(self):
        roots = self.roots("darwin")
        self.assertEqual(roots["vivaldi"], os.path.join("/home/u", "Library", "Application Support", "Vivaldi"))

    def test_linux(self):
        roots = self.roots("linux")
        self.assertEqual(roots["vivaldi"], os.path.join("/home/u", ".config", "vivaldi"))
        self.assertEqual(roots["vivaldi-snapshot"], os.path.join("/home/u", ".config", "vivaldi-snapshot"))
        self.assertEqual(roots["vivaldi-flatpak"], os.path.join("/home/u", ".var", "app", "com.vivaldi.Vivaldi", "config", "vivaldi"))


class TestVivaldiScan(BrowserLaunchBase):
    def vivaldi_root(self):
        root = os.path.join(self.tmp, "Vivaldi", "User Data")
        browser.CHROMIUM_ROOTS = [("vivaldi", root)]
        browser.ROAMING = browser.LOCAL = self.empty
        return root

    def test_discovered_roots_scan_profiles_without_changing_source_files(self):
        # All discovered roots stay inside the fixture, including non-Vivaldi
        # roots. Exercise discovery through run(), not a hand-written root list.
        for platform in ("win32", "darwin", "linux"):
            home = os.path.join(self.tmp, platform)
            with patch.object(browser.sys, "platform", platform), \
                    patch.object(browser, "LOCAL", home), \
                    patch.object(browser.os.path, "expanduser", return_value=home):
                roots = browser._chromium_roots()
            vivaldi = [(name, root) for name, root in roots if name.startswith("vivaldi")]
            for name, root in vivaldi:
                chromium_history_db(os.path.join(root, "Default", "History"),
                                    "https://{}/x".format(TEST_DOMAIN))
                chromium_cookie_db(os.path.join(root, "Profile 1", "Network", "Cookies"))
            before = {str(p): p.read_bytes() for p in pathlib.Path(home).rglob("*") if p.is_file()}
            browser.CHROMIUM_ROOTS = roots
            result = browser.run(self.ctx)
            self.assertEqual(len(result.hits), len(vivaldi) * 2)
            self.assertTrue(all(h.evidence == EV_CONTACTED for h in result.hits))
            self.assertEqual({h.profile for h in result.hits}, {"Default", "Profile 1"})
            after = {str(p): p.read_bytes() for p in pathlib.Path(home).rglob("*") if p.is_file()}
            self.assertEqual(before, after)

    def test_locked_vivaldi_is_unknown_not_clean(self):
        root = self.vivaldi_root()
        chromium_history_db(os.path.join(root, "Default", "History"))
        self.lock(lambda path: True)
        result = browser.run(self.ctx)
        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(any(not c.ran and "vivaldi" in c.name for c in result.checks))

    def test_one_locked_profile_preserves_gap(self):
        root = self.vivaldi_root()
        for profile in ("Default", "Profile 1"):
            chromium_history_db(os.path.join(root, profile, "History"))
        self.lock(lambda path: "Profile 1" in path)
        self.assertEqual(browser.run(self.ctx).status, PARTIAL)

    def test_research_reference_is_not_contact(self):
        root = self.vivaldi_root()
        chromium_history_db(os.path.join(root, "Default", "History"),
                            "https://research.invalid/?indicator=" + TEST_DOMAIN)
        result = browser.run(self.ctx)
        self.assertEqual(len(result.hits), 1)
        self.assertEqual(result.hits[0].evidence, EV_REFERENCED)

    def test_absent_vivaldi_is_not_reported_clean(self):
        self.vivaldi_root()
        result = browser.run(self.ctx)
        self.assertFalse(result.hits)
        self.assertEqual(result.status, UNKNOWN)

    def test_corrupt_vivaldi_history_is_a_gap(self):
        root = self.vivaldi_root()
        history = pathlib.Path(root) / "Default" / "History"
        history.parent.mkdir(parents=True)
        history.write_bytes(b"not a SQLite database")
        result = browser.run(self.ctx)
        self.assertFalse(result.hits)
        self.assertEqual(result.status, UNKNOWN)

    def test_history_hit_in_vivaldi_profile(self):
        ud = os.path.join(self.tmp, "Vivaldi", "User Data")
        chromium_history_db(os.path.join(ud, "Default", "History"),
                            "https://{}/x".format(TEST_DOMAIN))
        browser.CHROMIUM_ROOTS = [("vivaldi", ud)]
        browser.ROAMING = browser.LOCAL = self.empty
        result = browser.run(self.ctx)
        self.assertTrue(result.hits, "an indicator in Vivaldi history must be found")

    def test_locked_note_names_vivaldi(self):
        for path in (r"C:\Users\u\AppData\Local\Vivaldi\User Data\Default\History",
                     "/home/u/.config/vivaldi/Default/History"):
            note = browser._locked_note(path, PermissionError(13, "locked"))
            self.assertIn("Vivaldi", note)


if __name__ == "__main__":
    unittest.main()
