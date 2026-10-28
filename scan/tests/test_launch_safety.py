"""Launch blockers reproduced against reserved indicators and temporary files."""

import json
import os
import posixpath
import sqlite3
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path[:0] = [os.path.dirname(os.path.dirname(__file__)), os.path.dirname(__file__)]

from test_browser_launch import (BrowserLaunchBase, FirefoxArtifactBase,
                                 TEST_DOMAIN, chromium_cookie_db,
                                 chromium_history_db)
from adint_scan import localpaths
from adint_scan.modules import browser, hashscan, host
from adint_scan.result import ModuleResult


class TestBrowserLaunchSafety(BrowserLaunchBase):
    def setUp(self):
        super().setUp()
        self.ud = os.path.join(self.tmp, "User Data")
        self.prof = os.path.join(self.ud, "Default")
        self.blobs = os.path.join(self.prof, "Local Storage", "leveldb")
        os.makedirs(self.blobs)
        self.blob = os.path.join(self.blobs, "000003.log")

    def plant_blob(self, payload=b"ordinary saved content"):
        with open(self.blob, "wb") as fh:
            fh.write(payload)

    def assert_gap(self, result):
        self.assertNotEqual(result.status, "CLEAN")
        self.assertTrue(any(not c.ran for c in result.checks))

    def test_saved_url_values_are_references_in_both_encodings(self):
        for encoding in ("utf-8", "utf-16le"):
            with self.subTest(encoding=encoding):
                self.plant_blob(("saved article <a href='https://" + TEST_DOMAIN
                                 + "/report'>source</a>").encode(encoding))
                result = self.run_chromium(self.ud)
                self.assertTrue(result.hits)
                self.assertTrue(all(h.evidence == "referenced" for h in result.hits))

    def test_unreadable_only_blob_is_a_gap(self):
        self.plant_blob()
        real_open = browser.io.open
        def denied(path, *args, **kwargs):
            if path == self.blob:
                raise PermissionError(13, "locked", path)
            return real_open(path, *args, **kwargs)
        with patch.object(browser.io, "open", side_effect=denied):
            result = self.run_chromium(self.ud)
        self.assert_gap(result)
        self.assertEqual(result.checked, 0)
        self.assertEqual(result.skipped, 1)

    def test_readable_blob_does_not_hide_a_subtree_failure(self):
        self.plant_blob()
        real_walk = browser.walk_local
        def failing_walk(path, onerror=None):
            if path == self.blobs:
                onerror(PermissionError(13, "denied subtree", path))
            yield from real_walk(path, onerror=onerror)
        with patch.object(browser, "walk_local", side_effect=failing_walk):
            result = self.run_chromium(self.ud)
        self.assert_gap(result)
        self.assertEqual(result.checked, 1)

    def test_oversize_blob_is_a_gap_without_allocating_it(self):
        self.plant_blob()
        real_stat = browser.os.stat
        def oversized(path, *args, **kwargs):
            if path == self.blob:
                return SimpleNamespace(st_size=401 * 1024 * 1024, st_mtime=0)
            return real_stat(path, *args, **kwargs)
        with patch.object(browser.os, "stat", side_effect=oversized):
            self.assert_gap(self.run_chromium(self.ud))

    def test_history_username_is_not_the_contacted_host(self):
        chromium_history_db(os.path.join(self.prof, "History"),
                            "https://" + TEST_DOMAIN + ":password@example.org/page")
        result = self.run_chromium(self.ud)
        self.assertTrue(result.hits)
        self.assertTrue(all(h.evidence == "referenced" for h in result.hits))

    def test_url_parser_keeps_real_host_and_ipv6(self):
        self.assertEqual(browser._host_of("https://user:pass@" + TEST_DOMAIN + ":443/x"),
                         TEST_DOMAIN)
        self.assertEqual(browser._host_of("https://[2001:db8::1]:443/x"), "2001:db8::1")
        self.assertEqual(browser._host_of("https://[broken"), "")

    def test_unrecognized_history_schema_is_a_gap(self):
        with sqlite3.connect(os.path.join(self.prof, "History")) as con:
            con.execute("CREATE TABLE unsupported_urls (url TEXT)")
        con.close()
        self.assert_gap(self.run_chromium(self.ud))

    def test_cookie_schema_requires_host_column(self):
        with sqlite3.connect(os.path.join(self.prof, "Cookies")) as con:
            con.execute("CREATE TABLE cookies (name TEXT)")
            con.execute("INSERT INTO cookies VALUES ('sid')")
        con.close()
        self.assert_gap(self.run_chromium(self.ud))

    def test_malformed_network_state_does_not_skip_later_profiles(self):
        network = os.path.join(self.prof, "Network")
        os.makedirs(network)
        chromium_history_db(os.path.join(self.ud, "Profile 1", "History"),
                            "https://" + TEST_DOMAIN + "/")
        cases = [{"net": 42}, {"net": {"http_server_properties": []}},
                 {"net": {"http_server_properties": {"servers": 42}}},
                 {"net": {"http_server_properties": {"servers": [42]}}}]
        for value in cases:
            with self.subTest(value=value):
                with open(os.path.join(network, "Network Persistent State"),
                          "w", encoding="utf-8") as fh:
                    json.dump(value, fh)
                result = self.run_chromium(self.ud)
                self.assertTrue(any(not c.ran for c in result.checks))
                self.assertTrue(any(h.profile == "Profile 1" for h in result.hits))

    def test_rejected_browser_root_is_never_tested_for_existence(self):
        with patch.object(browser, "path_problem", return_value="remote root"), \
             patch.object(browser.os.path, "isdir", side_effect=AssertionError("unsafe stat")):
            self.assert_gap(self.run_chromium(self.ud))


class TestKnownPathLaunchSafety(BrowserLaunchBase):
    def test_unreadable_known_drop_is_unverified_not_likely_legitimate(self):
        path = os.path.join(self.tmp, "review.dll")
        with open(path, "wb") as fh:
            fh.write(b"synthetic")
        result = ModuleResult("host")
        with patch.dict(os.environ, {"SystemRoot": self.tmp}), \
             patch.object(host, "_KNOWN_DROPS", [(("review.dll",), "synthetic")]), \
             patch.object(host.io, "open", side_effect=PermissionError(13, "locked")):
            host._check_known_paths(result, self.ctx)
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(result.skipped, 1)
        self.assertFalse(any("does NOT match" in n or "most likely" in n for n in result.notes))

    def test_unknown_known_path_is_not_treated_as_absent(self):
        result = ModuleResult("host")
        with patch.dict(os.environ, {"SystemRoot": self.tmp}), \
             patch.object(host, "_KNOWN_DROPS", [(("review.dll",), "synthetic")]), \
             patch.object(host, "path_problem", return_value="permission denied"):
            host._check_known_paths(result, self.ctx)
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(result.checked, 0)


class TestSnapshotFailureVisibility(BrowserLaunchBase):
    def test_partial_copy_with_failed_cleanup_names_leftover_directory(self):
        ud = os.path.join(self.tmp, "User Data")
        source = os.path.join(ud, "Default", "Network", "Cookies")
        chromium_cookie_db(source)
        real_copy = browser.shutil.copy2
        copied = []
        def copy_then_fail(src, dst, *args, **kwargs):
            real_copy(src, dst, *args, **kwargs)
            copied.append(dst)
            raise PermissionError(13, "copy metadata denied")
        with patch.object(browser, "local_temp_dir", return_value=self.tmp), \
             patch.object(browser.shutil, "copy2", side_effect=copy_then_fail), \
             patch.object(browser.shutil, "rmtree", return_value=None):
            result = self.run_chromium(ud)
        self.assertEqual(len(copied), 1)
        self.assertTrue(os.path.exists(copied[0]))
        leftover = os.path.dirname(copied[0])
        self.assertTrue(any(not c.ran and leftover in c.reason for c in result.checks))
        self.assertTrue(any("cleanup failed" in n and leftover in n for n in result.notes))

    def test_sqlite_open_failure_with_failed_cleanup_names_leftover_directory(self):
        ud = os.path.join(self.tmp, "User Data")
        chromium_cookie_db(os.path.join(ud, "Default", "Network", "Cookies"))
        with patch.object(browser, "local_temp_dir", return_value=self.tmp), \
             patch.object(browser.sqlite3, "connect", side_effect=sqlite3.OperationalError("open denied")), \
             patch.object(browser.shutil, "rmtree", return_value=None):
            result = self.run_chromium(ud)
        leftovers = [os.path.join(self.tmp, name) for name in os.listdir(self.tmp)
                     if name.startswith("bscan_")]
        self.assertEqual(len(leftovers), 1)
        self.assertTrue(any(not c.ran and leftovers[0] in c.reason for c in result.checks))


class TestFirefoxBookmarkEvidence(FirefoxArtifactBase):
    def test_unvisited_bookmark_is_a_reference_but_recorded_visit_is_contact(self):
        path = os.path.join(self.prof, "places.sqlite")
        con = sqlite3.connect(path)
        try:
            con.execute("CREATE TABLE moz_places (url TEXT, title TEXT, "
                        "last_visit_date INTEGER, visit_count INTEGER)")
            con.execute("CREATE TABLE moz_bookmarks (fk INTEGER, title TEXT)")
            con.execute("INSERT INTO moz_places VALUES (?, 'unvisited-bookmark', NULL, 0)",
                        ("https://" + TEST_DOMAIN + "/saved",))
            con.execute("INSERT INTO moz_bookmarks VALUES (1, 'unvisited-bookmark')")
            con.execute("INSERT INTO moz_places VALUES (?, 'recorded-visit', 1741089600000000, 1)",
                        ("https://" + TEST_DOMAIN + "/visited",))
            con.commit()
        finally:
            con.close()
        result = browser.run(self.ctx)
        self.assertEqual(len(result.hits), 2)
        bookmark = next(h for h in result.hits if "unvisited-bookmark" in h.detail)
        visited = next(h for h in result.hits if "recorded-visit" in h.detail)
        self.assertEqual(bookmark.evidence, "referenced")
        self.assertEqual(visited.evidence, "contacted")


class TestLocalPathGuard(BrowserLaunchBase):
    def test_remote_temp_candidate_is_not_probed(self):
        checked = []
        remote = "remote-temp-sentinel"
        def guard(path):
            checked.append(path)
            return "remote" if path == remote else ""
        with patch.dict(os.environ, {"TMPDIR": remote, "TEMP": self.tmp}), \
             patch.object(localpaths, "path_problem", side_effect=guard), \
             patch.object(browser.tempfile, "gettempdir", side_effect=AssertionError("temp write probe")):
            self.assertEqual(localpaths.local_temp_dir(), self.tmp)
        self.assertEqual(checked[:2], [remote, self.tmp])

    def test_unc_is_rejected_without_any_filesystem_query(self):
        path = chr(92) * 2 + "synthetic.invalid" + chr(92) + "share"
        with patch.object(localpaths.sys, "platform", "win32"), \
             patch.object(localpaths.os.path, "isabs", return_value=True), \
             patch.object(localpaths.os, "lstat", side_effect=AssertionError("unsafe query")):
            self.assertTrue(localpaths.path_problem(path))

    def test_reparse_component_is_not_followed(self):
        # Canonicalize only our already-created test directory so the mock
        # matches macOS's validated /var -> /private/var alias expansion.
        link = os.path.join(os.path.realpath(self.tmp), "junction")
        child = os.path.join(link, "payload.dll")
        real_lstat = localpaths.os.lstat
        touched = []
        def lstat(path):
            touched.append(path)
            if path == link:
                return SimpleNamespace(st_mode=0o040777, st_file_attributes=0x400)
            if path == child:
                raise AssertionError("followed reparse point")
            return real_lstat(path)
        with patch.object(localpaths.os, "lstat", side_effect=lstat):
            self.assertIn("reparse", localpaths.path_problem(child))
        self.assertNotIn(child, touched)

    def test_hash_root_is_guarded_before_walk(self):
        from adint_scan.iocs import Indicator
        self.ctx.iocs.indicators.append(Indicator("a" * 64, "sample", "primary", "sha256"))
        with patch.object(hashscan, "_roots", return_value=[self.tmp]), \
             patch.object(hashscan, "path_problem", return_value="remote root") as guard, \
             patch.object(hashscan, "walk_local", side_effect=AssertionError("unsafe walk")):
            result = hashscan.run(self.ctx)
        self.assertTrue(any(not c.ran for c in result.checks))
        guard.assert_called_with(self.tmp)


class TestDarwinSystemAliases(unittest.TestCase):
    def guard_fixture(self, path, links, owners=None, platform="darwin", temp=None):
        queried, readlinks = [], []
        owners = owners or {}
        def lstat(value):
            queried.append(value)
            return SimpleNamespace(
                st_mode=(stat.S_IFLNK if value in links else stat.S_IFDIR) | 0o755,
                st_uid=owners.get(value, 0))
        def readlink(value):
            readlinks.append(value)
            return links[value]
        fake_path = SimpleNamespace(isabs=posixpath.isabs,
                                    splitdrive=posixpath.splitdrive,
                                    join=posixpath.join,
                                    isdir=lambda value: value == temp)
        fake_os = SimpleNamespace(fspath=os.fspath, path=fake_path, sep="/",
                                  lstat=lstat, readlink=readlink,
                                  environ={"TMPDIR": temp} if temp else {})
        with patch.object(localpaths, "os", fake_os), \
             patch.object(localpaths, "sys", SimpleNamespace(platform=platform)):
            result = (localpaths.local_temp_dir() if temp
                      else localpaths.path_problem(path))
        return result, queried, readlinks

    def test_exact_root_owned_aliases_validate_their_target_components(self):
        for alias in ("/var", "/tmp", "/etc"):
            target = "/private" + alias
            for spelling in (target, target.lstrip("/")):
                with self.subTest(alias=alias, target=spelling):
                    problem, queried, links = self.guard_fixture(
                        alias + "/folder/file", {alias: spelling})
                    self.assertEqual(problem, "")
                    self.assertEqual(links, [alias])
                    self.assertIn("/private", queried)
                    self.assertIn(target + "/folder/file", queried)
                    self.assertNotIn(alias + "/folder", queried)

    def test_untrusted_owner_and_unexpected_targets_are_rejected(self):
        for target, owner in (("/private/var", 501), ("/Users/person", 0),
                              ("//server/share", 0), ("private/../var", 0)):
            with self.subTest(target=target, owner=owner):
                problem, queried, _links = self.guard_fixture(
                    "/var/folders", {"/var": target}, {"/var": owner})
                self.assertIn("not followed", problem)
                self.assertEqual(queried, ["/var"])

    def test_arbitrary_and_nested_symlinks_remain_rejected(self):
        problem, queried, links = self.guard_fixture(
            "/custom/file", {"/custom": "/private/var"})
        self.assertIn("not followed", problem)
        self.assertEqual(links, [])
        problem, queried, links = self.guard_fixture(
            "/var/folders/redirect/file",
            {"/var": "private/var", "/private/var/folders/redirect": "/elsewhere"})
        self.assertIn("not followed", problem)
        self.assertNotIn("/private/var/folders/redirect/file", queried)
        self.assertEqual(links, ["/var"])

    def test_target_ancestor_redirection_is_rejected(self):
        problem, queried, _links = self.guard_fixture(
            "/var/folders", {"/var": "private/var", "/private": "/elsewhere"})
        self.assertIn("not followed", problem)
        self.assertEqual(queried, ["/var", "/private"])

    def test_alias_exception_is_not_enabled_on_linux(self):
        problem, queried, links = self.guard_fixture(
            "/var/folders", {"/var": "private/var"}, platform="linux")
        self.assertIn("not followed", problem)
        self.assertEqual(links, [])

    def test_standard_darwin_temp_alias_is_usable_after_validation(self):
        temp = "/var/folders/synthetic/T"
        result, queried, links = self.guard_fixture(
            temp, {"/var": "private/var"}, temp=temp)
        self.assertEqual(result, temp)
        self.assertIn("/private/var/folders/synthetic/T", queried)
        self.assertEqual(links, ["/var"])
