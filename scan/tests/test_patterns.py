"""Hermetic patterns tests: harmless bytes, temporary trees, no live artifacts.

Real-engine positives exercise rule mechanics on assembled test byte fragments.
They do not validate detection against authentic spyware or its variants.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan.modules import host, patternscan as patterns
from adint_scan.candiru_rules import (CANDIRU_RULE_METADATA, CANDIRU_RULE_SOURCES,
                                     CANDIRU_ENGINE_VERSION)
from adint_scan.result import CLEAN, HITS, PARTIAL, UNKNOWN, ModuleResult


def synthetic_malpedia_fixture():
    """Artificial public-pattern fragments, not an authentic malware sample."""
    sequences = re.findall(r"\$sequence_\d+ = \{ ([^}]+) \}", CANDIRU_RULE_SOURCES[1])
    data = b"Harmless synthetic rule-mechanics fixture; never execute.\n"
    for sequence in sequences[:7]:
        data += bytes.fromhex(sequence.replace("?", "0")) + b"\x90" * 32
    return data


def synthetic_mstic_fixture():
    """Data-only DLL header and strings, zero entry point, no code sections."""
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 0, 0, 0, 0, 240, 0x2022)
    struct.pack_into("<H", data, 0x98, 0x20b)
    data += (b"Harmless synthetic headers, no executable sections.\x00"
             b"NtQueryInformationThread\x00StackWalk64\x00ConvertSidToStringSidW\x00SMNew.dll\x00")
    return bytes(data)


class PatternTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="candiru_patterns_test_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.messages = []
        self.ctx = SimpleNamespace(pattern_paths=(str(self.root),),
                                   emit=self.messages.append, partial=None)
        self.scanner = Mock()
        self.scanner.scan.return_value = SimpleNamespace(matching_rules=[])

    def file(self, name="extensionless", data=b"harmless test bytes"):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def run_mock(self):
        with patch.object(patterns, "_pattern_engine", return_value=self.scanner):
            return patterns.run(self.ctx)

    def counted_scandir(self, mode, total=1000, name="extensionless"):
        """A wide lazy iterator that records requests and classification work."""
        class Entries:
            requested = 0
            closed = False
            classified = []

            def __enter__(entries):
                return entries

            def __exit__(entries, *_args):
                entries.closed = True

            def __iter__(entries):
                return entries

            def __next__(entries):
                entries.requested += 1
                if entries.requested > total:
                    raise StopIteration
                entry = SimpleNamespace(name=name, path=str(self.root / name),
                                        stat=Mock(return_value=SimpleNamespace(st_mode=mode,
                                                  st_file_attributes=0)))
                entries.classified.append(entry.stat)
                return entry

        return Entries()

    def test_extensionless_miss_and_partial_recovery(self):
        self.file()
        result = self.run_mock()
        self.assertEqual(result.status, CLEAN)
        self.assertEqual(result.checked, 1)
        self.assertIs(self.ctx.partial, result)
        self.scanner.scan.assert_called_once_with(b"harmless test bytes")

    def test_file_path_and_attribution(self):
        target = self.file(data=b"harmless mock match")
        self.ctx.pattern_paths = (str(target),)
        self.scanner.scan.return_value.matching_rules = [
            SimpleNamespace(identifier=name) for name in CANDIRU_RULE_METADATA]
        result = self.run_mock()
        self.assertEqual(result.status, HITS)
        self.assertEqual(len(result.hits), 2)
        for hit, metadata in zip(result.hits, CANDIRU_RULE_METADATA.values()):
            self.assertEqual(hit.evidence, "file-pattern")
            self.assertEqual(hit.tier, "candiru-pattern")
            self.assertEqual(hit.confidence, "research-rule")
            self.assertEqual(hit.source, metadata["source"])
            self.assertIn(metadata["author"], hit.detail)
            self.assertIn(metadata["license"], hit.detail)
            self.assertIn("not an exact sample", hit.detail)
            self.assertIn("confirmed infection", hit.detail)
            self.assertTrue(any(metadata["author"] in msg for msg in self.messages))

    def test_missing_dependency_is_unknown(self):
        with patch.object(patterns._pattern_importlib, "import_module",
                          side_effect=ModuleNotFoundError("no yara_x")):
            result = patterns.run(self.ctx)
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("optional pinned yara-x", " ".join(result.notes))

    def test_old_python_is_unknown_without_import(self):
        with patch.object(patterns._pattern_sys, "version_info", (3, 8)), \
                patch.object(patterns._pattern_importlib, "import_module") as imported:
            result = patterns.run(self.ctx)
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("Python 3.9", " ".join(result.notes))
        imported.assert_not_called()

    @unittest.skipIf(sys.version_info < (3, 9), "optional engine requires Python 3.9+")
    def test_engine_uses_trusted_sources_disabled_includes_timeout(self):
        engine = Mock()
        metadata = SimpleNamespace(version=lambda name: CANDIRU_ENGINE_VERSION)
        with patch.object(patterns._pattern_importlib, "import_module",
                          side_effect=[engine, metadata]):
            scanner = patterns._pattern_engine()
        engine.Compiler.return_value.enable_includes.assert_called_once_with(False)
        self.assertEqual(engine.Compiler.return_value.add_source.call_count, 2)
        self.assertEqual([c.args[0] for c in engine.Compiler.return_value.add_source.call_args_list],
                         list(CANDIRU_RULE_SOURCES))
        scanner.set_timeout.assert_called_once_with(5)

    @unittest.skipIf(sys.version_info < (3, 9), "optional engine requires Python 3.9+")
    def test_wrong_engine_version_is_unknown(self):
        with patch.object(patterns._pattern_importlib, "import_module", side_effect=[
                Mock(), SimpleNamespace(version=lambda name: "0.0.0")]):
            result = patterns.run(self.ctx)
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("unsupported yara-x version", " ".join(result.notes))

    @unittest.skipIf(sys.version_info < (3, 9), "optional engine requires Python 3.9+")
    def test_compile_failure_is_unknown(self):
        engine = Mock()
        engine.Compiler.return_value.add_source.side_effect = ValueError("compile failed")
        with patch.object(patterns._pattern_importlib, "import_module", side_effect=[
                engine, SimpleNamespace(version=lambda name: CANDIRU_ENGINE_VERSION)]):
            result = patterns.run(self.ctx)
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("compile failed", " ".join(result.notes))

    def test_scan_error_or_timeout_is_gap(self):
        self.file()
        for error in (RuntimeError("scan failed"), TimeoutError("5 seconds")):
            with self.subTest(error=error):
                self.scanner.scan.side_effect = error
                result = self.run_mock()
                self.assertEqual(result.status, UNKNOWN)
                self.assertEqual(result.checked, 0)
                self.assertEqual(result.skipped, 1)
                self.assertIn(type(error).__name__, " ".join(result.notes))

    def test_unknown_rule_cannot_be_reported_as_clean_or_trusted(self):
        self.file()
        self.scanner.scan.return_value.matching_rules = [SimpleNamespace(identifier="untrusted")]
        result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertFalse(result.hits)
        self.assertIn("unknown rule identifier", " ".join(result.notes))

    def test_read_error_after_success_is_partial(self):
        self.file("good")
        self.file("bad")
        original = patterns._pattern_read
        with patch.object(patterns, "_pattern_read", side_effect=lambda path:
                          original(path) if Path(path).name == "good" else
                          (_ for _ in ()).throw(PermissionError("locked"))):
            result = self.run_mock()
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.skipped, 1)

    def test_oversized_is_not_opened(self):
        self.file(data=b"X" * (patterns._PATTERN_MAX_BYTES + 1))
        with patch.object(patterns._pattern_os, "open") as opened:
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("1 MiB", " ".join(result.notes))
        opened.assert_not_called()

    def test_preflight_rejection_is_distinct_from_unknown_read_failure(self):
        target = self.file(data=b"X" * (patterns._PATTERN_MAX_BYTES + 1))
        with self.assertRaises(patterns._PatternNoRead):
            patterns._pattern_read(str(target))

    def test_stream_read_error_cannot_be_marked_as_no_read(self):
        target = self.file()
        real_open = patterns._pattern_io.open
        class FailingRead:
            def __init__(stream, *args, **kwargs):
                stream.inner = real_open(*args, **kwargs)

            def __enter__(stream):
                return stream

            def __exit__(stream, *_args):
                stream.inner.close()

            def fileno(stream):
                return stream.inner.fileno()

            def read(stream, amount):
                raise OSError("read failed after it began")

        with patch.object(patterns._pattern_io, "open", side_effect=FailingRead):
            with self.assertRaises(OSError) as caught:
                patterns._pattern_read(str(target))
        self.assertNotIsInstance(caught.exception, patterns._PatternNoRead)

    def test_exact_cap_read_is_bounded(self):
        target = self.file(data=b"X" * patterns._PATTERN_MAX_BYTES)
        self.assertEqual(len(patterns._pattern_read(str(target))), patterns._PATTERN_MAX_BYTES)

    @unittest.skipUnless(sys.platform == "win32", "Windows file identity check")
    def test_windows_path_and_handle_identity_use_common_fields(self):
        target = self.file(data=b"harmless identity fixture")
        before = os.lstat(target)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(target, flags)
        try:
            opened = os.fstat(fd)
            second_path = os.lstat(target)
        finally:
            os.close(fd)
        self.assertEqual(patterns._pattern_shared_identity(before),
                         patterns._pattern_shared_identity(opened))
        self.assertEqual(patterns._pattern_identity(before),
                         patterns._pattern_identity(second_path))

    def test_missing_and_empty_requested_roots_are_unknown(self):
        for path in (self.root / "absent", self.root):
            with self.subTest(path=path):
                self.ctx.pattern_paths = (str(path),)
                result = self.run_mock()
                self.assertEqual(result.status, UNKNOWN)
                self.assertEqual(result.checked, 0)

    def test_no_roots_is_unknown(self):
        self.ctx.pattern_paths = ()
        with patch.object(patterns, "_pattern_roots", return_value=[]):
            self.assertEqual(self.run_mock().status, UNKNOWN)

    def test_default_roots_use_hash_roots(self):
        self.ctx.pattern_paths = ()
        self.file()
        with patch.object(patterns, "_pattern_roots", return_value=[str(self.root)]) as roots:
            result = self.run_mock()
        roots.assert_called_once_with()
        self.assertEqual(result.checked, 1)

    def test_default_scan_also_checks_registered_local_file_outside_roots(self):
        ordinary = self.file("ordinary")
        registered = self.file("elsewhere/registered.dll", b"registered harmless fixture")
        self.ctx.pattern_paths = ()
        self.ctx.pattern_candidate_paths = (str(registered),)
        self.scanner.scan.side_effect = lambda data: SimpleNamespace(matching_rules=(
            [SimpleNamespace(identifier="win_devilstongue_auto")]
            if data == registered.read_bytes() else []))
        with patch.object(patterns, "_pattern_roots", return_value=[str(ordinary)]):
            result = self.run_mock()
        self.assertEqual(result.checked, 2)
        self.assertEqual([hit.location for hit in result.hits], [str(registered)])
        self.assertEqual(result.status, HITS)
        self.assertEqual(self.scanner.scan.call_args_list[0].args[0],
                         registered.read_bytes())

    def test_explicit_path_does_not_expand_to_registered_files(self):
        requested = self.file("requested")
        registered = self.file("registered")
        self.ctx.pattern_paths = (str(requested),)
        self.ctx.pattern_candidate_paths = (str(registered),)
        result = self.run_mock()
        self.assertEqual(result.checked, 1)
        self.assertEqual(self.scanner.scan.call_count, 1)

    def test_registered_directory_is_not_recursively_scanned(self):
        inside = self.file("elsewhere/inside")
        self.ctx.pattern_paths = ()
        self.ctx.pattern_candidate_paths = (str(inside.parent),)
        with patch.object(patterns, "_pattern_roots", return_value=[]):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(result.checked, 0)
        self.scanner.scan.assert_not_called()

    def test_registered_candidate_cap_is_coverage_gap(self):
        registered = self.file("registered")
        self.ctx.pattern_paths = ()
        self.ctx.pattern_candidate_paths = (str(registered),)
        self.ctx.pattern_candidate_omitted = 1
        with patch.object(patterns, "_pattern_roots", return_value=[]):
            result = self.run_mock()
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.status, PARTIAL)
        self.assertTrue(any(c.name == "com-pattern-candidates" for c in result.checks))

    def test_host_passes_only_local_writable_com_targets(self):
        local = self.file("registered.dll")
        second = self.file("registered2.dll")
        remote = r"\\attacker.invalid\share\bad.dll"
        entries = [{"clsid": "{A}", "kind": "InprocServer32", "raw": str(local),
                    "view": "native"},
                   {"clsid": "{C}", "kind": "InprocServer32", "raw": str(second),
                    "view": "native"},
                   {"clsid": "{B}", "kind": "InprocServer32", "raw": remote,
                    "view": "native"}]
        ctx = SimpleNamespace(patterns=True, pattern_paths=(), emit=lambda _: None,
                              iocs=SimpleNamespace(search=lambda _: []),
                              pattern_candidate_paths=(), pattern_candidate_omitted=0)
        original_exists = os.path.exists

        def safe_exists(path):
            if path == remote:
                raise AssertionError("remote path was handed to the filesystem")
            return original_exists(path)

        with patch.object(host, "_enum_com_registrations", return_value=(entries, [])), \
                patch.object(host, "_network_drive_letters", return_value=(set(), True)), \
                patch.object(host, "_user_writable_dirs", return_value=[str(self.root).lower()]), \
                patch.object(host, "_COM_PATTERN_CANDIDATE_CAP", 1), \
                patch.object(host, "_signature_status", return_value=({}, "")), \
                patch.object(os.path, "exists", side_effect=safe_exists):
            host._check_com(ModuleResult("host"), ctx)
        self.assertEqual(ctx.pattern_candidate_paths, (str(local),))
        self.assertEqual(ctx.pattern_candidate_omitted, 1)

    def test_overlapping_roots_do_not_duplicate_files(self):
        target = self.file("nested/extensionless")
        self.ctx.pattern_paths = (str(target), str(target.parent), str(self.root), str(self.root))
        result = self.run_mock()
        self.assertEqual(result.checked, 1)
        self.assertEqual(self.scanner.scan.call_count, 1)
        self.assertEqual(result.status, CLEAN)

    def test_explicit_child_under_pruned_parent_is_still_scanned(self):
        ordinary = self.file("ordinary")
        wanted = self.file("cache/wanted", synthetic_malpedia_fixture())
        self.ctx.pattern_paths = (str(self.root), str(wanted))
        self.scanner.scan.side_effect = lambda data: SimpleNamespace(matching_rules=(
            [SimpleNamespace(identifier="win_devilstongue_auto")]
            if data == wanted.read_bytes() else []))
        result = self.run_mock()
        self.assertEqual(result.checked, 2)
        self.assertEqual([hit.location for hit in result.hits], [str(wanted)])
        self.assertEqual(result.status, HITS)

    def test_relative_and_traversal_roots_refused(self):
        for root in ("relative", str(self.root) + os.sep + ".." + os.sep + self.root.name):
            with self.subTest(root=root):
                self.ctx.pattern_paths = (root,)
                result = self.run_mock()
                self.assertEqual(result.status, UNKNOWN)
        self.scanner.scan.assert_not_called()

    def test_remote_roots_refused_without_read(self):
        self.ctx.pattern_paths = (r"\\server.invalid\share\file",)
        with patch.object(patterns, "_pattern_read") as reader:
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        reader.assert_not_called()

    def test_symlink_and_reparse_are_refused(self):
        target = self.file()
        actual = os.lstat(target)
        fake = SimpleNamespace(**{name: getattr(actual, name) for name in
                               ("st_dev", "st_ino", "st_size", "st_mtime", "st_ctime")},
                               st_mode=actual.st_mode, st_file_attributes=0x400)
        original = patterns._pattern_os.lstat
        with patch.object(patterns._pattern_os, "lstat", side_effect=lambda path:
                          fake if os.fspath(path) == str(target) else original(path)):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(result.skipped, 1)
        self.scanner.scan.assert_not_called()

    def test_real_symlink_if_platform_allows(self):
        target = self.file()
        link = self.root / "link"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("creating symlinks requires privileges on this Windows host")
        self.ctx.pattern_paths = (str(link),)
        result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.scanner.scan.assert_not_called()

    def test_cloud_recall_file_refused_before_open(self):
        target = self.file()
        actual = os.lstat(target)
        for attribute in (0x1000, 0x40000, 0x400000):
            fake = SimpleNamespace(st_mode=actual.st_mode, st_file_attributes=attribute)
            original = patterns._pattern_os.lstat
            self.ctx.pattern_paths = (str(target),)
            with self.subTest(attribute=attribute), \
                    patch.object(patterns._pattern_os, "lstat", side_effect=lambda path:
                                 fake if os.fspath(path) == str(target) else original(path)), \
                    patch.object(patterns._pattern_os, "open") as opened:
                result = self.run_mock()
            self.assertEqual(result.status, UNKNOWN)
            opened.assert_not_called()

    def test_special_file_refused(self):
        target = self.file()
        with patch.object(patterns._pattern_stat, "S_ISREG", return_value=False), \
                patch.object(patterns._pattern_stat, "S_ISDIR", return_value=False), \
                patch.object(patterns._pattern_os, "open") as opened:
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        opened.assert_not_called()

    def test_changed_file_before_read_is_gap(self):
        self.file()
        original = patterns._pattern_os.fstat
        def changed(fd):
            info = original(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev,
                                   st_ino=info.st_ino, st_size=info.st_size + 1,
                                   st_mtime=info.st_mtime, st_ctime=info.st_ctime,
                                   st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)
        with patch.object(patterns._pattern_os, "fstat", side_effect=changed):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("changed before", " ".join(result.notes))

    def test_changed_file_after_read_is_gap(self):
        self.file()
        original = patterns._pattern_os.fstat
        calls = []
        def changed(fd):
            info = original(fd)
            calls.append(fd)
            if len(calls) == 1:
                return info
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev,
                                   st_ino=info.st_ino, st_size=info.st_size,
                                   st_mtime=info.st_mtime, st_ctime=info.st_ctime,
                                   st_mtime_ns=info.st_mtime_ns + 1,
                                   st_ctime_ns=info.st_ctime_ns)
        with patch.object(patterns._pattern_os, "fstat", side_effect=changed):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("grew or changed", " ".join(result.notes))
        self.scanner.scan.assert_not_called()

    def test_unreadable_subtree_is_gap(self):
        self.file()
        denied = self.root / "denied"
        denied.mkdir()
        original = patterns._pattern_os.scandir
        def unreadable_scandir(root):
            if os.fspath(root) == str(denied):
                raise PermissionError(13, "subtree denied", str(denied))
            return original(root)
        with patch.object(patterns._pattern_os, "scandir", side_effect=unreadable_scandir):
            result = self.run_mock()
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.skipped, 1)

    def test_grown_file_read_is_bounded_and_discarded(self):
        target = self.file()
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        stream.read.return_value = b"X" * (patterns._PATTERN_MAX_BYTES + 1)
        with open(target, "rb") as real:
            stream.fileno.return_value = real.fileno()
            original_open = patterns._pattern_os.open
            descriptors = []
            def tracked_open(*args):
                fd = original_open(*args)
                descriptors.append(fd)
                return fd
            try:
                with patch.object(patterns._pattern_io, "open", return_value=stream), \
                        patch.object(patterns._pattern_os, "open", side_effect=tracked_open):
                    result = self.run_mock()
            finally:
                for fd in descriptors:
                    os.close(fd)
        stream.read.assert_called_once_with(patterns._PATTERN_MAX_BYTES + 1)
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("grew or changed", " ".join(result.notes))

    def test_pruned_directories_are_disclosed(self):
        self.file("safe")
        self.file("node_modules/ignored")
        result = self.run_mock()
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.submetrics["directories_pruned"], 1)
        self.assertIn("node_modules", " ".join(result.notes))
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.skipped, 1)

    def test_unscanned_hit_under_pruned_directory_cannot_report_clean(self):
        self.file("safe")
        self.file("cache/unscanned-hit", synthetic_malpedia_fixture())
        result = self.run_mock()
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.hits, [])
        self.assertEqual(result.status, PARTIAL)
        self.assertIn("cache", " ".join(result.notes))

    def test_file_cap_partial_and_stops(self):
        self.file("a")
        self.file("b")
        with patch.object(patterns, "_PATTERN_MAX_FILES", 1):
            result = self.run_mock()
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.checked, 1)
        self.assertIn("cap reached", " ".join(result.notes))

    def test_wide_folder_file_cap_stops_before_next_entry_or_stat(self):
        self.file()
        entries = self.counted_scandir(patterns._pattern_stat.S_IFREG)
        with patch.object(patterns._pattern_os, "scandir", return_value=entries), \
                patch.object(patterns, "_PATTERN_MAX_FILES", 1):
            result = self.run_mock()
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.checked, 1)
        self.assertEqual(entries.requested, 1)
        self.assertEqual(sum(stat.call_count for stat in entries.classified), 1)
        self.assertTrue(entries.closed)

    def test_wide_refused_folder_entry_cap_bounds_metadata_and_gap_count(self):
        entries = self.counted_scandir(patterns._pattern_stat.S_IFLNK)
        with patch.object(patterns._pattern_os, "scandir", return_value=entries), \
                patch.object(patterns, "_PATTERN_MAX_ENTRIES", 3), \
                patch.object(patterns, "_pattern_problem", wraps=patterns._pattern_problem) as cloud:
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(result.skipped, 3)
        self.assertEqual(entries.requested, 3)
        self.assertEqual(sum(stat.call_count for stat in entries.classified), 3)
        self.assertEqual(result.submetrics["filesystem_entries_considered"], 3)
        self.assertEqual(cloud.call_count, 2)  # requested root and traversal root only
        self.assertTrue(entries.closed)
        self.scanner.scan.assert_not_called()

    def test_wide_pruned_folder_entries_are_charged_before_pruning(self):
        entries = self.counted_scandir(patterns._pattern_stat.S_IFDIR, name="cache")
        with patch.object(patterns._pattern_os, "scandir", return_value=entries) as opened, \
                patch.object(patterns, "_PATTERN_MAX_ENTRIES", 4):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(entries.requested, 4)
        self.assertEqual(result.submetrics["directories_pruned"], 4)
        opened.assert_called_once_with(str(self.root))
        self.assertTrue(entries.closed)

    def test_wide_directories_do_not_accumulate_pending_paths(self):
        entries = self.counted_scandir(patterns._pattern_stat.S_IFDIR, name="child")
        with patch.object(patterns._pattern_os, "scandir", return_value=entries) as opened, \
                patch.object(patterns, "_PATTERN_MAX_DIRS", 1), \
                patch.object(patterns, "_pattern_problem", wraps=patterns._pattern_problem) as cloud:
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(entries.requested, 1)
        self.assertEqual(sum(stat.call_count for stat in entries.classified), 1)
        self.assertEqual(cloud.call_count, 2)
        opened.assert_called_once_with(str(self.root))
        self.assertTrue(entries.closed)

    def test_depth_cap_closes_all_streaming_iterators(self):
        self.file("a/b/c/target")
        real = patterns._pattern_os.scandir
        opened = []
        class Tracked:
            def __init__(tracked, path):
                tracked.inner = real(path)
                tracked.closed = False
                opened.append(tracked)

            def __enter__(tracked):
                return tracked.inner

            def __exit__(tracked, *_args):
                tracked.inner.close()
                tracked.closed = True

        with patch.object(patterns._pattern_os, "scandir", side_effect=Tracked), \
                patch.object(patterns, "_PATTERN_MAX_DEPTH", 3):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(len(opened), 3)
        self.assertTrue(all(entries.closed for entries in opened))
        self.assertIn("depth cap reached", " ".join(result.notes))

    def test_failed_reads_still_consume_total_byte_budget(self):
        self.file("a")
        self.file("b")
        with patch.object(patterns, "_pattern_read", side_effect=OSError("file changed")) as reader, \
                patch.object(patterns, "_PATTERN_MAX_TOTAL_BYTES", patterns._PATTERN_MAX_BYTES + 1):
            result = self.run_mock()
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(reader.call_count, 1)
        self.assertIn("byte cap reached", " ".join(result.notes))

    def test_directory_cap_partial_and_stops(self):
        first = self.file("a")
        self.file("nested/b")
        # Complete one explicit file root before walking the directory. Native
        # scandir order is unspecified; encountering nested first must not turn
        # this test into an assumption that root files are enumerated first.
        self.ctx.pattern_paths = (str(first), str(self.root))
        with patch.object(patterns, "_PATTERN_MAX_DIRS", 1):
            result = self.run_mock()
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.submetrics["directories_pattern_visited"], 1)
        self.assertTrue(any(check.name == "pattern-limits" and
                            "directory cap reached" in check.reason
                            for check in result.checks))

    def test_total_byte_cap_partial(self):
        self.file("a", b"A" * patterns._PATTERN_MAX_BYTES)
        self.file("b", b"B")
        with patch.object(patterns, "_PATTERN_MAX_TOTAL_BYTES", patterns._PATTERN_MAX_BYTES + 1):
            result = self.run_mock()
        self.assertEqual(result.status, PARTIAL)
        self.assertEqual(result.checked, 1)

    def test_error_notes_are_bounded(self):
        for number in range(30):
            self.file(str(number))
        with patch.object(patterns, "_pattern_read", side_effect=PermissionError("locked")):
            result = self.run_mock()
        self.assertEqual(result.skipped, 30)
        self.assertEqual(sum("Pattern file skipped" in note for note in result.notes), 10)

    def test_embedded_sources_are_verbatim_and_hashed(self):
        base = Path(__file__).resolve().parents[2] / "third_party" / "candiru"
        provenance = json.loads((base / "PROVENANCE.json").read_text(encoding="utf-8"))
        for source, metadata in zip(CANDIRU_RULE_SOURCES, CANDIRU_RULE_METADATA.values()):
            raw = (base / metadata["filename"]).read_bytes()
            self.assertEqual(source.encode("utf-8"), raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             provenance["files_sha256"][metadata["filename"]])
            self.assertIn(metadata["author"], source)
        self.assertIn("malpedia_license = \"CC BY-SA 4.0\"", CANDIRU_RULE_SOURCES[1])


@unittest.skipUnless(importlib.util.find_spec("yara_x"), "optional yara-x is absent")
class RealEnginePatternTests(unittest.TestCase):
    setUp = PatternTests.setUp
    file = PatternTests.file

    def test_real_engine_misses_harmless_file(self):
        self.file(data=b"Synthetic harmless text. No malware or executable content.")
        result = patterns.run(self.ctx)
        self.assertEqual(result.status, CLEAN, result.notes)
        self.assertEqual(result.checked, 1)

    def test_real_malpedia_pattern_fragments_extensionless(self):
        # Deliberately artificial concatenation of seven public hex patterns.
        self.file(data=synthetic_malpedia_fixture())
        result = patterns.run(self.ctx)
        self.assertEqual([hit.indicator for hit in result.hits], ["yara:win_devilstongue_auto"])

    def test_real_mstic_strings_in_synthetic_pe_header(self):
        # Minimal artificial DLL headers + four strings; no executable section.
        self.file("synthetic.dll", synthetic_mstic_fixture())
        result = patterns.run(self.ctx)
        self.assertEqual([hit.indicator for hit in result.hits], ["yara:MAL_DevilsTongue_HijackDll"], result.notes)

    def test_real_explicit_pattern_blob_survives_parent_pruning(self):
        self.file("ordinary", b"harmless text")
        wanted = self.file("cache/wanted", synthetic_malpedia_fixture())
        self.ctx.pattern_paths = (str(self.root), str(wanted))
        result = patterns.run(self.ctx)
        self.assertEqual(result.checked, 2)
        self.assertEqual([hit.location for hit in result.hits], [str(wanted)])
        self.assertEqual([hit.indicator for hit in result.hits], ["yara:win_devilstongue_auto"])

    def test_real_registered_candidate_outside_general_roots(self):
        wanted = self.file("elsewhere/registered.dll", synthetic_malpedia_fixture())
        self.ctx.pattern_paths = ()
        self.ctx.pattern_candidate_paths = (str(wanted),)
        with patch.object(patterns, "_pattern_roots", return_value=[]):
            result = patterns.run(self.ctx)
        self.assertEqual([hit.indicator for hit in result.hits],
                         ["yara:win_devilstongue_auto"])
        self.assertEqual([hit.location for hit in result.hits], [str(wanted)])

    def test_300_oversized_files_do_not_exhaust_data_read_budget(self):
        # Sparse temporary test files: metadata says >1 MiB, no contents read.
        for number in range(300):
            with (self.root / ("oversized_{:03d}".format(number))).open("wb") as stream:
                stream.truncate(patterns._PATTERN_MAX_BYTES + 1)
        wanted = self.file("wanted", synthetic_malpedia_fixture())
        result = patterns.run(self.ctx)
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.skipped, 300)
        self.assertEqual(result.submetrics["filesystem_entries_considered"], 301)
        self.assertEqual([hit.location for hit in result.hits], [str(wanted)])
        self.assertEqual([hit.indicator for hit in result.hits], ["yara:win_devilstongue_auto"])
        self.assertFalse(any(check.name == "pattern-limits" for check in result.checks))


if __name__ == "__main__":
    unittest.main()
