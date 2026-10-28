"""A locked LevelDB LOCK sentinel is NOT a gap.

Regression test for the zero-breach-plus change in scan_blobs. While a Chromium
browser is running it holds an exclusive OS lock on the zero-byte ``LOCK``
sentinel inside each LevelDB store (Local Storage / Session Storage /
IndexedDB). The blob scanner used to try to read every file under those
folders, fail on LOCK with PermissionError (errno 13 - the real Windows
sharing violation), and record that as a GAP. A fully searched profile then
looked incompletely scanned, which is exactly the false-uncertainty noise the
project tries to avoid.

The fix skips any file named ``LOCK`` outright: a lock sentinel is always empty
and can never match an indicator, so not reading it loses no detection. These
tests pin both halves of that contract:

  - an unreadable LOCK sentinel is NOT a gap (the data beside it was searched)
  - a genuinely unreadable DATA file IS still a gap (we do not over-skip)

Hermetic: a reserved-TLD indicator, every path inside a temp dir, the browser
module's import-time path globals pinned directly, and the OS lock simulated by
making ``io.open`` raise PermissionError for the chosen file - the same error
the real lock path raises. No real browser is needed and nothing on the real
machine is touched.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import iocs as iocmod                 # noqa: E402
from adint_scan.context import ScanContext            # noqa: E402
from adint_scan.modules import browser                # noqa: E402
from adint_scan.result import CLEAN                    # noqa: E402

TEST_DOMAIN = "synthetic-test-indicator.invalid"


class LevelDbLockBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lvldb_")
        self.empty = os.path.join(self.tmp, "empty")
        os.makedirs(self.empty)
        ioc_path = os.path.join(self.tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{}\tdelivery\tprimary\ttest-source\n".format(TEST_DOMAIN))
        self.ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)
        # Save every module global we touch, plus the real io.open, and restore
        # them in tearDown so the patch can never leak into another test.
        self._saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                       browser.FIREFOX_ROOTS, io.open)
        browser.FIREFOX_ROOTS = []   # never read the tester's real Firefox
        self._unreadable = set()

    def tearDown(self):
        (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
         browser.FIREFOX_ROOTS, io.open) = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _leveldb_profile(self, *, with_lock=True,
                         data_name="000003.ldb", data_bytes=b"ordinary data"):
        """Build User Data/Default/Local Storage/leveldb holding one data file
        and, optionally, a zero-byte LOCK sentinel. Returns the User Data root."""
        user_data = os.path.join(self.tmp, "User Data")
        self.leveldb = os.path.join(
            user_data, "Default", "Local Storage", "leveldb")
        os.makedirs(self.leveldb)
        with open(os.path.join(self.leveldb, data_name), "wb") as fh:
            fh.write(data_bytes)
        if with_lock:
            # The real sentinel is a zero-byte file the OS locks exclusively.
            with open(os.path.join(self.leveldb, "LOCK"), "wb") as fh:
                fh.write(b"")
        return user_data

    def _run(self, user_data):
        """Run the browser module with every path in self._unreadable made to
        raise PermissionError on open, exactly as a real OS lock does."""
        real_open = self._saved[4]
        blocked = {os.path.abspath(p) for p in self._unreadable}

        def faux_open(path, *args, **kwargs):
            if os.path.abspath(path) in blocked:
                raise PermissionError(
                    13, "The process cannot access the file because it is "
                        "being used by another process")
            return real_open(path, *args, **kwargs)

        browser.CHROMIUM_ROOTS = [("test", user_data)]
        browser.ROAMING = self.empty
        browser.LOCAL = self.empty
        io.open = faux_open
        try:
            return browser.run(self.ctx)
        finally:
            io.open = real_open


class TestLevelDbLockIsNotAGap(LevelDbLockBase):
    def test_unreadable_lock_sentinel_does_not_create_a_gap(self):
        user_data = self._leveldb_profile(with_lock=True)
        self._unreadable = {os.path.join(self.leveldb, "LOCK")}

        r = self._run(user_data)

        self.assertEqual(r.hits, [], "a lock sentinel cannot produce a hit")
        self.assertEqual(
            r.status, CLEAN,
            "an unreadable LevelDB LOCK sentinel is not a gap: the data file "
            "beside it was searched and the lock file holds nothing to search")
        gaps = [c.name for c in r.checks if not c.ran]
        self.assertFalse(gaps, "no check should be a gap: " + "; ".join(gaps))
        self.assertFalse(
            any("LOCK" in n for n in r.notes),
            "the LOCK file must not appear as a could-not-read note")


class TestUnreadableDataFileIsStillAGap(LevelDbLockBase):
    def test_a_genuinely_unreadable_data_file_remains_a_gap(self):
        # Guard against over-skipping: only LOCK is exempt. A real .ldb that
        # cannot be read must still surface as a gap, never be swept under the
        # same exemption - otherwise the fix would hide real uncertainty.
        user_data = self._leveldb_profile(with_lock=False)
        self._unreadable = {os.path.join(self.leveldb, "000003.ldb")}

        r = self._run(user_data)

        self.assertTrue(
            any(not c.ran for c in r.checks),
            "an unreadable data file is a real gap and must be reported")


if __name__ == "__main__":
    unittest.main()
