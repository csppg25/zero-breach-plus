"""D2 — the tool must never contact an indicator. Asserted, not merely intended.

SPEC-scanner.md, testing requirements: "Verify no module ever performs DNS
resolution of an indicator — assert this in a test, do not merely intend it."

Three layers of assertion here:
  1. the guard itself blocks every resolution / egress entry point
  2. a real full scan, run with socket instrumented, performs ZERO resolutions
  3. no module even imports a network library (a static check, so a future edit
     that adds `import requests` fails the suite rather than shipping)
"""

from __future__ import annotations

import os
import re
import socket
import sys
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan.netguard import NetworkContactAttempt, no_network  # noqa: E402


class TestGuardBlocks(unittest.TestCase):
    def test_getaddrinfo_blocked(self):
        with no_network():
            with self.assertRaises(NetworkContactAttempt):
                socket.getaddrinfo("fearevolve.com", 443)

    def test_gethostbyname_blocked(self):
        with no_network():
            with self.assertRaises(NetworkContactAttempt):
                socket.gethostbyname("keyadapter.com")

    def test_create_connection_blocked(self):
        with no_network():
            with self.assertRaises(NetworkContactAttempt):
                socket.create_connection(("controlium.net", 80), timeout=1)

    def test_socket_connect_blocked(self):
        with no_network():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with self.assertRaises(NetworkContactAttempt):
                    s.connect(("185.181.8.155", 80))
            finally:
                s.close()

    def test_guard_restores_socket_afterwards(self):
        original = socket.getaddrinfo
        with no_network():
            self.assertIsNot(socket.getaddrinfo, original)
        self.assertIs(socket.getaddrinfo, original,
                      "the guard must restore socket on exit, or it would break "
                      "the IOC-update path that is allowed to use the network")

    def test_attempt_is_recorded(self):
        with no_network() as recorder:
            try:
                socket.gethostbyname("jobmarcher.com")
            except NetworkContactAttempt:
                pass
            self.assertEqual(recorder.attempts, ["socket.gethostbyname"])


class TestRealScanResolvesNothing(unittest.TestCase):
    """Exercise host orchestration with synthetic OS inputs, never live host I/O."""

    def test_full_scan_performs_no_resolution(self):
        from adint_scan import iocs as iocmod
        from adint_scan.context import ScanContext
        from adint_scan.modules import host

        ioc_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))),
            "iocs", "adfection_iocs.txt")
        ioc_set = iocmod.load(ioc_path)

        calls = []
        real_getaddrinfo = socket.getaddrinfo
        real_gethostbyname = socket.gethostbyname

        def spy_getaddrinfo(*a, **k):
            calls.append(("getaddrinfo", a))
            raise AssertionError("unexpected resolution")

        def spy_gethostbyname(*a, **k):
            calls.append(("gethostbyname", a))
            raise AssertionError("unexpected resolution")

        socket.getaddrinfo = spy_getaddrinfo
        socket.gethostbyname = spy_gethostbyname
        try:
            ctx = ScanContext(iocs=ioc_set, emit=lambda _m: None)
            with tempfile.TemporaryDirectory() as tmp:
                with patch.dict(os.environ, {"SystemRoot": tmp}), \
                     patch.object(host.platform, "system", return_value="Windows"), \
                     patch.object(host, "_enum_com_registrations", return_value=([], [])), \
                     patch.object(host, "_network_drive_letters", return_value=(set(), True)), \
                     patch.object(host, "_ps_json", return_value=([], "")), \
                     patch.object(host, "_ps", return_value=("", "")), \
                     patch.object(host.subprocess, "run", side_effect=AssertionError("live subprocess")):
                    host.run(ctx)
        finally:
            socket.getaddrinfo = real_getaddrinfo
            socket.gethostbyname = real_gethostbyname

        self.assertEqual(
            calls, [],
            "D2 VIOLATION: the scan resolved {} name(s). Resolving an indicator "
            "announces a possible victim to the people running the "
            "infrastructure.".format(len(calls)))


class TestNoNetworkImports(unittest.TestCase):
    """Static guard: a module must not even import a network library."""

    FORBIDDEN = ("import requests", "import urllib", "from urllib",
                 "import http.client", "import httpx", "import socket",
                 "import ftplib", "import telnetlib", "dns.resolver")

    def test_modules_import_nothing_networked(self):
        mod_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "adint_scan", "modules")
        offenders = []
        for fn in os.listdir(mod_dir):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(mod_dir, fn), encoding="utf-8") as fh:
                text = fh.read()
            # urllib.parse is a pure string parser; no other urllib module is
            # permitted. Keep the exemption exact instead of allowing urllib.
            text = text.replace("from urllib.parse import urlsplit", "")
            for needle in self.FORBIDDEN:
                if needle in text:
                    offenders.append("{}: {}".format(fn, needle))
        self.assertEqual(offenders, [],
                         "scan modules must not import network libraries: {}"
                         .format(offenders))

    def test_no_module_shells_out_to_a_resolver(self):
        """Blocks the other way to resolve a name: handing it to a system tool."""
        mod_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "adint_scan", "modules")
        # Word-boundary matched, not plain substring: "ping" as a substring also
        # occurs inside "skipping", which would fail the suite for no reason.
        forbidden = ("resolve-dnsname", "nslookup", "ping", "curl", "wget",
                     "invoke-webrequest", "test-netconnection", "whois",
                     "tnc", "portqry")
        pattern = re.compile(
            r"\b(" + "|".join(re.escape(f) for f in forbidden) + r")\b")
        offenders = []
        for fn in os.listdir(mod_dir):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(mod_dir, fn), encoding="utf-8") as fh:
                text = fh.read().lower()
            for found in sorted(set(pattern.findall(text))):
                offenders.append("{}: {}".format(fn, found))
        self.assertEqual(offenders, [],
                         "a module appears to shell out to a name resolver or "
                         "HTTP client: {}".format(offenders))


class TestRemotePathsAreNeverTouched(unittest.TestCase):
    """The socket guard cannot see a filesystem path.

    A COM registration value comes out of the registry, which an attacker on a
    compromised machine controls. os.path.exists() on \\\\attacker-host\\share\\x.dll
    makes WINDOWS open an SMB session - no Python socket is involved, so the
    guard above records nothing - and that handshake can hand the remote host
    the user's NetNTLM credentials. A drive letter mapped to a remote share does
    the same with none of the visual warning.
    """

    BACKSLASH = chr(92)

    def _run_com_over(self, raw_values, remote_letters=(), kind="InprocServer32"):
        import tempfile
        from adint_scan import iocs as iocmod
        from adint_scan.context import ScanContext
        from adint_scan.modules import host

        tmp = tempfile.mkdtemp(prefix="comunc_")
        ioc_path = os.path.join(tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("synthetic-indicator.invalid\tdelivery\tprimary\tt\n")
        ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)

        touched = []
        real_exists, real_isfile = os.path.exists, os.path.isfile
        saved_enum = host._enum_com_registrations
        saved_drives = host._network_drive_letters
        saved_sigs = host._signature_status

        def spy_exists(p):
            touched.append(p)
            return False

        def spy_isfile(p):
            touched.append(p)
            return False

        host._enum_com_registrations = lambda _r: ([
            {"clsid": "{{{}}}".format(i), "kind": kind, "raw": v,
             "view": "native"} for i, v in enumerate(raw_values)], [])
        host._network_drive_letters = lambda: (set(remote_letters), True)
        # Never spawn PowerShell from the suite; signatures are not what this
        # test is about.
        host._signature_status = lambda paths, timeout=180: ({}, "")
        os.path.exists, os.path.isfile = spy_exists, spy_isfile
        try:
            r = host.ModuleResult("host")
            host._check_com(r, ctx)
        finally:
            os.path.exists, os.path.isfile = real_exists, real_isfile
            host._enum_com_registrations = saved_enum
            host._network_drive_letters = saved_drives
            host._signature_status = saved_sigs
        return r, touched

    def test_unc_registration_is_never_handed_to_the_filesystem(self):
        b = self.BACKSLASH
        unc = b + b + "attacker-host" + b + "share" + b + "payload.dll"
        unc_ext = b + b + "?" + b + "UNC" + b + "attacker-host" + b + "p.dll"
        # The safe control must be local on the OS running the test. A C:\\
        # path is relative/unknown on Linux and should correctly be rejected.
        with tempfile.TemporaryDirectory(prefix="com_local_") as local_root:
            local = os.path.join(local_root, "synthetic-local-library.dll")
            r, touched = self._run_com_over([unc, unc_ext, local])
        for p in touched:
            self.assertFalse(str(p).startswith(b + b),
                             "D2 VIOLATION: the scan stat()ed {}, which makes "
                             "Windows connect to the remote host".format(p))
        self.assertEqual(r.submetrics.get("com_remote_paths"), 2)

    def test_network_mapped_drive_letter_is_never_touched(self):
        b = self.BACKSLASH
        r, touched = self._run_com_over(["Z:" + b + "payload.dll"],
                                        remote_letters=("Z",))
        self.assertEqual(touched, [])
        self.assertEqual(r.submetrics.get("com_remote_paths"), 1)

    def test_localserver_remote_paths_are_rejected_before_command_parsing_io(self):
        b = self.BACKSLASH
        for raw in (b + b + "synthetic.invalid" + b + "share" + b + "app.exe",
                    b + b + "?" + b + "UNC" + b + "synthetic.invalid" + b + "a.exe",
                    "Z:" + b + "app.exe -Embedding"):
            with self.subTest(raw=raw):
                r, touched = self._run_com_over([raw], ("Z",), "LocalServer32")
                self.assertEqual(touched, [])
                self.assertTrue(any(not c.ran for c in r.checks))

    def test_signature_inventory_never_starts_a_subprocess(self):
        from adint_scan.modules import host
        with patch.object(host, "_ps_json", side_effect=AssertionError("network-capable verifier")):
            statuses, reason = host._signature_status(["C:" + self.BACKSLASH + "example.dll"])
        self.assertTrue(reason)
        self.assertEqual(next(iter(statuses.values()))[0], "NotChecked")

    def test_a_rejected_path_is_a_recorded_gap_not_a_silent_drop(self):
        """D3: UNKNOWN is never CLEAN. Refusing to look is honest; pretending
        the entry was checked is not."""
        b = self.BACKSLASH
        unc = b + b + "attacker-host" + b + "share" + b + "payload.dll"
        r, _touched = self._run_com_over([unc])
        com = [c for c in r.checks if c.name == "com-persistence"]
        self.assertEqual(len(com), 1)
        self.assertFalse(com[0].ran, "the COM check must not report as fully "
                                     "run when an entry was left unverified")
        self.assertIn("not on a local disk", com[0].reason)
        self.assertTrue(any("UNVERIFIED" in n for n in r.notes),
                        "the user must be told which entries were not checked")
        self.assertTrue(any("attacker-host" in n for n in r.notes),
                        "and which path it was")


if __name__ == "__main__":
    unittest.main(verbosity=2)
