"""Optional pattern feature stays opt-in and keeps reports honest in both CLIs.

All scan modules are redirected to fixtures; no personal data or live malware.
"""
import contextlib
import datetime
import importlib.util
import io
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adint_scan import cli, report
from adint_scan.context import ScanContext
from adint_scan.iocs import load
from adint_scan.modules import browser, hashscan, host, patternscan
from adint_scan.result import Hit, ModuleResult, EV_FILE_PATTERN

ROOT = Path(__file__).resolve().parents[2]


class PatternIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(prefix="zb_pattern_bundle_")
        output = Path(cls.build_dir.name) / "candidate.py"
        subprocess.run([sys.executable, "-B", str(ROOT / "build/bundle.py"),
                        str(ROOT), str(output)], check=True, capture_output=True)
        spec = importlib.util.spec_from_file_location("_pattern_bundle", output)
        cls.bundle = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.bundle
        spec.loader.exec_module(cls.bundle)

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("_pattern_bundle", None)
        cls.build_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zb_pattern_integration_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.feed = self.root / "iocs.txt"
        self.feed.write_text("# as-of: 2026-10-19\nunused.invalid\tdelivery\tprimary\tfixture\n",
                             encoding="utf-8")

    def run_cli(self, bundled, extra, patterns):
        documents = []
        target = self.bundle if bundled else cli

        def empty(name):
            def run(ctx):
                result = target.ModuleResult(name)
                result.ran("fixture")
                return result
            return run

        with contextlib.ExitStack() as stack:
            if bundled:
                for name in ("browser", "hash", "host"):
                    stack.enter_context(patch.object(target, "run_" + name, empty(name)))
                stack.enter_context(patch.object(target, "run_patterns", patterns))
            else:
                for mod in (browser, hashscan, host):
                    stack.enter_context(patch.object(mod, "run", empty(mod.NAME)))
                stack.enter_context(patch.object(patternscan, "run", patterns))
            stack.enter_context(patch.object(target, "_force_utf8_io", lambda: None))
            stack.enter_context(patch.object(target, "render_human",
                                            lambda d: documents.append(d) or ""))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            args = ["--iocs", str(self.feed)] + extra
            if bundled:
                args.append("--no-pause")
            code = target.main(args)
        return code, documents[0]

    def test_default_does_not_run_pattern_engine(self):
        def forbidden(ctx):
            self.fail("optional pattern check ran without --patterns")
        for bundled in (False, True):
            with self.subTest(bundled=bundled):
                code, doc = self.run_cli(bundled, [], forbidden)
                self.assertEqual(code, 0)
                self.assertNotIn("patterns", doc["modules"])

    def test_explicit_patterns_runs_with_quick_and_paths(self):
        for bundled in (False, True):
            target = self.bundle if bundled else cli
            def selected(ctx):
                self.assertTrue(ctx.patterns)
                self.assertEqual(ctx.pattern_paths, (str(self.root),))
                r = target.ModuleResult("patterns")
                r.could_not_run("engine", "fixture engine unavailable")
                return r
            with self.subTest(bundled=bundled):
                code, doc = self.run_cli(bundled,
                    ["--quick", "--patterns", "--pattern-path", str(self.root)], selected)
                self.assertEqual(code, 0)
                self.assertEqual(doc["modules"]["patterns"]["status"], "UNKNOWN")
                self.assertEqual(doc["verdict"]["status"], "NO_KNOWN_INDICATORS_WITH_GAPS")
                self.assertTrue(any("engine unavailable" in g for g in doc["verdict"]["gaps"]))

    def test_failure_preserves_pattern_hit_and_gap(self):
        for bundled in (False, True):
            target = self.bundle if bundled else cli
            hit_type = self.bundle.Hit if bundled else Hit
            def interrupted(ctx):
                r = target.ModuleResult("patterns")
                ctx.partial = r
                r.add_hit(hit_type("yara:fixture", str(self.root / "data"), "fixture",
                                  tier="candiru-pattern", evidence=EV_FILE_PATTERN))
                raise ValueError("fixture late failure")
            with self.subTest(bundled=bundled):
                code, doc = self.run_cli(bundled, ["--patterns"], interrupted)
                self.assertEqual(code, 2)
                self.assertEqual(doc["verdict"]["hits_total"], 1)
                self.assertTrue(any("late failure" in g for g in doc["verdict"]["gaps"]))

    def test_pattern_report_does_not_claim_exact_sample_or_infection(self):
        r = ModuleResult("patterns")
        r.ran("fixture")
        r.add_hit(Hit("yara:MAL_DevilsTongue_HijackDll", str(self.root / "data"),
                      "Author: Microsoft Threat Intelligence Center (MSTIC)",
                      tier="candiru-pattern", evidence=EV_FILE_PATTERN,
                      source="https://example.org/research"))
        doc = report.build_document(load(str(self.feed)), [r], datetime.datetime.now())
        text = " ".join(report.render_human(doc).split())
        self.assertIn("A FILE MATCHED A CANDIRU DETECTION RULE", text)
        self.assertIn("pattern match alone does not prove infection", text)
        self.assertIn("Microsoft Threat Intelligence Center", text)
        self.assertNotIn("A KNOWN SPYWARE FILE IS ON THIS MACHINE", text)
        self.assertEqual(doc["verdict"]["status"], "INDICATORS_FOUND")

    def test_pattern_path_requires_opt_in(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as err:
            cli._parse(["--pattern-path", str(self.root)])
        self.assertEqual(err.exception.code, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as err:
            self.bundle.main(["--pattern-path", str(self.root), "--no-pause"])
        self.assertEqual(err.exception.code, 2)

    @unittest.skipUnless(importlib.util.find_spec("yara_x"), "optional YARA-X not installed")
    def test_actual_rules_through_both_entrypoints_preserve_fixture_bytes(self):
        from test_patterns import synthetic_mstic_fixture, synthetic_malpedia_fixture
        fixtures = (("mstic", synthetic_mstic_fixture(), "MAL_DevilsTongue_HijackDll"),
                    ("malpedia", synthetic_malpedia_fixture(), "win_devilstongue_auto"),
                    ("ordinary", b"ordinary harmless local document", None))
        for bundled in (False, True):
            target = self.bundle.run_patterns if bundled else patternscan.run
            for name, data, rule in fixtures:
                with self.subTest(bundled=bundled, fixture=name):
                    path = self.root / name
                    path.write_bytes(data)
                    before = hashlib.sha256(path.read_bytes()).hexdigest()
                    code, doc = self.run_cli(bundled,
                        ["--quick", "--patterns", "--pattern-path", str(path)], target)
                    matches = doc["modules"]["patterns"]["hits"]
                    self.assertEqual(code, 2 if rule else 0)
                    self.assertEqual({h["indicator"] for h in matches},
                                     {"yara:" + rule} if rule else set())
                    self.assertEqual(doc["modules"]["patterns"]["checked"], 1)
                    self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())
                    for hit in matches:
                        self.assertEqual(hit["evidence"], "file-pattern")
                        self.assertIn("author:", hit["detail"])


if __name__ == "__main__":
    unittest.main()
