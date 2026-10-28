"""D1 / D3 — the doctrine contract, asserted against the literal wording.

SPEC-scanner.md, "The doctrine":

  D1  Every run that finds nothing prints EXACTLY the mandatory closing line.
      A reword is a doctrine regression, so the sentence is asserted here as a
      literal, not by referring to report.D1_LINE alone.
  D3  Measured, never inferred. A check that could not run is UNKNOWN, which is
      a DISTINCT outcome from CLEAN, and a gap must be stated out loud in the
      interface rather than rolled into a clean verdict.

Also asserted here: a hit renders as "investigate" and never as a claim of
compromise, and the IOC-freshness rule from "IOC freshness" (older than 30 days
must be said prominently).

Hermetic: nothing here touches the real machine. IOC sets are built in temp
files or in memory; no module is run.
"""

from __future__ import annotations

import datetime
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import iocs as iocmod                                # noqa: E402
from adint_scan import report                                        # noqa: E402
from adint_scan.result import (CLEAN, HITS, PARTIAL, UNKNOWN,        # noqa: E402
                               Hit, ModuleResult)

# The sentence D1 requires, written out by hand. If report.D1_LINE is ever
# reworded this literal is what fails the suite.
D1_LITERAL = ("No known indicators were found in the places that can be checked. "
              "This is not a clean bill of health.")

STARTED = datetime.datetime(2025, 1, 1, 12, 0, 0)


def empty_iocset(path="<test>", mtime=None):
    """An IocSet with no indicators; enough for build_document/render_human."""
    return iocmod.IocSet([], path, mtime)


def clean_module(name="browser", checks=("history", "cache")):
    m = ModuleResult(name)
    m.checked = 10
    for c in checks:
        m.ran(c)
    return m


class TestD1ClosingLine(unittest.TestCase):
    def test_d1_line_constant_is_the_required_sentence(self):
        self.assertEqual(report.D1_LINE, D1_LITERAL,
                         "D1: the mandatory closing line must not be reworded")

    def test_d1_line_present_in_document_and_rendered_text_when_nothing_found(self):
        doc = report.build_document(empty_iocset(), [clean_module()], STARTED)
        self.assertEqual(doc["doctrine_line"], D1_LITERAL)
        text = report.render_human(doc)
        self.assertIn(D1_LITERAL, text,
                      "D1: the exact sentence must appear in the human report")

    def test_d1_line_absent_when_there_is_a_hit(self):
        m = ModuleResult("browser")
        m.ran("history")
        m.add_hit(Hit("fearevolve.com", r"C:\fake\History", "history: x",
                      tier="delivery", confidence="primary"))
        doc = report.build_document(empty_iocset(), [m], STARTED)
        self.assertIsNone(doc["doctrine_line"],
                          "D1 is the closing line for a run that found NOTHING")
        text = report.render_human(doc)
        self.assertNotIn(D1_LITERAL, text,
                         "the 'nothing was found' sentence must not be printed "
                         "alongside a match")

    def test_d1_line_present_even_when_there_are_gaps(self):
        gapped = ModuleResult("host")
        gapped.ran("hosts-file")
        gapped.could_not_run("dns-log", "log disabled")
        doc = report.build_document(empty_iocset(), [clean_module(), gapped],
                                    STARTED)
        self.assertEqual(doc["doctrine_line"], D1_LITERAL)
        self.assertIn(D1_LITERAL, report.render_human(doc))


class TestD3StatusRollup(unittest.TestCase):
    """CLEAN and UNKNOWN must stay distinct outcomes."""

    def test_unknown_is_not_clean(self):
        self.assertNotEqual(UNKNOWN, CLEAN,
                            "D3: UNKNOWN must be a distinct outcome from CLEAN")

    def test_zero_checks_is_unknown(self):
        m = ModuleResult("host")
        self.assertEqual(m.status, UNKNOWN)
        self.assertNotEqual(m.status, CLEAN,
                            "a module that observed nothing is not clean")

    def test_all_checks_ran_is_clean(self):
        m = ModuleResult("host")
        m.ran("hosts-file")
        m.ran("dns-cache")
        self.assertEqual(m.status, CLEAN)

    def test_mixed_ran_and_could_not_run_is_partial(self):
        m = ModuleResult("host")
        m.ran("hosts-file")
        m.could_not_run("dns-log", "Microsoft-Windows-DNS-Client/Operational "
                                   "is disabled")
        self.assertEqual(m.status, PARTIAL)
        self.assertNotEqual(m.status, CLEAN)

    def test_no_check_ran_is_unknown(self):
        m = ModuleResult("host")
        m.could_not_run("dns-log", "disabled")
        m.could_not_run("com", "access denied")
        self.assertEqual(m.status, UNKNOWN)

    def test_any_hit_is_hits_even_with_gaps(self):
        m = ModuleResult("browser")
        m.ran("chromium:chrome")
        m.could_not_run("firefox", "profile locked")
        m.add_hit(Hit("fearevolve.com", "loc", "detail"))
        self.assertEqual(m.status, HITS)

    def test_could_not_run_is_recorded_as_a_visible_note(self):
        m = ModuleResult("host")
        m.could_not_run("dns-log", "disabled")
        self.assertTrue(any("dns-log" in n and "could not run" in n
                            for n in m.notes),
                        "a gap must be surfaced, not silently swallowed")


class TestVerdictRollup(unittest.TestCase):
    def test_all_clean_is_v_none(self):
        doc = report.build_document(
            empty_iocset(), [clean_module("browser"), clean_module("hash")],
            STARTED)
        self.assertEqual(doc["verdict"]["status"], report.V_NONE)
        self.assertEqual(doc["verdict"]["gaps"], [])
        self.assertEqual(doc["verdict"]["hits_total"], 0)

    def test_clean_plus_gap_is_v_none_with_gaps_and_names_the_gap(self):
        gapped = ModuleResult("host")
        gapped.ran("hosts-file")
        gapped.could_not_run("dns-log", "log is disabled by default")
        doc = report.build_document(empty_iocset(),
                                    [clean_module("browser"), gapped], STARTED)
        v = doc["verdict"]
        self.assertEqual(v["status"], report.V_NONE_WITH_GAPS)
        self.assertTrue(v["gaps"], "a gap must be reported in the verdict")
        joined = " | ".join(v["gaps"])
        self.assertIn("host", joined, "the gap must name the module")
        self.assertIn("dns-log", joined, "the gap must name the check")
        self.assertIn("log is disabled by default", joined,
                      "the gap must carry the reason")
        text = report.render_human(doc)
        self.assertIn("could NOT run", text)
        self.assertIn("dns-log", text)

    def test_any_hit_is_v_hits(self):
        m = ModuleResult("hash")
        m.ran("root:C:/fake")
        m.add_hit(Hit("a" * 64, r"C:\fake\payload.dll", "known sample",
                      tier="sample", confidence="primary"))
        doc = report.build_document(empty_iocset(),
                                    [clean_module("browser"), m], STARTED)
        self.assertEqual(doc["verdict"]["status"], report.V_HITS)
        self.assertEqual(doc["verdict"]["hits_total"], 1)


class TestHitRendersAsInvestigate(unittest.TestCase):
    """A match means INVESTIGATE. The tool must never tell someone they are
    compromised — an ad impression is not proof of infection."""

    def setUp(self):
        m = ModuleResult("browser")
        m.ran("chromium:chrome")
        m.add_hit(Hit("fearevolve.com", r"C:\fake\Default\History",
                      "history: http://fearevolve.com/x",
                      tier="delivery", confidence="primary"))
        self.text = report.render_human(
            report.build_document(empty_iocset(), [m], STARTED))

    def test_says_investigate(self):
        self.assertIn("investigate", self.text.lower())
        self.assertIn("INVESTIGATE", self.text)

    def test_never_claims_compromise(self):
        low = self.text.lower()
        # report.py deliberately prints the phrase as a NEGATION:
        #   "A match means INVESTIGATE, not 'you are compromised'."
        # That wording is doctrine, so this test bans only AFFIRMATIVE claims.
        for affirmative in ("this device is compromised",
                            "your machine is compromised",
                            "you have been infected",
                            "you are infected"):
            self.assertNotIn(affirmative, low)
        # Every occurrence of "compromised" must sit inside a negation: the word
        # "not" has to appear within the 30 characters immediately before it.
        start = 0
        while True:
            idx = low.find("compromised", start)
            if idx < 0:
                break
            window = low[max(0, idx - 30):idx]
            self.assertIn("not", window,
                          "'compromised' at offset {} is not negated: {!r}"
                          .format(idx, low[max(0, idx - 40):idx + 20]))
            start = idx + 1
        self.assertEqual(low.count("you are compromised"),
                         low.count("not 'you are compromised'"),
                         "the only permitted use of 'you are compromised' is "
                         "the explicit denial of it")

    def test_carries_provenance_and_location(self):
        # Defanged, because every rendering of the name in the human report is -
        # including the one inside the detail line, which quotes a whole URL.
        self.assertIn("fearevolve[.]com", self.text)
        self.assertNotIn("fearevolve.com", self.text)
        self.assertIn("delivery/primary", self.text)
        self.assertIn(r"C:\fake\Default\History", self.text)

    def test_offers_the_referrals(self):
        for url in ("accessnow.org", "securitylab.amnesty.org", "citizenlab.ca"):
            self.assertIn(url, self.text,
                          "a hit must hand the user to people who do this "
                          "properly")

    def test_clean_run_also_offers_the_referrals(self):
        text = report.render_human(
            report.build_document(empty_iocset(), [clean_module()], STARTED))
        for url in ("accessnow.org", "securitylab.amnesty.org", "citizenlab.ca"):
            self.assertIn(url, text)


class TestIocFreshness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iocfresh_")
        self.path = os.path.join(self.tmp, "iocs.txt")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("# test set\nfearevolve.com\tdelivery\tprimary\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _age(self, days):
        when = datetime.datetime.now() - datetime.timedelta(days=days)
        ts = when.timestamp()
        os.utime(self.path, (ts, ts))

    def test_fresh_set_is_not_stale(self):
        self._age(1)
        s = iocmod.load(self.path)
        self.assertFalse(s.is_stale())
        self.assertLessEqual(s.age_days(), 2)
        text = report.render_human(
            report.build_document(s, [clean_module()], STARTED))
        self.assertNotIn("more than 30 days old", text)

    def test_set_older_than_30_days_is_stale_and_warned_about(self):
        self._age(45)
        s = iocmod.load(self.path)
        self.assertTrue(s.is_stale(),
                        "IOC freshness: older than 30 days must be flagged")
        self.assertGreaterEqual(s.age_days(), 44)
        doc = report.build_document(s, [clean_module()], STARTED)
        self.assertTrue(doc["ioc_set"]["stale"])
        text = report.render_human(doc)
        self.assertIn("WARNING", text)
        self.assertIn("more than 30 days old", text)

    def test_exactly_30_days_is_not_yet_stale(self):
        # threshold is "older than 30 days"; 30 days exactly is the boundary.
        self._age(30)
        self.assertFalse(iocmod.load(self.path).is_stale())

    def test_unknown_age_is_reported_as_unknown_not_as_fresh(self):
        s = iocmod.IocSet([], "<memory>", None)
        self.assertIsNone(s.age_days())
        self.assertFalse(s.is_stale())
        text = report.render_human(
            report.build_document(s, [clean_module()], STARTED))
        self.assertIn("unknown age", text)


class TestIocLoaderRejectsMalformedData(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="iocbad_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, body, name="iocs.txt"):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)
        return p

    def test_two_column_line_is_rejected(self):
        p = self._write("fearevolve.com\tdelivery\n")
        with self.assertRaises(iocmod.IocError):
            iocmod.load(p)

    def test_unknown_tier_is_rejected(self):
        p = self._write("fearevolve.com\tnot-a-tier\tprimary\n")
        with self.assertRaises(iocmod.IocError):
            iocmod.load(p)

    def test_unknown_confidence_is_rejected(self):
        p = self._write("fearevolve.com\tdelivery\tmaybe\n")
        with self.assertRaises(iocmod.IocError):
            iocmod.load(p)

    def test_missing_file_is_rejected(self):
        with self.assertRaises(iocmod.IocError):
            iocmod.load(os.path.join(self.tmp, "nope.txt"))

    def test_comments_and_blank_lines_are_ignored(self):
        p = self._write("# header\n\nfearevolve.com\tdelivery\tprimary\n\n")
        s = iocmod.load(p)
        self.assertEqual(len(s), 1)

    def test_valid_set_keeps_tier_and_confidence_provenance(self):
        p = self._write("fearevolve.com\tcc\tsecondary\n")
        ind = iocmod.load(p).lookup("fearevolve.com")
        self.assertIsNotNone(ind)
        self.assertEqual((ind.tier, ind.confidence), ("cc", "secondary"))


class TestIocTypeInference(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ioctype_")
        self.path = os.path.join(self.tmp, "iocs.txt")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{}\tsample\tprimary\n".format("ab12cd34" * 8))
            fh.write("185.181.8.155\tcc\tprimary\n")
            fh.write("fearevolve.com\tdelivery\tprimary\n")
        self.set = iocmod.load(self.path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_64_hex_is_sha256(self):
        self.assertEqual(iocmod.infer_type("ab12cd34" * 8), iocmod.TYPE_SHA256)
        self.assertEqual(self.set.lookup("ab12cd34" * 8).type,
                         iocmod.TYPE_SHA256)
        self.assertEqual([i.value for i in self.set.hashes], ["ab12cd34" * 8])

    def test_dotted_quad_is_ip(self):
        self.assertEqual(iocmod.infer_type("185.181.8.155"), iocmod.TYPE_IP)
        self.assertEqual([i.value for i in self.set.ips], ["185.181.8.155"])

    def test_name_is_domain(self):
        self.assertEqual(iocmod.infer_type("fearevolve.com"), iocmod.TYPE_DOMAIN)
        self.assertEqual([i.value for i in self.set.domains], ["fearevolve.com"])

    def test_network_strings_hold_domains_and_ips_but_no_hashes(self):
        net = self.set.network_strings
        self.assertIn("fearevolve.com", net)
        self.assertIn("185.181.8.155", net)
        self.assertNotIn("ab12cd34" * 8, net)


if __name__ == "__main__":
    unittest.main(verbosity=2)
