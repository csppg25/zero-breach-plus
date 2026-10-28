"""Matching must not fire on a longer name or number that merely contains an
indicator.

This is the false-positive direction, and it became urgent when the file grew to
109 IP indicators: plain substring matching reports 52.174.65.77 as present in
152.174.65.771, and controlium.net as present in notcontrolium.net. A tool that
sends people to a human-rights helpline must not do that.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import iocs as iocmod  # noqa: E402


def make_set(lines):
    path = os.path.join(tempfile.mkdtemp(prefix="match_"), "iocs.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return iocmod.load(path)


class TestIpBoundaries(unittest.TestCase):
    def setUp(self):
        self.s = make_set(["52.174.65.77\tcc\tprimary\ttest"])

    def hits(self, text):
        return [i.value for i in self.s.search(text)]

    def test_exact_ip_matches(self):
        self.assertEqual(self.hits("connected to 52.174.65.77 today"),
                         ["52.174.65.77"])

    def test_ip_at_string_edges_matches(self):
        self.assertEqual(self.hits("52.174.65.77"), ["52.174.65.77"])

    def test_longer_number_does_not_match(self):
        self.assertEqual(self.hits("x 152.174.65.771 y"), [],
                         "an IP must not match inside a longer number")

    def test_trailing_digit_does_not_match(self):
        self.assertEqual(self.hits("52.174.65.771"), [])

    def test_leading_digit_does_not_match(self):
        self.assertEqual(self.hits("152.174.65.77"), [])

    def test_further_octet_does_not_match(self):
        self.assertEqual(self.hits("52.174.65.77.9"), [])

    def test_ip_with_port_matches(self):
        self.assertEqual(self.hits("52.174.65.77:443"), ["52.174.65.77"])

    def test_real_occurrence_found_even_after_a_near_miss(self):
        # The near miss must not stop the scan finding the genuine one later.
        self.assertEqual(self.hits("152.174.65.771 and also 52.174.65.77"),
                         ["52.174.65.77"])


class TestDomainBoundaries(unittest.TestCase):
    def setUp(self):
        self.s = make_set(["controlium.net\tdelivery\tprimary\ttest"])

    def hits(self, text):
        return [i.value for i in self.s.search(text)]

    def test_exact_domain_matches(self):
        self.assertEqual(self.hits("https://controlium.net/x"), ["controlium.net"])

    def test_subdomain_matches(self):
        self.assertEqual(self.hits("noas.controlium.net"), ["controlium.net"],
                         "a subdomain of an indicator is still that indicator")

    def test_prefixed_name_does_not_match(self):
        self.assertEqual(self.hits("notcontrolium.net"), [],
                         "a different domain that merely ends with the indicator "
                         "must not match")

    def test_longer_tld_does_not_match(self):
        self.assertEqual(self.hits("controlium.network"), [])

    def test_hyphenated_name_does_not_match(self):
        self.assertEqual(self.hits("safe-controlium.net"), [])


class TestBytesPathAgrees(unittest.TestCase):
    """The binary cache scan must apply the same rules as the text scan."""

    def test_bytes_and_text_agree(self):
        s = make_set(["52.174.65.77\tcc\tprimary\ttest",
                      "controlium.net\tdelivery\tprimary\ttest"])
        for text in ("152.174.65.771 notcontrolium.net",
                     "52.174.65.77 noas.controlium.net",
                     "controlium.network"):
            self.assertEqual(
                sorted(i.value for i in s.search(text)),
                sorted(i.value for i in s.search_bytes(text.encode())),
                "text and binary matching disagree on {!r}".format(text))


class TestSourceColumn(unittest.TestCase):
    def test_optional_fourth_column_is_read(self):
        s = make_set(["a.example\tcc\tprimary\tsome-report-2025"])
        self.assertEqual(s.lookup("a.example").source, "some-report-2025")

    def test_three_column_file_still_loads(self):
        s = make_set(["b.example\tcc\tprimary"])
        self.assertEqual(s.lookup("b.example").source, "")

    def test_new_tiers_accepted(self):
        s = make_set(["c.example\tcandiru\tprimary\tr",
                      "1.2.3.4\tcandiru-ip\tprimary\tr"])
        self.assertEqual(len(s), 2)

    def test_unknown_tier_still_rejected(self):
        with self.assertRaises(iocmod.IocError):
            make_set(["d.example\tnot-a-tier\tprimary\tr"])


class TestLoaderRobustness(unittest.TestCase):
    """The loader's failure modes are silent false negatives - the worst class.
    A list that fails to load a line, or loads it mangled, makes the scan report
    'nothing found' for an indicator it never actually searched for."""

    def _write(self, text, encoding):
        path = os.path.join(tempfile.mkdtemp(prefix="load_"), "iocs.txt")
        with open(path, "w", encoding=encoding, newline="\n") as fh:
            fh.write(text)
        return path

    def test_utf8_bom_does_not_corrupt_first_indicator(self):
        # A Windows editor saves a BOM; U+FEFF is not whitespace to strip().
        p = self._write("controlium.net\tdelivery\tprimary\tt\n", "utf-8-sig")
        s = iocmod.load(p)
        self.assertEqual(s.indicators[0].value, "controlium.net")
        self.assertFalse(s.indicators[0].value.startswith("﻿"))
        self.assertTrue(s.search("go to controlium.net now"))

    def test_empty_file_is_refused(self):
        p = self._write("# only a comment\n\n", "utf-8")
        with self.assertRaises(iocmod.IocError):
            iocmod.load(p)

    def test_zero_width_character_in_indicator_is_rejected(self):
        p = self._write("contro​lium.net\tdelivery\tprimary\tt\n", "utf-8")
        with self.assertRaises(iocmod.IocError):
            iocmod.load(p)

    def test_internationalised_domain_is_stored_as_punycode(self):
        p = self._write("müller.example\tdelivery\tprimary\tt\n", "utf-8")
        s = iocmod.load(p)
        self.assertEqual(s.indicators[0].value, "xn--mller-kva.example")

    def test_trailing_dot_is_normalised_at_load(self):
        p = self._write("controlium.net.\tdelivery\tprimary\tt\n", "utf-8")
        s = iocmod.load(p)
        self.assertEqual(s.indicators[0].value, "controlium.net")


class TestUtf16AndIpv6(unittest.TestCase):
    def test_utf16le_bytes_match(self):
        s = make_set(["controlium.net\tdelivery\tprimary\tt"])
        buf = "visited controlium.net today".encode("utf-16-le")
        self.assertEqual([i.value for i in s.search_bytes(buf.lower())],
                         ["controlium.net"])

    def test_utf16le_respects_boundaries(self):
        s = make_set(["controlium.net\tdelivery\tprimary\tt"])
        buf = "notcontrolium.network".encode("utf-16-le")
        self.assertEqual(s.search_bytes(buf.lower()), [])

    def test_ipv6_exact_and_boundary(self):
        s = make_set(["2a02:db8::1\tcandiru-ip\tprimary\tt"])
        self.assertTrue(s.search("peer 2a02:db8::1 seen"))
        self.assertEqual(s.search("2a02:db8::1a"), [])

    def test_suffix_trap_domain_does_not_match(self):
        s = make_set(["controlium.net\tdelivery\tprimary\tt"])
        self.assertEqual(s.search("controlium.net.evil.example"), [])

    def test_parent_and_child_one_record_collapses(self):
        s = make_set(["powerium.net\tdelivery\tprimary\tt",
                      "noas.powerium.net\tdelivery\tprimary\tt"])
        got = sorted(i.value for i in s.search("cookie for .noas.powerium.net"))
        self.assertEqual(got, ["noas.powerium.net"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
