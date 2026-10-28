"""Human-only next steps follow evidence and provenance, never match counts."""

import copy
import datetime
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import report
from adint_scan.iocs import Indicator, IocSet, TYPE_DOMAIN, TYPE_IP, TYPE_SHA256
from adint_scan.result import (Hit, ModuleResult, EV_ON_DISK, EV_PERSISTENCE,
                               EV_CONTACTED, EV_DNS, EV_ATTEMPTED,
                               EV_CONFIGURED, EV_REFERENCED)


class TestReportTriage(unittest.TestCase):
    def hit(self, tier, evidence, number=1, observed=""):
        if evidence == EV_ON_DISK or tier in ("sample", "vuln-driver"):
            value = "{:064x}".format(number)
        elif tier == "candiru-ip":
            value = "192.0.2.{}".format(number)
        else:
            value = "indicator-{}.invalid".format(number)
        return Hit(value, "synthetic saved record {}".format(number),
                   "synthetic evidence", tier, "primary", "synthetic-source",
                   evidence, observed, "Synthetic Profile")

    def document(self, hits, gap=False):
        module = ModuleResult("synthetic")
        module.ran("fixture")
        for hit in hits:
            module.add_hit(hit)
        if gap:
            module.could_not_run("unread-profile", "synthetic profile could not be read")
        indicators = []
        for hit in hits:
            kind = (TYPE_SHA256 if len(hit.indicator) == 64 else
                    TYPE_IP if hit.tier == "candiru-ip" else TYPE_DOMAIN)
            indicators.append(Indicator(hit.indicator, hit.tier, "primary", kind))
        if not indicators:
            indicators = [Indicator("unused.invalid", "delivery", "primary", TYPE_DOMAIN)]
        iocs = IocSet(indicators, "synthetic-fixture", None)
        platform = {"system": "Synthetic", "release": "test", "version": "test",
                    "machine": "test", "python": "test"}
        with patch.object(report, "_platform_info", return_value=platform):
            return report.build_document(iocs, [module], datetime.datetime(2026, 10, 18))

    def summary(self, hits, gap=False):
        return " ".join(report.render_summary(self.document(hits, gap)).split())

    def test_summary_keeps_full_copyable_evidence_location(self):
        hit = self.hit("delivery", EV_CONTACTED)
        hit.location = (r"C:\Users\Example User\AppData\Local\Google\Chrome"
                        r"\User Data\Profile 1\Network\Cookies")
        text = report.render_summary(self.document([hit]))
        self.assertIn("Where: " + hit.location, text)
        self.assertNotIn(r"...\Google", text)

    def assert_self_review(self, text):
        self.assertIn("start with the saved context", text)
        self.assertNotIn("RESULT: SERIOUS FINDING", text)
        self.assertNotIn("RESULT: potentially SERIOUS", text)
        self.assertNotIn("Seek expert help promptly", text)

    def test_delivery_network_variants_start_with_context(self):
        for evidence in (EV_CONTACTED, EV_DNS, EV_ATTEMPTED):
            with self.subTest(evidence=evidence):
                hit = self.hit("delivery", evidence)
                self.assertEqual(report._recommended_action(hit.to_dict()), 1)
                text = self.summary([hit])
                self.assert_self_review(text)
                self.assertIn("Advertising-network records alone do not show", text)
                self.assertIn("credible targeting concern", text)

    def test_delivery_configuration_is_not_explained_as_an_ad_impression(self):
        text = self.summary([self.hit("delivery", EV_CONFIGURED)])
        self.assert_self_review(text)
        self.assertIn("check who or what created it and why", text)
        self.assertIn("An ordinary ad impression does not explain a local hosts-file entry", text)
        self.assertNotIn("A connection can result from an ordinary ad", text)

    def test_legitimate_driver_alone_routes_to_software_context(self):
        text = self.summary([self.hit("vuln-driver", EV_ON_DISK)])
        self.assert_self_review(text)
        self.assertIn("hardware or software you use", text)
        self.assertIn("Do not delete it solely because of this match", text)
        self.assertNotIn("A KNOWN SPYWARE FILE", text)

    def test_historical_ip_dates_do_not_invent_temporal_attribution(self):
        for observed in ("", "2025-03-04T12:00:00Z", "2026-10-18T12:00:00Z"):
            for evidence in (EV_DNS, EV_CONTACTED):
                with self.subTest(observed=observed, evidence=evidence):
                    text = self.summary([self.hit("candiru-ip", evidence, observed=observed)])
                    self.assert_self_review(text)
                    self.assertIn("has not established who controlled it at the time", text)
                    self.assertNotIn("THIS DEVICE CONTACTED THIS INFRASTRUCTURE", text)
                    if observed:
                        self.assertIn(observed[:10], text)

    def test_attributed_domain_contact_requests_specialist_review(self):
        for tier in ("cc", "validator", "candiru", "historical"):
            with self.subTest(tier=tier):
                hit = self.hit(tier, EV_CONTACTED)
                self.assertEqual(report._recommended_action(hit.to_dict()), 2)
                text = self.summary([hit])
                self.assertIn("qualified review recommended", text)
                self.assertIn("warrants specialist review", text)
                self.assertNotIn("start with the saved context", text)

    def test_domain_dns_retains_lookup_limit_and_qualified_interpretation(self):
        for tier in ("cc", "validator", "candiru", "historical"):
            with self.subTest(tier=tier):
                text = self.summary([self.hit(tier, EV_DNS)])
                self.assertIn("Qualified interpretation is recommended", text)
                self.assertIn("A DNS record may be a failed lookup", text)
                self.assertNotIn("THIS DEVICE CONTACTED", text)

    def test_known_sample_receives_prompt_preservation_guidance(self):
        text = self.summary([self.hit("sample", EV_ON_DISK)])
        self.assertIn("RESULT: SERIOUS FINDING", text)
        self.assertIn("Seek expert help promptly", text)
        self.assertIn("Do NOT delete, move, run or try to clean", text)
        self.assertIn("Neither alone establishes that spyware executed", text)
        self.assertNotIn("start with the saved context", text)

    def test_persistence_overrides_lower_concern_tiers(self):
        for tier in ("delivery", "candiru-ip", "vuln-driver", "cc"):
            with self.subTest(tier=tier):
                hit = self.hit(tier, EV_PERSISTENCE)
                self.assertEqual(report._recommended_action(hit.to_dict()), 3)
                self.assertIn("Seek expert help promptly", self.summary([hit]))

    def test_unknown_metadata_never_routes_to_reassurance(self):
        for tier, evidence, action in (("delivery", "", 2), ("cc", "misspelled", 2),
                                       ("future-tier", EV_CONTACTED, 2),
                                       ("", EV_ON_DISK, 3),
                                       ("future-tier", EV_ON_DISK, 3)):
            with self.subTest(tier=tier, evidence=evidence):
                hit = self.hit(tier, evidence)
                self.assertEqual(report._recommended_action(hit.to_dict()), action)
                text = self.summary([hit])
                self.assertNotIn("start with the saved context", text)
                self.assertNotIn("probably not a sign of compromise", text)

    def test_unknown_on_disk_provenance_does_not_invent_known_malware(self):
        hit = self.hit("future-tier", EV_ON_DISK)
        text = " ".join(report.render_human(self.document([hit])).split())
        self.assertIn("Seek expert help promptly", text)
        self.assertNotIn("A KNOWN SPYWARE FILE", text)
        self.assertNotIn("this is conclusive", text)

    def test_reference_only_retains_gaps_and_does_not_clear_device(self):
        for tier in ("delivery", "cc", "validator", "historical", "sample"):
            with self.subTest(tier=tier):
                hit = self.hit(tier, EV_REFERENCED)
                self.assertEqual(report._recommended_action(hit.to_dict()), 0)
                text = self.summary([hit], gap=True)
                self.assertIn("reference-only", text)
                self.assertIn("unvisited bookmark", text)
                self.assertIn("does not clear the device", text)
                self.assertIn("WHAT COULD NOT BE CHECKED", text)
                self.assertIn("synthetic profile could not be read", text)

    def test_mixed_results_use_strongest_action_and_keep_gaps(self):
        weak = self.hit("vuln-driver", EV_ON_DISK, 1)
        strong = self.hit("sample", EV_ON_DISK, 2)
        reference = self.hit("delivery", EV_REFERENCED, 3)
        text = self.summary([weak, reference, strong], gap=True)
        self.assertIn("Seek expert help promptly", text)
        self.assertIn("WHAT COULD NOT BE CHECKED", text)
        self.assertLess(text.index(strong.indicator), text.index(weak.indicator))
        self.assertNotIn("This finding alone does not call for a spyware helpline referral", text)

    def test_multiple_weak_findings_do_not_upgrade_by_count(self):
        hits = [self.hit("delivery", EV_CONTACTED, number) for number in range(1, 10)]
        hits.extend((self.hit("vuln-driver", EV_ON_DISK, 10),
                     self.hit("candiru-ip", EV_DNS, 11)))
        self.assert_self_review(self.summary(hits))

    def test_support_is_available_independent_of_scan_and_no_ai_is_recommended(self):
        examples = ([], [self.hit("delivery", EV_REFERENCED)],
                    [self.hit("delivery", EV_CONTACTED)],
                    [self.hit("vuln-driver", EV_ON_DISK)],
                    [self.hit("sample", EV_ON_DISK)])
        for hits in examples:
            with self.subTest(evidence=[h.evidence for h in hits]):
                text = " ".join(report.render_human(self.document(hits, gap=True)).split())
                self.assertIn("qualified help regardless of this scan's result", text)
                self.assertIn("You do not need to complete self-checks first", text)
                self.assertIn("https://www.accessnow.org/help/", text)
                self.assertIn("intake instructions before sending private evidence", text)
                self.assertNotRegex(text, r"(?i)\b(?:AI|ChatGPT|LLM)\b")

    def test_human_routing_preserves_machine_evidence(self):
        doc = self.document([self.hit("delivery", EV_DNS),
                             self.hit("vuln-driver", EV_ON_DISK, 2)], gap=True)
        before = copy.deepcopy(doc)
        report.render_summary(doc)
        report.render_human(doc)
        self.assertEqual(doc, before)


if __name__ == "__main__":
    unittest.main()
