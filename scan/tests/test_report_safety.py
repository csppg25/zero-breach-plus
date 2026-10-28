"""Human reports must not reintroduce live indicators through notes or gaps."""
import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adint_scan.iocs import Indicator, IocSet, TYPE_DOMAIN
from adint_scan.result import Hit, ModuleResult, EV_PERSISTENCE, EV_DNS
from adint_scan.report import build_document, render_human, render_summary, write_json


class TestReportSafety(unittest.TestCase):
    def test_dns_record_does_not_claim_endpoint_contact(self):
        domain = "review-indicator.invalid"
        iocs = IocSet([Indicator(domain, "delivery", "primary", TYPE_DOMAIN)],
                     "fixture", None)
        result = ModuleResult("host")
        result.add_hit(Hit(domain, "DNS log", "failed query", tier="delivery",
                           evidence=EV_DNS))
        text = render_human(build_document(iocs, [result], datetime.datetime.now()))
        self.assertIn("THIS INDICATOR APPEARS IN LOCAL DNS RECORDS", text)
        self.assertNotIn("THIS DEVICE CONTACTED", text)
        self.assertNotIn("server belonging to this network reached", text)
        self.assertIn("lookup may have failed", text)

    def test_all_human_fields_are_safe_and_json_stays_raw(self):
        domain = "review-indicator.invalid"
        other = "second-indicator.invalid"
        iocs = IocSet([Indicator(v, "cc", "primary", TYPE_DOMAIN)
                      for v in (domain, other)], "fixture", None)
        result = ModuleResult("host")
        raw_path = "\\\\" + domain + "\\share\\payload.exe"
        result.add_hit(Hit(domain, raw_path, "also references " + other,
                           tier="cc", evidence=EV_PERSISTENCE,
                           profile="https://" + domain + "/profile",
                           source="https://example.org/research"))
        result.note(raw_path)
        result.could_not_run("remote", "cannot read https://" + other)
        doc = build_document(iocs, [result], datetime.datetime.now())
        for render in (render_human, render_summary):
            human = render(doc)
            self.assertNotIn(domain, human)
            self.assertNotIn(other, human)
            self.assertIn("review-indicator[.]invalid", human)
        self.assertIn("https://example.org/research", render_human(doc))
        self.assertEqual(doc["modules"]["host"]["notes"][0], raw_path)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            write_json(doc, path)
            with open(path, encoding="utf-8") as stream:
                saved = json.load(stream)
        self.assertEqual(saved["modules"]["host"]["hits"][0]["indicator"], domain)
        self.assertFalse(any(key.startswith("_") for key in saved))


if __name__ == "__main__":
    unittest.main()
