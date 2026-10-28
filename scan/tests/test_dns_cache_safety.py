"""A hosts-file blocklist can populate DNS cache without any attempted lookup."""

import datetime
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adint_scan.context import ScanContext
from adint_scan.iocs import Indicator, IocSet, TYPE_DOMAIN
from adint_scan.modules import host
from adint_scan.report import build_document, render_human
from adint_scan.result import EV_DNS, ModuleResult


class TestPreloadedDnsBlocks(unittest.TestCase):
    def scan(self, rows):
        ctx = ScanContext(iocs=IocSet([
            Indicator("blocked.invalid", "cc", "primary", TYPE_DOMAIN),
            Indicator("other.invalid", "cc", "primary", TYPE_DOMAIN),
        ], "synthetic", None), emit=lambda _msg: None)
        result = ModuleResult("host")
        with patch.object(host, "_ps_json", return_value=(rows, "")), \
                patch.object(host, "_boot_time", return_value=("2026-10-18", "")):
            host._check_dns_cache(result, ctx)
        return ctx, result

    def test_preloaded_blocklist_does_not_create_a_finding_or_attempt(self):
        ctx, result = self.scan([{"Entry": "blocked.invalid", "Data": "0.0.0.0"}])
        doc = build_document(ctx.iocs, [result], datetime.datetime.now())
        human = render_human(doc)
        self.assertEqual(doc["verdict"]["hits_total"], 0)
        self.assertNotEqual(doc["verdict"]["status"], "INDICATORS_FOUND")
        self.assertIn("protective state", human)
        self.assertIn("without any lookup", human)
        self.assertNotIn("ATTEMPTED", human)

    def test_protective_entry_does_not_hide_a_separate_dns_record(self):
        _, result = self.scan([
            {"Entry": "blocked.invalid", "Data": "127.0.0.1"},
            {"Entry": "other.invalid", "Data": "192.0.2.10"},
        ])
        self.assertEqual(result.checked, 2)
        self.assertEqual(result.submetrics["dns_cache_blocked_indicators"], 1)
        self.assertEqual([(h.indicator, h.evidence) for h in result.hits],
                         [("other.invalid", EV_DNS)])


if __name__ == "__main__":
    unittest.main()
