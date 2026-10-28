"""Reviewed Candiru source coverage, blocking scope and STIX update semantics."""
import contextlib
import datetime
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scan'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from adint_scan import iocs
from test_bundle_release import import_file


# Source-reviewed fixtures: literal domain spellings, independent of the IOC file.
ADDITIONS = {'amnesty-candiru-indonesia-2024': ['aqaf.net', 'gelora.org', 'nusantaraqurban.com'],
 'avast-2022': ['bad-shop.net',
                'bestcarent.org',
                'core-update.com',
                'datanalytic.org',
                'expertglobal.org',
                'only-music.net',
                'popsonglist.com',
                'querylight.net',
                'smartstand.org',
                'webs-update.com'],
 'citizenlab-candiru-2021': ['refugeeinternational.org',
                             'genderconference.org',
                             'un-asia.co',
                             'armenpress.net',
                             'tehrantimes.org',
                             'total-slovenia-news.net'],
 'citizenlab-catalangate-2022': ['stat.email', 'adtrack.link', 'cortana.cloud', 'rbtlnk.net'],
 'confiant-adint-2026': ['dtech.mtrtb.com',
                         'tekma.adtimizer.co',
                         'www.discover-tech.io',
                         'd8lmy5wyiokrq.cloudfront.net',
                         'd23625plpxg1yn.cloudfront.net',
                         'd39619tdxn6mhj.cloudfront.net',
                         'd2f4zpg1mgzwov.cloudfront.net',
                         'd1fzw0miu1r9rc.cloudfront.net',
                         'd19oo8r6k9oumb.cloudfront.net',
                         'd147nolwbekx2b.cloudfront.net',
                         'dcv2rnj2ograe.cloudfront.net',
                         'd1x4e580sn23dn.cloudfront.net',
                         'd2epnp0vokbtl7.cloudfront.net',
                         'pagead.trustlayersdk.com'],
 'google-tag-candiru-2021': ['lragir.org',
                             'armradio.org',
                             'asbares.com',
                             'armtimes.net',
                             'armlur.org',
                             'armenpress.org',
                             'hraparak.org',
                             'armtimes.org',
                             'hetq.org',
                             'lioiamcount.com',
                             'db-control-uplink.com',
                             'kidone.xyz',
                             'workaj.com',
                             'wordzmncount.com'],
 'microsoft-devilstongue-2021': ['noc-service-streamer.com',
                                 'fbcdnads.live',
                                 'hilocake.info',
                                 'backxercise.com',
                                 'winmslaf.xyz',
                                 'service-deamon.com',
                                 'online-affiliate-mon.com',
                                 'codeingasmylife.com',
                                 'kenoratravels.com',
                                 'weathercheck.digital',
                                 'colorpallatess.com',
                                 'library-update.com',
                                 'online-source-validate.com',
                                 'grayhornet.com',
                                 'johnshopkin.net',
                                 'eulenformacion.com']}
SOURCE_EXPECTATIONS = {'amnesty-candiru-indonesia-2024': ('Amnesty International Security Lab',
                                    '2024-05-01',
                                    'https://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/'),
 'avast-2022': ('Avast / Gen',
                '2022-07-21',
                'https://www.gendigital.com/blog/insights/research/the-return-of-candiru-zero-days-in-the-middle-east'),
 'citizenlab-adfection-2026': ('The Citizen Lab',
                               '2026-10-15',
                               'https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/'),
 'citizenlab-candiru-2021': ('The Citizen Lab',
                             '2021-07-15',
                             'https://citizenlab.ca/research/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/'),
 'citizenlab-catalangate-2022': ('The Citizen Lab',
                                 '2022-04-18',
                                 'https://citizenlab.ca/research/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/'),
 'confiant-adint-2026': ('Confiant',
                         '2026-10-15',
                         'https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming'),
 'eset-swc-2021': ('ESET',
                   '2021-11-16',
                   'https://www.welivesecurity.com/2021/11/16/strategic-web-compromises-middle-east-pinch-candiru/'),
 'google-tag-candiru-2021': ('Google Threat Analysis Group',
                             '2021-07-14',
                             'https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks/'),
 'microsoft-devilstongue-2021': ('Microsoft',
                                 '2021-07-15',
                                 'https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/'),
 'recordedfuture-2025-08': ('Recorded Future (Insikt Group)',
                            '2025-08-05',
                            'https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware')}


class TestFeedCuration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = iocs.load(str(ROOT / 'iocs/adfection_iocs.txt'))
        cls.deny = import_file('_curation_deny', ROOT / 'build/emit_denylist.py')
        cls.stix = import_file('_curation_stix', ROOT / 'build/emit_stix.py')
        cls.misp = import_file('_curation_misp', ROOT / 'build/emit_misp.py')

    @classmethod
    def tearDownClass(cls):
        for name in ('_curation_deny', '_curation_stix', '_curation_misp'):
            sys.modules.pop(name, None)

    def test_reviewed_additions_have_exact_source_and_evidence_role(self):
        self.assertEqual((len(self.data), len(self.data.domains), len(self.data.ips),
                          len(self.data.hashes)), (405, 292, 111, 2))
        self.assertEqual(sum(map(len, ADDITIONS.values())), 67)
        for source, names in ADDITIONS.items():
            for name in names:
                with self.subTest(domain=name):
                    ind = self.data.lookup(name)
                    self.assertIsNotNone(ind)
                    self.assertEqual(ind.source, source)
                    self.assertEqual(ind.type, iocs.TYPE_DOMAIN)
                    self.assertEqual(ind.tier, 'delivery' if source ==
                                     'confiant-adint-2026' else 'historical')
        for held in ('oiip.org', 'vfsglobal.fr', 'tekma-dmp.ai', 'webfx.cc',
                     'engagebay.cc', 'dl.nmcyclingexperience.com',
                     'supportcdn.web.app', 'vegmobile.com', 'cloudflare-dns.com',
                     'middleeasteye.net', 'tutanota.com'):
            self.assertIsNone(self.data.lookup(held), held)

    def test_live_membership_excludes_bare_domain_and_shared_hosting_parents(self):
        self.assertIsNotNone(self.data.lookup('adtimizer.co'))
        live = set(self.deny._domains(self.data, True))
        self.assertEqual(len(live), 291)
        self.assertNotIn('adtimizer.co', live)
        self.assertTrue({'dtech.adtimizer.co', 'noas.adtimizer.co',
                         'tekma.adtimizer.co'} <= live)
        # A future mistaken parent import must not become a global cloud block.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'parents.txt'
            path.write_text('\n'.join(
                name + '\tdelivery\tprimary\ttest'
                for name in ('cloudfront.net', 'amazonaws.com', 'azure.com',
                             'cloudapp.azure.com', 'herokuapp.com',
                             'tenant.cloudfront.net')), encoding='utf-8')
            self.assertEqual(self.deny._domains(iocs.load(str(path)), True),
                             ['tenant.cloudfront.net'])

    def test_four_formats_export_same_reviewed_names_and_historical_optout(self):
        for omit in (False, True):
            with self.subTest(no_historical=omit), tempfile.TemporaryDirectory() as tmp:
                args = ['--outdir', tmp]
                if omit:
                    args.append('--no-historical')
                with contextlib.redirect_stdout(io.StringIO()):
                    self.deny.main(args)
                def body(name):
                    return [line for line in (Path(tmp) / name).read_text(
                        encoding='utf-8').splitlines() if line and
                        not line.startswith(('#', '!'))]
                plain = set(body('adfection.domains.txt'))
                self.assertEqual(plain, {x.split()[1] for x in body('adfection.hosts.txt')})
                self.assertEqual(plain, {x[2:-1] for x in body('adfection.adblock.txt')})
                self.assertEqual(plain, {x.split('/')[1] for x in body('adfection.dnsmasq.conf')})
                self.assertEqual(len(plain), 161 if omit else 291)
                self.assertNotIn('adtimizer.co', plain)
                self.assertTrue(plain.isdisjoint(i.value for i in self.data.ips + self.data.hashes))
                for source, names in ADDITIONS.items():
                    if omit and source != 'confiant-adint-2026':
                        self.assertTrue(plain.isdisjoint(names))
                    else:
                        self.assertTrue(set(names) <= plain)
                if omit:
                    header = (Path(tmp) / 'adfection.domains.txt').read_text(encoding='utf-8')
                    self.assertIn('historical tier excluded', header)
                    self.assertNotIn('current campaign only', header)

    def test_stix_and_misp_citations_use_exact_publisher_date_and_url(self):
        now = datetime.datetime(2026, 10, 18)
        bundle = self.stix.build_bundle(self.data, now)
        indicators = {o['name']: o for o in bundle['objects'] if o['type'] == 'indicator'}
        event = self.misp.build_event(self.data, now)['Event']
        attrs = {a['value']: a for a in event['Attribute']}
        sources = {s['key']: s for s in event['extra']['sources']}
        self.assertEqual(self.stix.SOURCES, self.misp.SOURCES)
        self.assertEqual(set(sources), set(SOURCE_EXPECTATIONS))
        for key, (publisher, date, url) in SOURCE_EXPECTATIONS.items():
            self.assertEqual(sources[key]['url'], url)
            self.assertIn(date, sources[key]['citation'])
            for ind in self.data.indicators:
                if ind.source != key or ind.tier == 'vuln-driver':
                    continue
                ref = indicators[ind.value]['external_references'][0]
                self.assertEqual(ref['source_name'], publisher)
                self.assertEqual(ref['url'], url)
                self.assertIn(date, ref['description'])
                self.assertIn(date, attrs[ind.value]['comment'])
        driver = '6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5'
        self.assertNotIn(driver, indicators)
        self.assertFalse(attrs[driver]['to_ids'])

    def test_all_baseline_stix_ids_creation_and_valid_from_survive_update(self):
        history = json.loads((ROOT / 'build/stix-first-published.json').read_text(encoding='utf-8'))
        baseline_names = set(history['2026-10-18T00:00:00.000Z'])
        self.assertEqual(len(baseline_names), 338)
        baseline = iocs.IocSet([i for i in self.data.indicators if i.value in baseline_names],
                               'baseline', None)
        old = self.stix.build_bundle(baseline, datetime.datetime(2026, 10, 18))
        new = self.stix.build_bundle(self.data, datetime.datetime(2026, 10, 18))
        by_id = {o['id']: o for o in new['objects']}
        self.assertEqual(len(old['objects']), 676)
        for obj in old['objects']:
            with self.subTest(id=obj['id']):
                updated = by_id[obj['id']]
                self.assertEqual(updated['created'], '2026-10-18T00:00:00.000Z')
                if updated['type'] == 'indicator':
                    self.assertEqual(updated['valid_from'], '2026-10-18T00:00:00.000Z')
                for field in ('id', 'created', 'valid_from'):
                    self.assertEqual(obj.get(field), updated.get(field))
                self.assertGreater(updated['modified'], '2026-10-18T18:29:47.000Z')
                self.assertGreaterEqual(updated['modified'], updated['created'])
        added = set(history['2026-10-18T22:33:48.000Z'])
        self.assertEqual(len(added), 67)
        for obj in new['objects']:
            if obj.get('name') in added:
                self.assertEqual(obj['created'], '2026-10-18T22:33:48.000Z')
                self.assertEqual(obj['valid_from'], obj['created'])


if __name__ == '__main__':
    unittest.main()
