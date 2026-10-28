#!/usr/bin/env python3
"""Emit a MISP event (JSON) from the curated IOC file.

Why MISP: the victims in this campaign were institutions — the ICC, the IAEA,
Al Jazeera. Institutions deploy by policy, not by 400 people installing a browser
extension (DESIGN.md). One newsroom admin importing one MISP event protects
everyone behind that gateway.

Usage:
    python emit_misp.py [--iocs ../iocs/adfection_iocs.txt] [--out ../dist/adfection.misp.json]

No network access. Reads one local file, writes one local file.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scan"))

from adint_scan import iocs as iocmod  # noqa: E402

NAMESPACE = uuid.UUID("6f0b4a2e-5d1c-4f3b-9a7e-adf3c70f1001")

CITIZENLAB_URL = ("https://citizenlab.ca/research/"
                  "how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/")

# Per-indicator provenance: publisher, report title, publication date, report URL.
# Older campaign entries remain historical; publication is not a currency check.
SOURCES = {
    'citizenlab-adfection-2026': (
        'The Citizen Lab',
        'Exposing AdFection: How Discover-Tech Turned Targeted Ads Into a Pipeline for Zero-Click Mercenary Spyware',
        '2026-10-15',
        'https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/',
    ),
    'recordedfuture-2025-08': (
        'Recorded Future (Insikt Group)',
        "Tracking Candiru's DevilsTongue Spyware in Multiple Countries (CTA-2025-0805)",
        '2025-08-05',
        'https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware',
    ),
    'citizenlab-candiru-2021': (
        'The Citizen Lab',
        'Hooking Candiru',
        '2021-07-15',
        'https://citizenlab.ca/research/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/',
    ),
    'eset-swc-2021': (
        'ESET',
        'Strategic web compromises in the Middle East with a pinch of Candiru',
        '2021-11-16',
        'https://www.welivesecurity.com/2021/11/16/strategic-web-compromises-middle-east-pinch-candiru/',
    ),
    'avast-2022': (
        'Avast / Gen',
        'The Return of Candiru: Zero-days in the Middle East',
        '2022-07-21',
        'https://www.gendigital.com/blog/insights/research/the-return-of-candiru-zero-days-in-the-middle-east',
    ),
    'confiant-adint-2026': (
        'Confiant',
        'ADINT: Weaponized Ad Tech for Zero-Click Spyware and Mass Identity Vacuuming',
        '2026-10-15',
        'https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming',
    ),
    'microsoft-devilstongue-2021': (
        'Microsoft',
        'Protecting customers from a private-sector offensive actor using 0-day exploits and DevilsTongue malware',
        '2021-07-15',
        'https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/',
    ),
    'citizenlab-catalangate-2022': (
        'The Citizen Lab',
        'CatalanGate: Extensive Mercenary Spyware Operation against Catalans Using Pegasus and Candiru',
        '2022-04-18',
        'https://citizenlab.ca/research/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/',
    ),
    'google-tag-candiru-2021': (
        'Google Threat Analysis Group',
        'How we protect users from 0-day attacks',
        '2021-07-14',
        'https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks/',
    ),
    'amnesty-candiru-indonesia-2024': (
        'Amnesty International Security Lab',
        'A Web of Surveillance: Unravelling a murky network of spyware exports to Indonesia',
        '2024-05-01',
        'https://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/',
    ),
}


def _citation(source_key: str) -> str:
    """One attribute's real citation, for its comment line.

    An unmapped key is emitted verbatim so a consumer can see which report they
    have to go and find; attributing it to the Citizen Lab instead would be a
    false citation in a file other people act on.
    """
    cite = SOURCES.get(source_key)
    if not cite:
        return source_key or "source unspecified"
    name, title, date, _url = cite
    return "{}, {}, {}".format(name, title, date)

# MISP attribute type per inferred indicator type.
MISP_TYPE = {
    iocmod.TYPE_DOMAIN: "domain",
    iocmod.TYPE_IP: "ip-dst",
    iocmod.TYPE_SHA256: "sha256",
}

# Which MISP object-relation category each tier belongs in.
MISP_CATEGORY = {
    "cc": "Network activity",
    "validator": "Network activity",
    "delivery": "Network activity",
    "historical": "Network activity",
    "sample": "Payload delivery",
    # Legitimate signed software this actor abuses: a file artifact found on a
    # host, not a payload this campaign delivers.
    "vuln-driver": "Artifacts dropped",
    "candiru": "Network activity",
    "candiru-ip": "Network activity",
}

# to_ids says "this is safe to turn into a detection rule". Delivery-tier ad
# infrastructure is deliberately NOT to_ids: an ad impression is not proof of
# infection, and shipping it as a detection signature would bury analysts in
# false positives and teach them to ignore the feed (D4, precision over coverage).
# `candiru` domains are included: they are attributed attack infrastructure with
# distinctive names, so a detection rule on them is defensible.
# `candiru-ip` is deliberately EXCLUDED. Cloud IPs from a 2025 report are very
# likely reassigned, and shipping 109 of them as detection signatures would
# generate alerts on innocent tenants and teach analysts to mute the feed.
# `vuln-driver` is deliberately EXCLUDED. It is legitimately signed software that
# ships with real products, so turning its hash into a detection signature alerts
# on every clean machine that uses that hardware (D4, precision over coverage).
# It is still published - with its tier - so an analyst can hunt it deliberately.
TO_IDS_TIERS = {"cc", "validator", "sample", "candiru"}


def build_event(ioc_set: iocmod.IocSet, now: datetime.datetime) -> dict:
    date = now.strftime("%Y-%m-%d")
    stamp = str(int(now.timestamp()))

    attributes = []
    for ind in ioc_set.indicators:
        misp_type = MISP_TYPE.get(ind.type)
        if not misp_type:
            continue
        attributes.append({
            "uuid": str(uuid.uuid5(NAMESPACE, "misp-attr:" + ind.value)),
            "type": misp_type,
            "category": MISP_CATEGORY.get(ind.tier, "Network activity"),
            "value": ind.value,
            "to_ids": ind.tier in TO_IDS_TIERS,
            "timestamp": stamp,
            "comment": "tier={} confidence={} ({})".format(
                ind.tier, ind.confidence, _citation(ind.source)),
            "Tag": [
                {"name": 'adint:tier="{}"'.format(ind.tier)},
                {"name": 'adint:confidence="{}"'.format(ind.confidence)},
                {"name": 'adint:source="{}"'.format(
                    ind.source or "unspecified")},
            ],
        })

    # Sorted so the event is byte-identical on every build.
    sources_used = []
    for key in sorted({i.source or "" for i in ioc_set.indicators}):
        entry = {"key": key or "unspecified", "citation": _citation(key)}
        cite = SOURCES.get(key)
        if cite and cite[3]:
            entry["url"] = cite[3]
        sources_used.append(entry)

    return {
        "Event": {
            "uuid": str(uuid.uuid5(NAMESPACE, "misp-event:adfection")),
            "info": "AdFection / Discover-Tech / Candiru — zero-click spyware "
                    "delivered through real-time ad bidding",
            "date": date,
            "timestamp": stamp,
            # 2 = "Possibly false" is wrong here; 1 = Confirmed for primary-sourced
            # indicators read out of the report body.
            "analysis": "2",
            "threat_level_id": "1",
            "published": False,
            "Attribute": attributes,
            "Tag": [
                {"name": 'type:OSINT'},
                {"name": 'misp-galaxy:mercenary-spyware="Candiru"'},
                {"name": 'adint:campaign="AdFection"'},
            ],
            "Object": [],
            "extra": {
                "source": "The Citizen Lab, 'Exposing AdFection' (2026-10-15) and "
                          "Confiant, 'ADINT' (2026-10-15).",
                "source_url": CITIZENLAB_URL,
                # The event spans several researchers' reports, so the whole
                # roster is listed here and each attribute names its own one.
                # An importer that only reads the event header must not come
                # away believing one team published all of this.
                "sources": sources_used,
                "attribution_note": "Neither The Citizen Lab nor Confiant is "
                                    "affiliated with this tool or endorses it. "
                                    "Their report is the source; the tool is not "
                                    "theirs.",
                "caveat": "An ad impression from the delivery-tier infrastructure "
                          "is NOT proof of infection. The validator server decided "
                          "per device whether to proceed. A hit means investigate.",
            },
        }
    }


def main(argv=None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description="Emit a MISP event from the IOC file.")
    p.add_argument("--iocs", default=os.path.join(here, "..", "iocs",
                                                  "adfection_iocs.txt"))
    p.add_argument("--out", default=os.path.join(here, "..", "dist",
                                                 "adfection.misp.json"))
    args = p.parse_args(argv)

    ioc_set = iocmod.load(args.iocs)
    # Deterministic: use the committed 'as-of' date, not the wall clock, so the
    # event is byte-identical on every build. It MUST be UTC-aware - the event's
    # integer timestamp comes from .timestamp(), which interprets a naive
    # datetime in the machine's LOCAL timezone, so a naive stamp made the MISP
    # file differ between a Windows build and a UTC CI runner.
    stamp = (datetime.datetime.strptime(ioc_set.asof, "%Y-%m-%d").replace(
                 tzinfo=datetime.timezone.utc)
             if ioc_set.asof else datetime.datetime.now(datetime.timezone.utc))
    event = build_event(ioc_set, stamp)

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(event, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    attrs = event["Event"]["Attribute"]
    to_ids = sum(1 for a in attrs if a["to_ids"])
    print("wrote {}".format(out))
    print("  {} attributes, {} marked to_ids (detection-safe tiers only)".format(
        len(attrs), to_ids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
