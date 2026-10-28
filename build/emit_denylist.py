#!/usr/bin/env python3
"""Emit DNS/ad blocklists from the curated IOC file.

The protection The Citizen Lab recommends against this campaign is to block ad
delivery. These lists turn the indicator set into something a person can actually
load into the places that do the blocking: a phone's or router's DNS filter, a
Pi-hole or AdGuard Home, or a browser content blocker. One curated dataset, the
formats people's tools actually accept.

Which indicators go in a BLOCKLIST, and which do NOT:
  - Reviewed domains are included, except explicit exclusions below. Historical
    attribution does not establish current ownership: a domain may have expired,
    been reassigned, or also support legitimate activity. Rules are reversible,
    but blocking can still cause disruption.
  - IP addresses are DELIBERATELY EXCLUDED. Almost all of them are shared cloud
    addresses (Vultr/DigitalOcean) that are very likely reassigned to innocent
    tenants by now; a DNS blocklist cannot carry an IP anyway, and null-routing a
    shared cloud IP would break unrelated sites. A hit on a dated log is the only
    place an old IP is meaningful, which is the scanner's job, not a blocklist's.
  - Sample hashes are excluded (not a network indicator).
  - Historical domains ARE included by default but can be dropped with
    --no-historical: they are from older campaigns and some may have lapsed and
    been re-registered, so a cautious deployer may not want them in a live filter.

Usage:
    python emit_denylist.py [--iocs ../iocs/adfection_iocs.txt] [--outdir ../dist]
                            [--no-historical]

No network access. Reads one local file, writes several local files.
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scan"))

from adint_scan import iocs as iocmod  # noqa: E402

SOURCE_NOTE = ("AdFection / Candiru indicators. Curated from public reporting "
               "(The Citizen Lab, Confiant, Recorded Future, Microsoft, ESET, "
               "Avast, Google TAG, Amnesty Security Lab). Public domain "
               "(CC0). Blocking is a stopgap; it is not proof of anything and "
               "does not detect infection. https://github.com/interplains/zero-breach")

# Scanner evidence and live blocking have different membership decisions. Keep
# adtimizer.co in the scanner's historical evidence set, but block only the named
# operational hosts: Citizen Lab records Adtimizer's denial of involvement in
# Discover-Tech's separate infrastructure. A blanket rule can affect other uses.
BLOCKLIST_EXCLUSIONS = {
    "adtimizer.co": "Only named Discover-Tech operational subdomains are blocked.",
}

# Never promote shared hosting parents into rules when curating a tenant host.
SHARED_HOSTING_PARENTS = frozenset({
    "cloudfront.net", "amazonaws.com", "azure.com", "cloudapp.azure.com",
    "herokuapp.com",
})


def _domains(ioc_set, include_historical):
    out = []
    for ind in ioc_set.domains:
        if ind.value in BLOCKLIST_EXCLUSIONS or ind.value in SHARED_HOSTING_PARENTS:
            continue
        if ind.tier == "historical" and not include_historical:
            continue
        out.append(ind.value)
    # Deterministic and de-duplicated.
    return sorted(set(out))


def _asof_stamp(ioc_set):
    """The date to stamp into every generated list: the set's curated date.

    Stamping the wall clock made these files change every single day with no
    change to the source, so the build's artifact-drift check (build.py --check)
    failed on the day after the artifacts were committed. The '# as-of:' date is
    content, so every rebuild and every checkout agrees on it - the same reason
    the single-file build stamps it (build/bundle.py). Fall back to the file's
    own mtime for a set whose header carries no date.
    """
    if ioc_set.asof:
        return ioc_set.asof
    if ioc_set.source_mtime is not None:
        return datetime.date.fromtimestamp(ioc_set.source_mtime).isoformat()
    return datetime.date.today().isoformat()


def _header(fmt, comment, domains, include_historical, stamp):
    scope = "reviewed domains, all tiers" if include_historical else "historical tier excluded"
    lines = [
        "{} adint-scan denylist ({}) - generated {}".format(comment, fmt, stamp),
        "{} {}".format(comment, SOURCE_NOTE),
        "{} {} domains; {}. IP addresses are intentionally omitted (see the "
        "emitter).".format(comment, len(domains), scope),
        "{} Historical attribution does not establish current ownership or "
        "activity. Bare adtimizer.co is excluded; named operational hosts remain."
        .format(comment),
        "{}".format(comment),
    ]
    return lines


def write_hosts(domains, outdir, include_historical, stamp):
    """0.0.0.0 sinkhole file — works on Windows, macOS, Linux, Pi-hole, AdGuard Home."""
    lines = _header("hosts", "#", domains, include_historical, stamp)
    for d in domains:
        lines.append("0.0.0.0 {}".format(d))
    _write(os.path.join(outdir, "adfection.hosts.txt"), lines)


def write_adblock(domains, outdir, include_historical, stamp):
    """Adblock Plus / uBlock Origin / AdGuard filter syntax (||domain^)."""
    lines = _header("adblock", "!", domains, include_historical, stamp)
    lines.append("! Title: AdFection / Candiru blocklist")
    for d in domains:
        lines.append("||{}^".format(d))
    _write(os.path.join(outdir, "adfection.adblock.txt"), lines)


def write_dnsmasq(domains, outdir, include_historical, stamp):
    """dnsmasq address= form, for a router or a dnsmasq-based resolver."""
    lines = _header("dnsmasq", "#", domains, include_historical, stamp)
    for d in domains:
        lines.append("address=/{}/0.0.0.0".format(d))
    _write(os.path.join(outdir, "adfection.dnsmasq.conf"), lines)


def write_plain(domains, outdir, include_historical, stamp):
    """One domain per line — for NextDNS, Pi-hole regex/exact, or any tool that
    takes a bare domain list."""
    lines = _header("domains", "#", domains, include_historical, stamp)
    lines.extend(domains)
    _write(os.path.join(outdir, "adfection.domains.txt"), lines)


def _write(path, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote {} ({} lines)".format(path, len(lines)))


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description="Emit DNS/ad blocklists from the IOC file.")
    p.add_argument("--iocs", default=os.path.join(here, "..", "iocs",
                                                   "adfection_iocs.txt"))
    p.add_argument("--outdir", default=os.path.join(here, "..", "dist"))
    p.add_argument("--no-historical", action="store_true",
                   help="exclude older-campaign (historical) domains, which may "
                        "have lapsed and been re-registered")
    args = p.parse_args(argv)

    ioc_set = iocmod.load(args.iocs)
    include_historical = not args.no_historical
    domains = _domains(ioc_set, include_historical)
    if not os.path.isdir(args.outdir):
        os.makedirs(args.outdir)

    stamp = _asof_stamp(ioc_set)
    write_hosts(domains, args.outdir, include_historical, stamp)
    write_adblock(domains, args.outdir, include_historical, stamp)
    write_dnsmasq(domains, args.outdir, include_historical, stamp)
    write_plain(domains, args.outdir, include_historical, stamp)
    print("\n{} domains written in 4 formats (IPs and hashes excluded by design)."
          .format(len(domains)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
