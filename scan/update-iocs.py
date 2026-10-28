#!/usr/bin/env python3
"""Refresh the indicator list from the project repository.

WHY THIS IS A SEPARATE SCRIPT, not part of the scanner. The scanner's strongest
guarantee is that it NEVER touches the network: it cannot be made to resolve or
contact an indicator, and that is enforced and tested. Putting an update feature
inside it would weaken that guarantee and the claim built on it. So updating is a
deliberate, separate act you run yourself, on a tool that plainly does reach the
network and does nothing else.

WHAT IT DOES
  Downloads the current indicator file from the project repo over HTTPS, checks
  it against a published SHA-256, confirms it actually parses as a valid, non-empty
  indicator set, shows you exactly what changed, and - only if you pass --apply -
  replaces your local copy. A dry run by default.

THE TRUST MODEL, STATED HONESTLY. This is a security tool for people who may be
targeted, so be clear about what the check does and does not prove:
  - HTTPS with certificate verification proves the bytes came from GitHub over an
    encrypted, authenticated channel. This is the same trust you place in GitHub
    when you download the tool in the first place.
  - The published SHA-256 catches a corrupted or truncated download. It does NOT,
    on its own, prove authenticity, because it is served from the same place as
    the file.
  - The new list is loaded and validated before it can replace your copy, so a
    malformed or empty download can never silently wipe out your indicators.
  - Tagged release artifacts have detached GPG signatures; see SIGNING.md.
    This updater does not verify signatures, and the signed release manifest
    does not authenticate later development-branch downloads. Do not treat its
    SHA-256 check as independent publisher authentication.

  For reproducibility, download a tagged release and compare its published hash
  with a build from that same tag.

USAGE
    python update-iocs.py                 # dry run: fetch, verify, show the diff
    python update-iocs.py --apply         # also replace the local indicator file
    python update-iocs.py --url <base>    # use a different base URL (e.g. a mirror)

Standard library only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import ssl
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from adint_scan.iocs import IocError, load  # noqa: E402

DEFAULT_BASE = ("https://raw.githubusercontent.com/interplains/zero-breach/"
                "main/iocs/")
IOC_NAME = "adfection_iocs.txt"
LOCAL_IOC = os.path.join(os.path.dirname(HERE), "iocs", IOC_NAME)


def _fetch(url, timeout=30):
    """Fetch a URL over HTTPS with certificate verification on. Returns bytes."""
    if not url.lower().startswith("https://"):
        raise SystemExit("refusing to fetch over a non-HTTPS URL: {}".format(url))
    ctx = ssl.create_default_context()  # verifies the certificate chain + hostname
    req = urllib.request.Request(url, headers={"User-Agent": "adint-scan-update"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def _index(path):
    """(value -> (tier, confidence, source), curated date, count) for one file.

    The metadata travels alongside the values because an upstream correction
    that retiers an indicator, downgrades its confidence or fixes its citation
    changes what the scanner tells you about a hit, even though no indicator
    value moved. Comparing values alone made those corrections invisible and
    unappliable.
    """
    s = load(path)
    meta = {i.value: (i.tier, i.confidence, i.source) for i in s.indicators}
    return meta, s.asof, len(s)


_FIELDS = ("tier", "confidence", "source")


def _describe_change(old_meta, new_meta):
    """"tier=a -> b, source=c -> d" for only the fields that actually moved."""
    parts = []
    for name, was, now in zip(_FIELDS, old_meta, new_meta):
        if was != now:
            parts.append("{}={} -> {}".format(name, was or "(none)",
                                              now or "(none)"))
    return ", ".join(parts)


def main(argv=None):
    p = argparse.ArgumentParser(description="Refresh the indicator list (dry run "
                                            "unless --apply).")
    p.add_argument("--apply", action="store_true",
                   help="replace the local indicator file if the new one is valid")
    p.add_argument("--url", default=DEFAULT_BASE,
                   help="base URL to fetch from (must end in /)")
    p.add_argument("--local", default=LOCAL_IOC,
                   help="path to the local indicator file to compare/replace")
    args = p.parse_args(argv)

    base = args.url if args.url.endswith("/") else args.url + "/"

    # 1. Download the indicator file and its published hash.
    try:
        print("fetching {}{} ...".format(base, IOC_NAME))
        data = _fetch(base + IOC_NAME)
        print("fetching published SHA-256 ...")
        published = _fetch(base + IOC_NAME + ".sha256").decode("ascii",
                                                               "replace").split()[0].strip().lower()
    except Exception as exc:
        print("error: download failed: {}".format(exc), file=sys.stderr)
        return 1

    # 2. Integrity: the bytes must match the published hash.
    got = hashlib.sha256(data).hexdigest()
    if got != published:
        print("error: downloaded file does not match the published SHA-256.\n"
              "  published: {}\n  got:       {}\n"
              "Not touching your local file.".format(published, got),
              file=sys.stderr)
        return 1
    print("SHA-256 verified: {}".format(got))

    # 3. Validity: it must parse as a non-empty indicator set BEFORE it can
    #    replace anything. A truncated or malformed download is refused here.
    tmp = tempfile.mkdtemp(prefix="adint_update_")
    newfile = os.path.join(tmp, IOC_NAME)
    with io.open(newfile, "wb") as fh:
        fh.write(data)
    try:
        new_meta, new_asof, new_count = _index(newfile)
    except IocError as exc:
        print("error: the downloaded file is not a valid indicator set ({}). "
              "Not touching your local file.".format(exc), file=sys.stderr)
        return 1
    print("downloaded list is valid: {} indicators".format(new_count))

    # 4. Diff against the local copy so the change is never silent.
    if os.path.exists(args.local):
        old_meta, old_asof, old_count = _index(args.local)
    else:
        old_meta, old_asof, old_count = {}, None, 0
        print("(no local indicator file at {} yet)".format(args.local))

    added = sorted(set(new_meta) - set(old_meta))
    removed = sorted(set(old_meta) - set(new_meta))
    changed = sorted(v for v in set(new_meta) & set(old_meta)
                     if new_meta[v] != old_meta[v])
    asof_changed = old_count and new_asof != old_asof
    print("\nchange since your copy: +{} new, -{} removed, ~{} changed "
          "(you have {}, repo has {})"
          .format(len(added), len(removed), len(changed), old_count, new_count))
    if asof_changed:
        print("  curation date: {} -> {}".format(old_asof or "(none)",
                                                 new_asof or "(none)"))
    for v in added[:40]:
        print("  + {}".format(v))
    if len(added) > 40:
        print("  + ... and {} more".format(len(added) - 40))
    for v in removed[:40]:
        print("  - {}".format(v))
    if len(removed) > 40:
        print("  - ... and {} more".format(len(removed) - 40))
    for v in changed[:40]:
        print("  ~ {}: {}".format(v, _describe_change(old_meta[v], new_meta[v])))
    if len(changed) > 40:
        print("  ~ ... and {} more".format(len(changed) - 40))

    if not added and not removed and not changed and not asof_changed:
        print("\nYour indicator list is already up to date.")
        return 0

    # 5. Apply only on explicit request.
    if not args.apply:
        print("\nThis was a dry run. Re-run with --apply to replace:\n  {}"
              .format(args.local))
        return 0

    # Write beside the destination and rename over it. Opening the destination
    # directly truncates it first, so an interruption or a failed write at that
    # moment leaves a targeted person with no usable indicator list at all -
    # and the scanner refuses to run without one. os.replace is atomic on both
    # Windows and POSIX, and the temp file is in the same directory so the
    # rename cannot cross a filesystem boundary.
    tmp_path = None
    try:
        dest = os.path.abspath(args.local)
        fd, tmp_path = tempfile.mkstemp(prefix=".adint_iocs_",
                                        dir=os.path.dirname(dest) or ".")
        with io.open(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, dest)
        tmp_path = None  # ownership handed to the destination
    except OSError as exc:
        print("error: could not write {}: {}".format(args.local, exc),
              file=sys.stderr)
        return 1
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass  # a leftover temp file is not worth failing the update over
    print("\nupdated {} ({} indicators).".format(args.local, new_count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
