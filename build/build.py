#!/usr/bin/env python3
"""Rebuild every generated artifact from the one indicator file, in order.

This is the single command that turns iocs/adfection_iocs.txt into everything
that ships: the STIX and MISP feeds, the DNS/ad blocklists, the indicator
checksum, and the single-file build. It is deterministic - run it on a fresh
checkout and you get byte-identical output - which is what lets anyone verify
that the published zero-breach.py was built from exactly this source.

Usage:
    python build/build.py            # regenerate dist/ and the standalone
    python build/build.py --check    # also fail if anything is now out of date

The standalone is written to dist/zero-breach.py. Its SHA-256 is printed at the
end; that is the value to publish in the release notes so people can verify their
download.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOC = os.path.join(ROOT, "iocs", "adfection_iocs.txt")
DIST = os.path.join(ROOT, "dist")
STANDALONE = os.path.join(DIST, "zero-breach.py")


def _run(script, *args):
    path = os.path.join(ROOT, "build", script)
    print("--- {} ---".format(script))
    subprocess.check_call([sys.executable, path, *args])


def _sha256(path):
    h = hashlib.sha256()
    with io.open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser(description="Rebuild all generated artifacts.")
    p.add_argument("--check", action="store_true",
                   help="exit non-zero if any artifact changed (for CI)")
    p.add_argument("--expect-version", metavar="X.Y.Z",
                   help="fail unless the package __version__ equals this. Run "
                        "with the release's own number when cutting a release, "
                        "so the single file can never again ship reporting a "
                        "different version than the tag (as v0.1.7 did).")
    args = p.parse_args(argv)

    if args.expect_version:
        init = io.open(os.path.join(ROOT, "scan", "adint_scan", "__init__.py"),
                       encoding="utf-8").read()
        import re as _re
        found = _re.search(r'__version__\s*=\s*"([^"]+)"', init)
        found = found.group(1) if found else "(unreadable)"
        if found != args.expect_version:
            print("\nERROR: package __version__ is {!r} but the release "
                  "being cut is {!r}. Update scan/adint_scan/__init__.py "
                  "before building.".format(found, args.expect_version),
                  file=sys.stderr)
            return 1
        print("version check: package reports {} as expected.".format(found))

    if not os.path.isdir(DIST):
        os.makedirs(DIST)

    # 1. Publish the indicator checksum (the updater verifies against this).
    digest = _sha256(IOC)
    with io.open(IOC + ".sha256", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("{}  adfection_iocs.txt\n".format(digest))
    print("iocs sha256: {}".format(digest))

    # 2. Regenerate every export from the one source.
    _run("emit_stix.py")
    _run("emit_misp.py")
    _run("emit_denylist.py")

    # 3. Build the deterministic single file.
    _run("bundle.py", ROOT, STANDALONE)

    sa_hash = _sha256(STANDALONE)
    print("\nstandalone: {}".format(STANDALONE))
    print("SHA-256   : {}".format(sa_hash))
    print("           ^ publish this in the release notes for people to verify.")

    if args.check:
        # Fail if the working tree now differs from what is committed - i.e.
        # someone changed the indicators but forgot to regenerate the artifacts.
        try:
            out = subprocess.check_output(
                ["git", "-C", ROOT, "status", "--porcelain",
                 "dist", "iocs/adfection_iocs.txt.sha256"],
                text=True)
        except (OSError, subprocess.CalledProcessError):
            print("(--check: git not available; skipping drift check)")
            return 0
        if out.strip():
            print("\nERROR: generated artifacts are out of date. Run "
                  "`python build/build.py` and commit the result:\n" + out,
                  file=sys.stderr)
            return 1
        print("\n--check: generated artifacts are up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
