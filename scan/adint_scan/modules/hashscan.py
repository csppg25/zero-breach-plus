"""Hunt known sample hashes across the user-writable parts of this machine.

Citizen Lab (and others) publish SHA-256 hashes for the Windows payloads this
infrastructure delivers. Hashing every file on C: would take hours, so this
scans the locations an implant DLL actually lands in, plus anything the user
downloaded, and compares each file's digest against the sample hashes carried in
the IOC set.

A clean result means "none of these exact files are in these locations" - nothing
more. Each sample is one build; another victim's payload would hash differently,
which is why a clean hash scan is never a clean bill of health (D1/D3).

Contract: defines NAME and run(ctx) -> ModuleResult. Read-only, stdlib only, no
network (D2) - hashing a local file resolves nothing.
"""

from __future__ import annotations

import hashlib
import io
import os

from ..result import Hit, ModuleResult, EV_ON_DISK
from ..localpaths import path_problem, walk_local

NAME = "hash"

# Only file types a payload plausibly ships as. Keeps the walk cheap and avoids
# hashing the user's documents and media for no reason.
EXTS = (".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr", ".tmp", ".dat", ".bin", ".ax")

# Files larger than this are almost certainly not the implant; skipping them
# (counted as skipped, never as clean) keeps the scan from stalling on big blobs.
MAX_BYTES = 120 * 1024 * 1024

# Directory names pruned from the walk: browser/code caches, dependency trees and
# the Windows component store - huge, noisy, and not where an implant DLL lands.
PRUNE_DIRS = (
    "cache", "cache_data", "gpucache", "code cache", "node_modules",
    ".git", "servicepackfiles", "winsxs",
)


def _roots():
    """The user-writable locations an implant actually drops into, filtered to
    those that exist on this host. Matches the proof-of-concept exactly."""
    user = os.path.expanduser("~")
    roots = [
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("PROGRAMDATA", ""),
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Documents"),
        r"C:\Users\Public",
    ]
    # De-duplicate by resolved, case-normalised path, then drop any root that is
    # nested inside another. %TEMP% is %LOCALAPPDATA%\Temp on a default install,
    # so without this every file under Temp is hashed twice - inflating the
    # coverage counts and reporting one real sample as two separate hits.
    resolved = []
    for raw in roots:
        if not raw:
            continue
        # Do not resolve links or test existence before the locality guard.
        norm = os.path.normcase(os.path.normpath(raw))
        if norm not in resolved:
            resolved.append(norm)
    kept = []
    for r1 in resolved:
        if any(r1 != r2 and r1.startswith(r2 + os.sep) for r2 in resolved):
            continue  # r1 lives inside another root; walking that one covers it
        kept.append(r1)
    return kept


def _sha256(full):
    """SHA-256 of a file, read in 1 MiB chunks so a large file never loads whole
    into memory. Returns (hex_digest, size) or raises OSError for the caller to
    count as skipped."""
    problem = path_problem(full)
    if problem:
        raise PermissionError(13, problem, full)
    size = os.path.getsize(full)
    h = hashlib.sha256()
    with io.open(full, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest(), size


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Build the hex-digest -> Indicator map once so each file is a single dict
    # lookup. The hashes come from the IOC set, never hardcoded (ctx.iocs.hashes).
    targets = {ind.value: ind for ind in ctx.iocs.hashes}

    # D3: with nothing to compare against we cannot claim CLEAN. State the gap
    # and stop - an empty target set is UNKNOWN for this check, not clean.
    if not targets:
        r.could_not_run("hash-compare", "no sample hashes in the indicator set")
        return r

    ctx.emit("[hash] looking for {} known sample hash(es)".format(len(targets)))

    for root in _roots():
        problem = path_problem(root)
        if problem:
            r.could_not_run("root:" + root, problem)
            continue
        if not os.path.isdir(root):
            continue
        # The full path, not the basename: %TEMP% and %SystemRoot%\Temp both end
        # in "Temp", and two roots collapsing to one name would make the check
        # list lie about what was actually covered.
        #
        # The verdict for this root is decided AFTER the walk, not before it.
        # Marking it as a check that ran up front meant a root where every
        # candidate file failed to open still counted as a clean, completed
        # check: nothing was fingerprinted, nothing was reported, and the scan
        # said CLEAN with no gap. A file that could not be read has not been
        # cleared of anything (D3).
        ctx.emit("[hash] scanning {} ...".format(root))
        tally = {"hashed": 0, "candidates": 0, "unreadable": 0}

        def _walk_err(exc, _r=r, _t=tally):
            # An unreadable subtree would otherwise vanish silently from os.walk.
            _r.skipped += 1
            _t["unreadable"] += 1

        for dirpath, dirs, files in walk_local(root, onerror=_walk_err):
            # Prune noisy / huge subtrees in place so os.walk never descends them.
            dirs[:] = [d for d in dirs if d.lower() not in PRUNE_DIRS]
            for fn in files:
                if not fn.lower().endswith(EXTS):
                    continue
                full = os.path.join(dirpath, fn)
                tally["candidates"] += 1
                try:
                    problem = path_problem(full)
                    if problem:
                        raise PermissionError(13, problem, full)
                    size = os.path.getsize(full)
                    # Over the size cap: skipped, not clean (D-never-crash).
                    if size > MAX_BYTES:
                        r.skipped += 1
                        tally["unreadable"] += 1
                        continue
                    digest, size = _sha256(full)
                except OSError:
                    # Locked / permission-denied / unreadable: skip and continue.
                    r.skipped += 1
                    tally["unreadable"] += 1
                    continue

                tally["hashed"] += 1
                r.checked += 1
                r.submetrics["files_hashed"] = r.submetrics.get("files_hashed", 0) + 1
                r.submetrics["bytes_hashed"] = r.submetrics.get("bytes_hashed", 0) + size

                ind = targets.get(digest)
                if ind is not None:
                    # EV_ON_DISK is the whole point: a file whose fingerprint
                    # matches a published sample is conclusive. Without an
                    # evidence grade the report defaulted it to "referenced" and
                    # told the reader it was "probably not a sign of compromise" -
                    # over a known spyware binary sitting on their disk.
                    r.add_hit(Hit(
                        indicator=digest,
                        location=full,
                        detail="this file's SHA-256 matches a published sample: "
                               + ind.value,
                        tier=ind.tier,
                        confidence=ind.confidence,
                        source=ind.source,
                        evidence=EV_ON_DISK,
                    ))
                    ctx.emit("[hash] !! MATCH {} ({})".format(full, ind.value))

        # Now say honestly what this root amounted to.
        name = "root:" + root
        if tally["hashed"]:
            r.ran(name)
            if tally["unreadable"]:
                r.could_not_run(
                    name + " (partial)",
                    "{} of {} candidate file(s) under this root could not be "
                    "read or were too large to fingerprint, so they were not "
                    "compared against the known hashes".format(
                        tally["unreadable"], tally["candidates"]))
        elif tally["candidates"] or tally["unreadable"]:
            # Candidates existed but not one could be fingerprinted: this root
            # was not searched at all, however many files it holds.
            r.could_not_run(
                name,
                "no file under this root could be fingerprinted ({} candidate "
                "file(s) unreadable)".format(tally["unreadable"]))
        else:
            # Walked cleanly, held nothing to fingerprint. Genuinely covered.
            r.ran(name)

    return r
