# Contributing

Thank you for helping. This tool is run by people at real risk, so a few rules are
strict — they are what keep it trustworthy.

## Running the tests

Standard library only; nothing to install.

```
cd scan && python -m unittest discover -s tests
```

Every change must keep the suite green. New behaviour needs a test.

Before publishing, run `python tools/release_check.py --require-patterns` in
the virtual environment with the pinned optional engine installed. This builds
and tests the download against controlled fixtures without scanning your own
browser profiles. See [TESTING.md](TESTING.md) for setup, website checks, scope
and the short release checklist.

## Rebuilding the generated files

The STIX/MISP feeds, the blocklists, the indicator checksum and the single-file
build are all generated from `iocs/adfection_iocs.txt`. After changing indicators,
regenerate everything with one command and commit the result:

```
python build/build.py
```

The build is deterministic: a fresh clone produces a byte-identical `zero-breach.py`.
CI fails if the committed artifacts are out of date, or if the build is not
reproducible.

## Adding indicators — read this first

A bad indicator is worse than a missing one: a false match can send an innocent
person to a crisis helpline. So:

- **Only attacker-controlled infrastructure.** Never add a compromised victim
  site, and never add a domain that is, or could be, a real organisation's own
  domain. When in doubt, leave it out.
- **Verify against the primary report**, not news coverage. Put the source in the
  fourth column.
- **No IP addresses from old reporting.** Cloud IPs get reassigned to innocent
  tenants; an undated IP match is noise. The existing `candiru-ip` tier carries
  this caveat.
- **Hashes must be SHA-256.** The scanner computes SHA-256; a SHA-1 would be
  misread as a domain.
- **Update the `# as-of:` date** in the indicator file header when you change the
  set, and rerun `build/build.py`.

## Design rules the code is held to

These are enforced by tests, not convention. A change that breaks one will fail CI.

- **Never contact an indicator.** The scan's Python socket guard blocks direct
  DNS and network calls. It is not an OS network sandbox: POSIX network mounts
  and concurrent filesystem changes require OS isolation for strict offline use.
  The network feature, `update-iocs.py`, is a separate script, never invoked
  during a scan.
- **Measured, never inferred.** A check that could not run is a reported gap, never
  a clean result.
- **Query only what is needed.** Cookie queries select host metadata and
  timestamps, not values. Temporary snapshots copy complete database bytes;
  the scanner does not decrypt browser credentials.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a
  finding. Alarms that mean nothing teach people to ignore the tool.
- **Read-only, no administrator, no telemetry, no third-party dependencies,
  Python 3.8+.**

## Style

Match the surrounding code. Comments explain *why*, not *what*. Keep the plain
language of the report text — a frightened non-technical person reads it.

## Questions

Not sure about something, or want to talk through a change before you build it? Reach the project on **Telegram** — https://t.me/+t9gq13mSKcE4NGI0.
