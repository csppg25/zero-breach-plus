# Security policy

Zero Breach is run by people who may be targeted by a state-grade adversary, so
its own integrity matters as much as what it detects.

## Reporting a problem

If you find a security issue in Zero Breach itself — a way to make it leak data,
contact the network during a scan, read more than it should, misreport a result,
or anything that could put a user at risk — please report it privately rather than
opening a public issue.

- Open a **private security advisory** on this repository (the "Security" tab →
  "Report a vulnerability"), or
- message the project on Telegram: https://t.me/+t9gq13mSKcE4NGI0

For a security report, prefer the private advisory; use Telegram if you cannot.

Please include what you found, how to reproduce it, and the impact. We will
acknowledge, investigate, and credit you if you wish.

## What is in scope

- The scanner reading, decrypting, or transmitting anything it should not.
- Any path that makes the scanner touch the network during a scan.
- A result that could be wrong in a way that misleads a user (a false "clean", a
  mislabelled severity, a missed gap).
- The update path (`scan/update-iocs.py`) accepting a tampered or unauthenticated
  indicator file.
- The build producing a file that does not match its source.

## What is not a vulnerability

- **A clean result is not a guarantee.** The tool states this itself. Spyware of
  this grade is built to defeat retrospective checks; "it did not find a real
  infection" is a known, documented limitation, not a bug.
- A false *alarm* on a benign indicator match is a tuning issue — useful to report
  as a normal issue, but not a security vulnerability.

## For users: verifying the tool

Do not run a security script on trust. Every release publishes the SHA-256 of
`zero-breach.py`, and the build is reproducible — you can rebuild the file from
source and confirm it matches. Release v0.1.2 also supplies detached GPG signatures
under ArchiveGenocide's established release key. Check the complete fingerprint
against the official publisher page before trusting a downloaded key. See
[SIGNING.md](SIGNING.md) and "Verifying what you downloaded" in the README.

## Handling indicators responsibly

The indicator set is curated to avoid false alarms against real people — it
excludes known compromised victim sites and ambiguous legitimate domains during
curation. Historical domains can later change ownership. If you believe an
indicator here is wrong, or would match legitimate traffic, that is worth
reporting: a false positive from this tool can send an
innocent person to a crisis helpline.
