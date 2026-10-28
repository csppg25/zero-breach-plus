# Optional Candiru file patterns: validation and limits

Zero Breach v0.1.3 adds an optional check to the existing scanner. The default
scan remains unchanged. This document records what the new mode checks, how it
was tested and where its results are limited.

## Scope

`--patterns` scans local file bytes with two unchanged published Candiru rules:
Microsoft's 2021 DevilsTongue hijack-DLL rule and Malpedia's automatically
generated DevilsTongue rule. The latter was derived from unpacked files or
memory dumps. A new date on a rule does not establish coverage of a new campaign.
Neither rule proves infection, execution, or coverage of every Candiru build.
This mode does not acquire or scan running memory, decrypt payloads, inspect
phone backups, or add Pegasus detection.

The default scanner still requires only Python's standard library. Pattern
scanning additionally requires Python 3.9+ and the pinned official YARA-X 1.21.0
wheel. `requirements-patterns.txt` pins all published wheel SHA-256 values and
rejects source builds. Install into a dedicated environment during setup:

```text
python -m venv .venv
<venv-python> -m pip install -r requirements-patterns.txt
<venv-python> scan/adint-scan.py --patterns
```

The scanner never installs packages, downloads rules, or contacts sample/IOC
servers. Without the requested engine it reports UNKNOWN with an explicit gap.
Python 3.8 remains supported for the default checks.

`--pattern-path ABSOLUTE_PATH` can be repeated to choose files or folders for
the pattern check. Without it, the check uses the existing file-hash roots.
It limits only the pattern check: browser, hash and host checks keep their
usual scope. `--quick` skips hashes but still runs explicitly requested patterns.
Relative, redirected and cloud-recall paths are refused. Windows UNC paths and
remote drives are refused. On POSIX systems, a network-mounted directory can
look like an ordinary absolute path and may be read; use operating-system
network isolation when strict offline operation is required. Files are eligible
regardless of extension. Per-file size and time limits, traversal and
total-byte limits, directory exclusions, unreadable files and other coverage
gaps are described in the module output. A limit is never treated as a completed
clean check.

The JSON evidence grade is `file-pattern`, separate from exact hash evidence
(`on-disk`). The human report asks for review and preserves rule authorship,
source and licence. Rule provenance and original texts are under
`third_party/candiru/`; these rules are not covered by the IOC feed's CC0 grant.

## Validation gate

**User-required release gate:** Before publishing this upgrade, remind the user
to switch to Astra and complete a final review of the changes, validation
evidence, remaining limitations and release artifacts. Do not publish before
that review. This gate was requested after the sample tests on 2026-10-19.

Before considering a release:

- Run default and optional-engine suites, source and standalone entry points,
  missing-engine/error/timeout cases, path and resource-limit cases.
- Verify deterministic builds and that ordinary files/fixtures stay unchanged.
- Check authentic, hash-verified Candiru files strictly inside the disposable
  VM. Download only inside that VM; disconnect acquisition networking before
  extracting/scanning. Never execute the samples or export them to the host,
  repository, backups or Docker image layers. Export only small structured
  results containing approved hashes, rule names and aggregate metrics.
- Measure false positives on a documented clean corpus. Harmless pattern
  fixtures prove integration and rule mechanics, not real malware sensitivity.
- Independently review the implementation and record all remaining gaps.

## Validation recorded on 2026-10-19

The authentic sample receipts certify candidate SHA-256
`d2aaaec5554d04e69db9700832e35d8e7f77aca6e962b31903683a1048e889a6`.
An Astra review then found that a pruned cache folder could be marked clean.
The candidate now records that omission as a coverage gap, with a regression
test. The change affects directory traversal, not the explicit-file rule scan
used for the sample receipts. Rebuild and record the final artifact hash before
publication. The Windows suite originally ran 267 tests with
no failures and one platform-permission skip; without the optional engine it
ran 267 tests with seven expected skips. The disposable Linux VM ran all 52
pattern/integration tests without failures or skips. A small clean corpus of
200 Debian files and 26 official Python Windows PE files produced no matches.

The reviewed release build is SHA-256
`1a1eb0e76cd2791349be9861840a5756940c3a950a134b5436bc7f9d1b50e3b8`.
After the prune correction and a Windows Python 3.12 file-metadata compatibility
fix, the Windows suite ran 269 tests with no failures and one permission skip;
without the optional engine it ran 269 tests with seven expected skips. The
release build changes the displayed version and help text, not the two rules
or file scanning logic. The signed final artifact and cross-platform CI must
still match this exact hash before publication.

Two hash-verified MalwareBazaar downloads were scanned as static bytes inside
the disconnected VM, without execution:

| SHA-256 | Published rule matched | Existing exact-hash coverage |
| --- | --- | --- |
| `255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8` | `win_devilstongue_auto` | Yes |
| `a550c64443d50c7863cf4b4e3c1d13714824938eac33691a580b6453374fd5be` | `MAL_DevilsTongue_HijackDll` | No |

The first hash has primary-source Candiru attribution. The second is tagged
DevilsTongue by MalwareBazaar and matches Microsoft's published rule; its
family attribution has not been independently corroborated by a primary source.
Both scans checked one file, skipped none, left the input unchanged and recorded
zero Python network attempts. The VM had no external network, host mounts or
shared folders. It has been removed; only sanitized results were exported.

These two positives and the small clean corpus demonstrate useful additional
coverage, not a measured detection rate or proof of broad Candiru coverage.
New native macOS execution, actual cloud placeholders and an adversarial
wall-clock engine-timeout case remain untested. At validation time the live
v0.1.2 release remained unchanged. Detailed local receipts are under
`findings/vm-lab/`.

## MVT integration assessment

MVT could power an optional phone-evidence mode in this same tool, but has not
been integrated in this candidate. It requires a supplied phone acquisition or
backup; it adds no desktop detection by itself. Current upstream requires
Python 3.10+ and does not officially support native Windows.

A safe adapter needs a pinned isolated worker, read-only inputs, controlled
config/output paths, operating-system network denial, disabled URL expansion
and update checks, no unreviewed plugins, and explicit coverage accounting.
The existing Python socket guard does not constrain a separate MVT process.
MVT writes configuration at import time and catches some module failures, so
an ordinary import/subprocess plus exit-code check would break our assumptions.
Its own licence and informed data-owner consent requirements must be retained.

Sources:
- https://github.com/mvt-project/mvt
- https://github.com/mvt-project/mvt/blob/main/pyproject.toml
- https://github.com/mvt-project/mvt/blob/main/docs/install.md
- https://docs.mvt.re/en/latest/iocs/
- https://license.mvt.re/1.1/
- https://github.com/VirusTotal/yara-x
