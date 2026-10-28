# Module contract — build against this

Development extension: `ctx.patterns` explicitly enables the optional `patterns`
module; `ctx.pattern_paths` supplies absolute local paths for that module only.
The Windows host module supplies bounded `ctx.pattern_candidate_paths` from
local, user-writable per-user COM server registrations when pattern paths are
not explicitly selected; the pattern module rechecks each path before reading.
The default checks remain standard-library-only. The optional module uses the
pinned YARA-X engine without downloads, writes or sample execution. Its hits use
`file-pattern` evidence and `candiru-pattern` tier, never exact-hash claims.

Each scan module is a file in `adint_scan/modules/` that defines exactly:

```python
NAME = "browser"   # or "hash", "host", "deep"

def run(ctx) -> ModuleResult:
    ...
```

- `ctx` is `adint_scan.context.ScanContext`: `ctx.iocs` (an `IocSet`),
  `ctx.deep` (bool), `ctx.emit(str)` for progress (goes to stderr — never print
  to stdout from a module; stdout is the final human report).
- Return `adint_scan.result.ModuleResult`.

## IocSet (adint_scan/iocs.py) — what modules read

- `ctx.iocs.network_strings` → sorted lower-case list of domain + IP strings for
  substring matching in artifacts. **Never resolve or connect to these.**
- `ctx.iocs.hashes` → list of `Indicator` with `.value` (lower-case sha256).
- `ctx.iocs.lookup(value)` → the `Indicator` for a matched string, or None;
  use it to attach `.tier` / `.confidence` provenance to each Hit.

## ModuleResult (adint_scan/result.py) — how to report

- `r = ModuleResult(NAME)`
- On every hit: `r.add_hit(Hit(indicator=ioc, location=path, detail=ctx, tier=..., confidence=...))`
  — get tier/confidence from `ctx.iocs.lookup(ioc)`.
- `r.checked`, `r.skipped` are running integer counts (files/DBs examined; items skipped).
- `r.submetrics` is a dict of named counts for the report, e.g.
  `{"sqlite": 28, "blob": 44634}`.
- **Record each sub-check's fate (this is the D3 contract):**
  - `r.ran("dns-cache")` when a sub-check executed (even if it found nothing).
  - `r.could_not_run("dns-log", "operational log disabled")` when it could not.
  A module with any `could_not_run` becomes PARTIAL/UNKNOWN automatically — do
  NOT report a clean sub-check that never actually ran.
- `r.note("free text")` for extra context.

## Hard rules (doctrine)

- **D2 — never contact an indicator.** No `socket`, `urllib`, `requests`, DNS
  resolution, ping, HTTP, WHOIS — nothing. The scan already runs inside a guard
  that raises `NetworkContactAttempt` if you try; do not work around it. Reading
  the LOCAL OS DNS cache (already-resolved entries) via a `subprocess` call to a
  system tool is allowed and resolves nothing.
- **Read-only.** A module must not create, modify or delete anything on the host
  (temp copies of locked DBs in the system temp dir, cleaned up, are the only
  writes permitted).
- **Never crash the run.** Catch per-item errors (locked file, permission
  denied, unreadable DB), count them as `skipped`, and continue. A skipped item
  is not a clean item.
- Match is case-insensitive substring for domains/IPs; exact hex compare for hashes.

## Platform

Windows first. On a platform where a module cannot run (e.g. the Windows-only
host module on Linux), return a ModuleResult whose checks are all `could_not_run`
with reason "not supported on <platform>" — never a fake CLEAN.
