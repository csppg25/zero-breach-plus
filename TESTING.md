# Before publishing

Run the release check from the repository root. It uses temporary, harmless
fixtures rather than your browser profiles, registry or real DNS history.
No VM, malware samples, administrator account or test service is needed.

## One-time optional-engine setup

Use Python 3.9+ for the pinned optional YARA-X engine (Python 3.12 is used in CI):

```text
python -m venv .venv
```

On Windows:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-patterns.txt
.venv\Scripts\python.exe tools/release_check.py --require-patterns
```

On macOS/Linux:

```sh
.venv/bin/python -m pip install -r requirements-patterns.txt
.venv/bin/python tools/release_check.py --require-patterns
```

Use the same interpreter for installation and tests. The runner never installs
anything. For ordinary standard-library development, `python
tools/release_check.py` works without YARA-X; its summary explicitly records the
untested optional positives as a skip. Use `--require-patterns` before release.

## What the command checks

- The existing unit/regression suite.
- Two byte-identical builds of the downloadable script, plus its help/version.
- Sixteen fixture scenarios, each in fresh source-CLI and single-file processes:
  clean data, contacted domain, harmless research reference, exact hash hit,
  corrupt database, a hit alongside a corrupt database, `--quick` coverage gap,
  a DNS hit past the old 20,000-event limit, unread older DNS events without a
  hit, four disabled-DNS-log cases (retained match, retained clean data,
  unreadable retained events and no events), invalid indicator input, and COM-referenced optional file patterns (both a bare DLL and an unquoted
  command under an extension-like folder name).
- Real browser-shaped SQLite files and harmless rule-matching bytes pass through
  the real scanner modules, evidence grading, exit codes and text/JSON reports.
  Source and download must agree. Cookie values must stay out of reports;
  full finding paths must remain visible. Fixtures must remain byte-identical
  and temporary snapshots must be removed.
- During fixture scans, an audit hook rejects socket activity, subprocesses and
  file opens/listings outside fixture, project-code and Python-runtime roots.
  The scanner's network-guard recorder is checked too, so caught network
  attempts cannot pass silently. Each unit-suite run has its own temp directory.
  Each fixture process has a 45-second timeout; timeouts or assertion failures
  make the command fail. Results/logs stay under ignored
  `findings/release-checks/summary.json`. `PASS_WITH_SKIPS` names missing coverage.

The host's registry and PowerShell collectors are replaced by fixed inputs;
the actual OS enumeration is **not** tested by these fixtures. This is an
end-to-end check of the application flow, not an OS sandbox or a measurement of
spyware detection rates. CI retains its real `--quick` smoke scans on disposable
Windows, macOS and Linux runners. It also runs the fixtures on all three with
YARA-X, and on Python 3.8 without it. Routine local runs normally take seconds;
timings are recorded rather than used as a hardware benchmark.

## Include the website and staged download

The Scan website is maintained separately from this public repository. When
its local source is available, include it explicitly:

```text
python tools/release_check.py --require-patterns --web-dir PATH_TO_SCAN_DIRECTORY --scanner PATH_TO_STAGED_ZERO_BREACH_PY
```

`--web-dir` requires Node, `index.html`, `scan.js`, and
`ops/test_scan_logic.js`. It runs the existing offline page-flow matrix and
  requires the verification card's code text and copy value to match the candidate script. These
are DOM/logic fixtures; actual rendering and touch behaviour still need the
browser smoke check. `--scanner` requires the staged download to match the
fresh build byte for byte. Omit it to test the freshly built download.
If `web/scan/` exists in this checkout, it is checked automatically; otherwise
the website is explicitly listed as not tested. A requested website check must
pass; it is never silently skipped. Use `--output-dir PATH` to keep separate runs.

## Short release checklist

1. Run the command above on the frozen candidate, including optional patterns,
   staged scanner and prepared website when those are being published.
2. Require all CI jobs for that exact commit. Run the existing live-browser
   smoke check for website changes, including a small mobile viewport. For OS
   collector changes, also use a disposable Windows VM with controlled data;
   do not substitute a scan of your everyday laptop.
3. Review remaining findings; get the requested independent Astra final review.
   Verify release signatures and checksums following [SIGNING.md](SIGNING.md).
4. Publish the tested bytes with a saved rollback. Verify the public download,
   page checksum/links and a basic user flow after deployment.

No soak test, load-test infrastructure or live malware is required for this
routine gate. A timed-out real scan is an unresolved performance observation,
even when these bounded fixtures pass.
