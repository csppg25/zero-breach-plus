# Candidate coverage improvements after v0.1.3

This branch keeps the ordinary scan read-only, dependency-free and offline.
With optional `--patterns`, local user-writable files named by per-user COM
registrations are scanned before broad folders. They are capped at 128 paths;
omitted, unsafe, changed and unreadable files remain coverage gaps. A registry
entry alone is not a detection. An explicit `--pattern-path` still limits the
optional check to the path the user selected.

Windows DNS history now reads up to 50,000 recent retained records rather than
20,000. If the log reports more records than were read, the older portion is
classified as incomplete, not clean. No DNS logging is enabled and no network
request is made. Logs that were never enabled cannot be reconstructed.

The proposed larger-file change was rejected during review: both embedded
published Candiru rules contain explicit file-size conditions below roughly
1 MB. Raising the scanner's 1 MB cap would add work without making either
rule match a larger file. This cap should only be revisited with a validated
additional rule whose size condition warrants it.

Release gate: full default and optional-engine suites, cross-platform CI,
single-file reproducibility, safe-path and incomplete-log tests, final public
artifact signatures and an independent Astra review. Do not deploy from this
branch before those checks finish.
