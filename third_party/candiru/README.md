These are pinned public textual research rules, not malware samples.

`apt_candiru.yar` is the unchanged signature-base rule by Microsoft Threat
Intelligence Center (MSTIC), under Detection Rule License 1.1. Its license text
is in `LICENSE-DRL-1.1.txt`. Match messages retain its author attribution.

`win_devilstongue_auto.yar` is the unchanged displayed Malpedia rule by Felix
Bilstein, licensed CC BY-SA 4.0. `LICENSE-CC-BY-SA-4.0.txt` provides attribution,
the original source, and links to the license and legal text. HTML entities
were decoded to reproduce the displayed rule. Its disclaimer is retained.

`PROVENANCE.json` records retrieval time, source URLs, rule metadata, the source
page hash, and SHA-256 hashes of vendored rule/license bytes. The embedded strings
in `scan/adint_scan/candiru_rules.py` reproduce the rule bytes exactly when
encoded as UTF-8, preserving their separate third-party licensing. These files
are a collection of separately licensed rules; project licensing does not
replace their licenses. No author endorsement is implied.

No malware, samples, binary links, or download-all endpoints were retrieved.
The scanner compiles only the embedded copies, with YARA includes disabled.
It never updates rules or downloads anything at scan time. A future update
requires deliberate source review, attribution, new hashes, and regression
checks. Pattern matches require investigation; they do not establish exact
sample identity or confirmed infection. Synthetic byte fixtures test matching
mechanics only, not real-world detection sensitivity.
