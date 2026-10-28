# The validator gap — and the published method for closing it

`adfection_iocs.txt` carries **2 of 305** Candiru validator server domains, and **0
of 319** validator IPs. This file records why, and the exact method The Citizen Lab
used to find them, so that whoever can run it is not starting from scratch.

## Why the list is missing

The report states the count but never publishes the set:

> "In all, we found 305 distinct domain names on 319 IP addresses."

Only `keyadapter.com` and `sharethere.net` are named in the body text. Appendix C
covers the **Discover-Tech / Controlium ad infrastructure** (all of which is now
imported), not the Candiru validator layer. There is no appendix listing validators.

This matters more than any other gap in the data set. The validator is the server
that decided, per device, whether to proceed to an exploit. **A validator hit is
evidence of targeting; a delivery-tier hit is only evidence of having seen an ad.**
We can detect the latter and are nearly blind to the former.

## The method, from the report (Section 2, "Fingerprinting Candiru Servers")

Citizen Lab did not get the list from an inside source. They found it by matching
an HTTP response pattern across historical internet-wide scan data on **Censys**.
Anyone with the same access can reproduce it.

**Fingerprint V1 — validator servers.** The report gives this regular expression
over the HTTP response banner (reproduced in two fragments as published):

```
HTTP/1\.1 [^\r\n]+\r\ndate: [^\r\n]+\r?\n(connection: [^\r\n]+\r\n)?content-type: [^\r\n]+\r\n
server: Apache[^\r\n]*\r\ncontent-length: [0-9]+\r\n.*
```

**Fingerprint C1 — command-and-control servers.** Four C&C servers matched:

```
HTTP/1\.1 [0-9]+ \r\nDate: [^\r\n]+\r?\nContent-Type: text/html
```
...continuing with `Connection: keep-alive` and `server: nginx` headers. The report
notes the other three C&C servers had no matching response in scan data.

**Search parameters used:** Censys, **one historical snapshot per month, August 2022
to July 2026**.

A footnote in the report warns that the `\r?` after the date header is an artifact of
a **2022 Censys bug**, not server behaviour — so a naive re-run against other scan
data, or against a different period, needs that allowance or it will miss hosts.

## What reproducing it actually requires

1. **Censys access with historical search.** The free tier queries only the current
   snapshot. This needs the paid/research tier, which Censys grants to academics and
   journalists on application.
2. **Accepting that the answer is mostly historical.** The report says the behaviour
   "gradually began being retired" in **May and June 2026**. A scan of today's
   internet will find few or no live validators. The value is in the monthly
   snapshots back to 2022, which is exactly the part that needs paid access.
3. **Care about false positives.** `server: Apache` plus a content-length is an
   extremely common shape. The fingerprint presumably worked because of the exact
   header order and casing; a loose re-implementation would match a large share of
   the ordinary web. **Do not put the raw output of a re-run into this IOC file
   without validating it.** An over-broad validator list is worse than none: it
   would point at innocent servers in the one tier where a hit implies targeting.

## The quicker path

**Ask.** Citizen Lab publishes to enable exactly this kind of defensive work, and the
report names **Sekoia** and **Recorded Future** as having previously attributed some
of these domains to Candiru. Any of the three may share the set, or confirm a
re-derived one, which solves the false-positive problem above. Amnesty's Security Lab
maintains indicator files for MVT and would be a natural home for the result.

That is a short email, versus a paid Censys tier plus a validation problem.

## Status

| | |
|---|---|
| Validator domains held | 2 of 305 |
| Validator IPs held | 0 of 319 |
| Method published? | Yes — Fingerprint V1, above |
| Reproducible without paid access? | No |
| Asked Citizen Lab / Sekoia / Recorded Future? | **Not yet — open action** |
