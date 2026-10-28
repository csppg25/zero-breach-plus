"""IOC loading, type inference and freshness.

Data contract (SPEC-scanner.md, matching iocs/adfection_iocs.txt):

    indicator <TAB> tier <TAB> confidence

  tier       = cc | validator | delivery | historical | sample
  confidence = primary | secondary

`#` lines are comments. The schema deliberately carries more than AdFection: the
threat is the ADINT *technique*, so the same file holds other vendors (NSO,
Intellexa/Predator, Paragon, Cytrox) and sample hashes as they are added. A hit
without a citation is unusable, so the provenance (confidence) column is required.

Indicator *type* is inferred from shape, not stored, so the file stays 3 columns:
  - 64 hex chars            -> sha256 sample hash
  - looks like an IPv4/IPv6 -> ip
  - otherwise               -> domain
"""

from __future__ import annotations

import io
import os
import ipaddress
import re
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VALID_TIERS = {
    "cc",           # Candiru command-and-control (Citizen Lab, named in body)
    "validator",    # Candiru validator / target-selection servers
    "delivery",     # Discover-Tech / Controlium ad infrastructure
    "historical",   # older, separate Candiru campaigns
    "sample",       # file hashes of the spyware itself
    # A legitimate, signed third-party driver or utility that this actor abuses
    # (bring-your-own-vulnerable-driver). The file is NOT spyware: it ships with
    # real products and is present on clean machines for innocent reasons. It is
    # tiered apart from `sample` precisely so a match can never be reported as
    # proof of infection - presence is a lead to investigate, nothing more.
    "vuln-driver",
    # Candiru-attributed server infrastructure whose individual ROLE is not stated
    # by the source. Recorded Future's Aug 2025 DevilsTongue report lists 8
    # clusters mixing victim-facing C2 and higher-tier operator infrastructure,
    # without saying which domain is which. Treating these as `cc` would claim
    # precision the source does not give, so they get their own tier.
    "candiru",
    # Same, but IP addresses. Separate because an IP indicator decays in a way a
    # domain does not: almost all of these are Vultr / DigitalOcean addresses
    # that are very likely reassigned to innocent tenants by now. A hit is only
    # meaningful if it is DATED (a DNS log entry from the period), which is why
    # the tier is distinguishable rather than mixed in with the domains.
    "candiru-ip",
}
VALID_CONFIDENCE = {"primary", "secondary"}

# Characters that may not sit immediately beside a match. Without this the
# matching is plain substring, so 52.174.65.77 matches inside 152.174.65.771 and
# controlium.net matches inside notcontrolium.net or controlium.network. With 100+
# IP indicators that stops being theoretical.
#
# A dot on the RIGHT is the subtle case. "controlium.net." (the fully-qualified
# form, or the end of a sentence) is the indicator; "controlium.net.evil.example"
# is a different domain that merely starts with it. So a trailing dot is allowed
# only when what follows it does not continue the name (the `cont` sets below).
_LABEL = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_LEFT_BAD = _LABEL | {"_"}
_RIGHT_BAD = _LABEL | {"_"}
_DIGIT = set("0123456789")
_DIGIT_DOT = _DIGIT | {"."}
_HEX = set("0123456789abcdef")
_HEX_COLON = _HEX | {":"}

TYPE_DOMAIN = "domain"
TYPE_IP = "ip"
TYPE_SHA256 = "sha256"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ASOF_RE = re.compile(r"^#\s*as-of:\s*(\d{4}-\d{2}-\d{2})\s*$")


def infer_type(indicator: str) -> str:
    s = indicator.strip().lower()
    if _SHA256_RE.match(s):
        return TYPE_SHA256
    if _IPV4_RE.match(s) or (":" in s and all(c in "0123456789abcdef:" for c in s)):
        return TYPE_IP
    return TYPE_DOMAIN


@dataclass(frozen=True)
class Indicator:
    value: str          # normalised: lower-case for domains/ips/hashes
    tier: str
    confidence: str
    type: str
    # Which published report this came from. Optional 4th column. With more than
    # one source in the file, "a hit without a citation is unusable" means the
    # citation has to travel per indicator, not per file.
    source: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "indicator": self.value,
            "tier": self.tier,
            "confidence": self.confidence,
            "type": self.type,
            "source": self.source,
        }


def _char_at(hay, pos):
    """One character of a str or bytes haystack, as a str, or None if out of range."""
    if pos < 0 or pos >= len(hay):
        return None
    c = hay[pos]
    return c if isinstance(c, str) else chr(c)


def _char_at16(hay: bytes, pos: int):
    """One UTF-16LE code unit of a bytes haystack starting at byte `pos`.

    Only ASCII matters for boundary decisions, so anything else comes back as a
    placeholder that is in none of the boundary sets.
    """
    if pos < 0 or pos + 1 >= len(hay):
        return None
    lo, hi = hay[pos], hay[pos + 1]
    return chr(lo) if hi == 0 and lo < 0x80 else "￿"


def _bad_sets(needle: str, ind_type: str):
    """(left_bad, right_bad, continues) for one indicator. `continues` is what
    may not follow a trailing dot - see the comment on _LABEL."""
    if ind_type == TYPE_IP:
        if ":" in needle:                      # IPv6
            return _HEX_COLON | {"."}, _HEX_COLON, _HEX
        return _DIGIT_DOT, _DIGIT, _DIGIT      # IPv4
    return _LEFT_BAD, _RIGHT_BAD, _LABEL


def _positions(hay, needle, ind_type: str, display: str, wide: bool = False):
    """Every offset at which `needle` occurs in `hay` as a whole indicator rather
    than as part of a longer name or number.

    Domains: the character before must not continue a label (so notcontrolium.net
    does not match controlium.net) and the character after must not either (so
    controlium.network does not match).
    IPs: neither side may continue the number, so 152.174.65.771 does not match
    52.174.65.77, and an IPv6 address may not sit inside a longer one.

    `display` is the indicator as text (for choosing boundary sets); `needle` is
    what is searched for, which differs when `wide` (UTF-16LE bytes).
    """
    left_bad, right_bad, cont = _bad_sets(display, ind_type)
    at = _char_at16 if wide else _char_at
    unit = 2 if wide else 1
    out = []
    start = 0
    while True:
        idx = hay.find(needle, start)
        if idx == -1:
            return out
        before = at(hay, idx - unit)
        after = at(hay, idx + len(needle))
        ok = before is None or before not in left_bad
        if ok and after is not None:
            if after in right_bad:
                ok = False
            elif after == ".":
                nxt = at(hay, idx + len(needle) + unit)
                ok = nxt is None or nxt not in cont
        if ok:
            out.append(idx)
        start = idx + 1


def _boundaries_ok(hay, needle, ind_type: str) -> bool:
    """True if `needle` occurs in `hay` at least once as a whole indicator."""
    display = needle if isinstance(needle, str) else needle.decode("ascii", "replace")
    return bool(_positions(hay, needle, ind_type, display))


def _prune_parents(found, hay) -> list:
    """Drop a parent domain whose every occurrence is just the tail of a matched
    child. "noas.powerium.net" in a cookie also contains "powerium.net", and both
    are indicators - but it is ONE contact, and reporting it as two servers that
    reached the device doubles the alarm for no reason. A parent that also occurs
    on its own somewhere in the same artifact is kept."""
    by_value = {ind.value: (ind, occ) for ind, occ in found}
    keep = []
    for ind, occ in found:
        children = [c for c in by_value
                    if c != ind.value and c.endswith("." + ind.value)]
        if ind.type != TYPE_DOMAIN or not children:
            keep.append(ind)
            continue
        standalone = False
        for enc, pos in occ:
            tail_of_child = False
            for child in children:
                extra = len(child) - len(ind.value)
                if enc == "wide":
                    start = pos - 2 * extra
                    seg = hay[start:pos + 2 * len(ind.value)] if start >= 0 else b""
                    tail_of_child = seg == child.encode("utf-16-le")
                else:
                    start = pos - extra
                    seg = hay[start:pos + len(ind.value)] if start >= 0 else ""
                    want = child if isinstance(hay, str) else child.encode("ascii")
                    tail_of_child = seg == want
                if tail_of_child:
                    break
            if not tail_of_child:
                standalone = True
                break
        if standalone:
            keep.append(ind)
    return keep


class IocSet:
    def __init__(self, indicators: List[Indicator], source_path: str,
                 source_mtime: Optional[float]):
        self.indicators = indicators
        self.source_path = source_path
        self.source_mtime = source_mtime
        self.asof = None  # "YYYY-MM-DD" from the header, set by load()
        self._by_value = {i.value: i for i in indicators}
        self._net_cache = None
        self._needle_cache = {}
        self._gate_text_re = None
        self._gate_bytes_re = None

    # --- views used by modules ---------------------------------------------

    @property
    def domains(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_DOMAIN]

    @property
    def ips(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_IP]

    @property
    def hashes(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_SHA256]

    @property
    def network_strings(self) -> List[str]:
        """Lower-case domain + IP strings, for substring matching in artifacts.
        Sorted for deterministic output. Never used to RESOLVE anything."""
        return sorted({i.value for i in self.indicators
                       if i.type in (TYPE_DOMAIN, TYPE_IP)})

    def lookup(self, value: str) -> Optional[Indicator]:
        return self._by_value.get(value.strip().lower())

    # --- matching -----------------------------------------------------------
    #
    # All matching goes through here so the boundary rules exist in exactly one
    # place. Both methods take an ALREADY LOWER-CASED haystack, and neither ever
    # resolves or contacts anything: this is text comparison only.

    @property
    def _net_indicators(self) -> List[Indicator]:
        if self._net_cache is None:
            self._net_cache = [i for i in self.indicators
                               if i.type in (TYPE_DOMAIN, TYPE_IP)]
        return self._net_cache

    # MEASURED, do not "optimise" this back into a regex.
    #
    # The obvious speedup is to compile one alternation of all 263 literals and
    # make a single pass per file instead of one pass per indicator. It was tried
    # and it is 4x SLOWER (10.7s vs 2.5s over 300 x 125 KB buffers): `in` on
    # bytes/str dispatches to an optimised C substring search, while Python's
    # `re` has to walk a large alternation itself. A genuine single-pass win
    # would need an Aho-Corasick implementation, which is not in the standard
    # library, and the tool has a hard no-dependencies rule.
    #
    # The boundary check runs only on candidates that already matched, so it
    # costs nothing on the overwhelming majority of files.

    def search(self, haystack_lower: str) -> List[Indicator]:
        """Indicators genuinely present in the text, with type-aware boundaries."""
        found = []
        for ind in self._net_indicators:
            if ind.value in haystack_lower:
                pos = _positions(haystack_lower, ind.value, ind.type, ind.value)
                if pos:
                    found.append((ind, [("str", p) for p in pos]))
        return _prune_parents(found, haystack_lower)

    def search_bytes(self, haystack_lower: bytes) -> List[Indicator]:
        """As search(), for raw binary artifacts (HTTP cache, LevelDB).

        Searches both single-byte text and UTF-16LE, because Chromium's storage
        and many Windows artifacts keep strings as UTF-16 - "c\\0o\\0n\\0..." -
        which a plain byte search walks straight past. bytes.lower() lower-cases
        the ASCII letters in both encodings, so the caller's lower-casing holds.
        """
        found = []
        for ind in self._net_indicators:
            occ = []
            narrow, wide = self._needles(ind)
            if narrow in haystack_lower:
                occ += [("narrow", p) for p in
                        _positions(haystack_lower, narrow, ind.type, ind.value)]
            if wide in haystack_lower:
                occ += [("wide", p) for p in
                        _positions(haystack_lower, wide, ind.type, ind.value,
                                   wide=True)]
            if occ:
                found.append((ind, occ))
        return _prune_parents(found, haystack_lower)

    def _needles(self, ind: Indicator):
        cache = self._needle_cache
        if ind.value not in cache:
            # Indicator values are ASCII by construction (load() converts IDN
            # domains to punycode), so this encode is exact, never lossy.
            cache[ind.value] = (ind.value.encode("ascii"),
                                ind.value.encode("utf-16-le"))
        return cache[ind.value]

    def most_specific(self, matched: List[Indicator]) -> List[Indicator]:
        """For ONE record (a cookie, an HSTS entry, a URL) that matched several
        indicators: keep only the most specific. A cookie for noas.powerium.net
        matches both noas.powerium.net and powerium.net, but it is one contact."""
        values = {i.value for i in matched}
        return [i for i in matched
                if not (i.type == TYPE_DOMAIN and
                        any(v != i.value and v.endswith("." + i.value)
                            for v in values))]

    def __len__(self) -> int:
        return len(self.indicators)

    # --- freshness ----------------------------------------------------------

    def _curated_at(self) -> Optional[datetime.datetime]:
        """When this set was last curated, as a datetime, or None if unknowable.

        The '# as-of:' date is preferred over the file's modification time
        because mtime is a property of the COPY, not of the data: a fresh clone,
        an unzip or a plain file copy resets it to now, so a set curated a year
        ago would report itself as zero days old and never trip the staleness
        warning. The header date is content, so it survives being copied.
        """
        if self.asof:
            try:
                return datetime.datetime.strptime(self.asof, "%Y-%m-%d")
            except ValueError:
                # A malformed header must degrade to the mtime, never raise in
                # the middle of a scan.
                pass
        if self.source_mtime is None:
            return None
        return datetime.datetime.fromtimestamp(self.source_mtime)

    def age_days(self, now: Optional[datetime.datetime] = None) -> Optional[int]:
        curated = self._curated_at()
        if curated is None:
            return None
        now = now or datetime.datetime.now()
        delta = now - curated
        return max(0, delta.days)

    def is_stale(self, threshold_days: int = 30) -> bool:
        age = self.age_days()
        return age is not None and age > threshold_days


class IocError(Exception):
    pass


# Indicator values drive substring searches over every artifact and are printed
# into reports people forward, but only the file's schema was checked. A hostile
# or corrupted feed could pass: a lone "." normalises to the empty string, which
# matches between every pair of bytes (measured at ~31 MB of RAM per MB scanned);
# a lone ":" parses as an IP that matches every URL; "0.0.0.0" would match every
# BLOCKED lookup; and a value carrying control characters went straight into the
# report. Real indicators are hostnames, IP addresses and hex digests. Anything
# else is refused, loudly, rather than scanned for.
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_MAX_INDICATORS = 20000


def _value_problem(value, kind):
    """Why an indicator value is unsafe to scan for, or an empty string."""
    if kind == TYPE_IP:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return "not a valid IP address"
        if addr.is_unspecified or len(value) < 7:
            return "would match far more than the intended host"
        return ""
    if kind == TYPE_DOMAIN:
        if not 4 <= len(value) <= 253:
            return "not the length of a hostname"
        labels = value.split(".")
        if len(labels) < 2:
            return "a hostname needs at least one dot"
        for label in labels:
            if not 1 <= len(label) <= 63 or not _DOMAIN_LABEL_RE.match(label):
                return "label {!r} is not a valid hostname label".format(label[:70])
        return ""
    return ""   # hashes are already pinned to 64 hex digits by infer_type


def load(path: str) -> IocSet:
    if not os.path.exists(path):
        raise IocError("IOC file not found: {}".format(path))
    seen: Dict[str, Indicator] = {}
    asof: Optional[str] = None
    # utf-8-sig, not utf-8: Windows editors save a byte-order mark, and U+FEFF is
    # not whitespace to str.strip(). With plain utf-8 the first indicator in a
    # user's own list silently became "﻿controlium.net", matched nothing,
    # and the scan then reported finding nothing without ever having looked.
    with io.open(path, encoding="utf-8-sig") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                # The '# as-of: YYYY-MM-DD' header is the set's curated date. It
                # is the deterministic timestamp every generated artifact uses,
                # so the whole build is reproducible from committed content.
                m = _ASOF_RE.match(line)
                if m:
                    asof = m.group(1)
                continue
            parts = [p.strip() for p in line.split("\t") if p.strip() != ""]
            if len(parts) < 3:
                raise IocError(
                    "line {}: expected 3 or 4 tab-separated columns, got {!r}"
                    .format(lineno, line))
            value, tier, confidence = parts[0].lower(), parts[1], parts[2]
            # 4th column is an optional source tag; files written before it
            # existed stay valid.
            source = parts[3] if len(parts) > 3 else ""
            if tier not in VALID_TIERS:
                raise IocError("line {}: unknown tier {!r}".format(lineno, tier))
            if confidence not in VALID_CONFIDENCE:
                raise IocError(
                    "line {}: unknown confidence {!r}".format(lineno, confidence))
            if value.startswith("﻿") or any(
                    c in value for c in "​‌‍⁠"):
                raise IocError("line {}: invisible character in {!r} - the "
                               "file was probably re-saved by an editor".format(
                                   lineno, value))
            kind = infer_type(value)
            if kind == TYPE_DOMAIN:
                value = value.rstrip(".")
                if not value.isascii():
                    # Store internationalised names in the punycode form that
                    # browsers and DNS actually record, so matching is exact.
                    try:
                        value = value.encode("idna").decode("ascii")
                    except UnicodeError:
                        raise IocError("line {}: {!r} is not a valid domain "
                                       "name".format(lineno, value))
            problem = _value_problem(value, kind)
            if problem:
                raise IocError("line {}: {!r}: {}".format(
                    lineno, value[:80], problem))
            seen[value] = Indicator(value, tier, confidence, kind, source)
            if len(seen) > _MAX_INDICATORS:
                raise IocError("more than {:,} indicators - refusing what looks "
                               "like a corrupted or hostile feed".format(
                                   _MAX_INDICATORS))
    if not seen:
        # An empty list must never produce a report. A truncated download or an
        # emptied file would otherwise run a full scan, search for nothing, and
        # print a result that reads as reassurance.
        raise IocError("indicator file contains no indicators: {}".format(path))
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    s = IocSet(sorted(seen.values(), key=lambda i: i.value),
               os.path.abspath(path), mtime)
    s.asof = asof
    return s
