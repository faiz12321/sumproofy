"""Parse official checksum text in the formats publishers actually use.

Supported lines (hex is case-insensitive; file-name match is exact on the
base name, after stripping any directory part):
  GNU:    "3f4a...  node-v22.11.0-x64.msi"   (two spaces, or " *" for binary)
  BSD:    "SHA256 (node-v22.11.0-x64.msi) = 3f4a..."
  Bare:   "3f4a..."   (only used when the file has no named lines at all)
"""
import re

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_GNU = re.compile(r"^(?P<hash>[0-9a-fA-F]{64})\s+[ *]?(?P<name>.+?)\s*$")
_BSD = re.compile(r"^SHA256\s*\((?P<name>.+?)\)\s*=\s*(?P<hash>[0-9a-fA-F]{64})\s*$", re.IGNORECASE)

MAX_LINE = 4096
MAX_LINES = 100000


def decode_text(body):
    """Decode checksum-file bytes: UTF-8, UTF-8 BOM, or UTF-16 (BOM or NUL pattern)."""
    if body.startswith(b"\xff\xfe") or body.startswith(b"\xfe\xff"):
        return body.decode("utf-16", "replace")
    if body.startswith(b"\xef\xbb\xbf"):
        return body.decode("utf-8-sig", "replace")
    head = body[:200]
    if head.count(b"\x00") > len(head) // 4:
        # lots of NULs: almost certainly UTF-16 without a BOM. For
        # ASCII-ish content the NUL byte position gives the endianness.
        even_nul = head[0::2].count(b"\x00")
        odd_nul = head[1::2].count(b"\x00")
        enc = "utf-16-be" if even_nul > odd_nul else "utf-16-le"
        try:
            return body.decode(enc)
        except UnicodeDecodeError:
            pass
    return body.decode("utf-8", "replace")


def _basename(name):
    name = name.strip().strip('"').replace("\\", "/")
    return name.rsplit("/", 1)[-1]


def parse_checksum_text(text, filename):
    """Return (hash_or_None, status, detail).

    status is "found", "not_found", or "ambiguous" (two different hashes for
    the same name: never guess).
    """
    target = _basename(filename).lower()
    if not target:
        return None, "not_found", "no file name to look for"
    named_for_target = set()
    saw_named_line = False
    bare = set()
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        return None, "not_found", "the checksum file is too large to read safely"
    for raw in lines:
        line = raw[:MAX_LINE].strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        m = _BSD.match(line)
        if m:
            saw_named_line = True
            if _basename(m.group("name")).lower() == target:
                named_for_target.add(m.group("hash").lower())
            continue
        m = _GNU.match(line)
        if m:
            saw_named_line = True
            if _basename(m.group("name")).lower() == target:
                named_for_target.add(m.group("hash").lower())
            continue
        if HEX64.match(line):
            bare.add(line.lower())
    if len(named_for_target) == 1:
        return next(iter(named_for_target)), "found", "official fingerprint found"
    if len(named_for_target) > 1:
        return None, "ambiguous", "the checksum file lists more than one answer for this file name"
    if not saw_named_line and len(bare) == 1:
        return next(iter(bare)), "found", "official fingerprint found"
    if not saw_named_line and len(bare) > 1:
        return None, "ambiguous", "the checksum file holds more than one fingerprint and none names this file"
    return None, "not_found", "no fingerprint for this file name in the checksum file"


# ---- HTML page extraction -------------------------------------------------

_HEX_ANYWHERE = re.compile(r"\b[0-9a-fA-F]{64}\b")
NEAR_WINDOW = 200  # characters each side of the file name
LABEL_WINDOW = 100  # how close a fingerprint label must sit to the hex
_LABEL = re.compile(r"sha\s*-?\s*256|checksum|fingerprint|hash|digest", re.IGNORECASE)


_FILENAME_RE = re.compile(r"[\w][\w. +()\-]{0,120}?\.[A-Za-z0-9]{1,10}")


def extract_hashes_near_name(page_text, filename):
    """64-hex strings near the file name in page text.

    A hash is only a candidate when the file name is the closest file-name-like
    token to it in the window; a hash sitting next to a different file name
    belongs to that file, not ours. Returns a set of distinct lowercase
    hashes; the caller treats 1 as a candidate and more than 1 as ambiguous
    (never guesses).
    """
    target = _basename(filename)
    out = set()
    if not target:
        return out
    lowered = page_text.lower()
    t_lower = target.lower()
    positions = []
    start = 0
    while True:
        i = lowered.find(t_lower, start)
        if i < 0:
            break
        positions.append(i)
        start = i + 1
    if not positions:
        return out
    for pos in positions:
        lo = max(0, pos - NEAR_WINDOW)
        hi = min(len(page_text), pos + len(target) + NEAR_WINDOW)
        window = page_text[lo:hi]
        names = []
        for nm in _FILENAME_RE.finditer(window):
            token = nm.group(0).split()[-1]
            names.append((nm.end() - len(token), token))
        for m in _HEX_ANYWHERE.finditer(window):
            hx_start = m.start()
            own_dist = min([abs(hx_start - n[0]) for n in names if n[1].lower() == t_lower] or [10 ** 9])
            other = [abs(hx_start - n[0]) for n in names if n[1].lower() != t_lower]
            if other and min(other) < own_dist:
                continue
            # a bare hex string is not enough: it must be labelled as a
            # fingerprint ("SHA256", "checksum", ...) or it is just noise.
            label_lo = max(0, hx_start - LABEL_WINDOW)
            label_hi = min(len(window), m.end() + LABEL_WINDOW)
            if not _LABEL.search(window[label_lo:label_hi]):
                continue
            out.add(m.group(0).lower())
    return out


_SIDECAR_RE = re.compile(
    r'href=["\'](?P<href>[^"\']*?(?:\.sha256(?:sums?|\.txt)?|sha256sums(?:\.txt)?|shasums256(?:\.txt)?))["\']',
    re.IGNORECASE,
)


def find_sidecar_links(html, base_url):
    """Absolute URLs of .sha256-style sidecar files linked from the page."""
    from urllib.parse import urljoin, urlparse

    out = []
    for m in _SIDECAR_RE.finditer(html):
        u = urljoin(base_url, m.group("href"))
        scheme = urlparse(u).scheme.lower()
        if scheme in ("http", "https"):
            out.append(u)
    return out
