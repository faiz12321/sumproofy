"""Find the maker's official SHA-256 for a file name, from a page link.

Strategy, safest first:
  1. GitHub release links: ask the GitHub API for the release asset's stored
     digest (GitHub computes SHA-256 for every uploaded asset), or a sidecar
     checksum asset.
  2. Any other page: follow a linked .sha256-style sidecar file and parse it.
  3. Last resort: a 64-hex fingerprint printed on the page near the file
     name. Exactly one distinct value is a candidate; more than one is
     reported as ambiguous, never guessed.

The fetcher is injectable so tests never touch the network:
  fetch(url) -> (body_bytes, final_url), raising FetchError.
"""
import html
import json
import re
from urllib.parse import urlparse

from .checksums import (parse_checksum_text, extract_hashes_near_name, find_sidecar_links, decode_text,
                         HEX64)
from .fetch import FetchError

MAX_PAGE_CHARS = 2 * 1024 * 1024


# Source kinds, strongest first. The verdict wording is bold only for
# strong kinds; a hash scraped off a web page gets careful wording.
STRONG = "strong"
WEAK = "weak"


class LookupResult:
    def __init__(self, status, official_hash=None, source=None, detail="", source_kind=None):
        self.status = status            # found | not_found | ambiguous | error
        self.official_hash = official_hash
        self.source = source            # short human description of where it came from
        self.detail = detail
        self.source_kind = source_kind  # STRONG | WEAK | None

    def as_dict(self):
        return {"status": self.status, "official_hash": self.official_hash,
                "source": self.source, "detail": self.detail,
                "source_kind": self.source_kind}


_GH_RELEASE = re.compile(r"^/([^/]+)/([^/]+)/releases(?:/|$)")

_CHECKSUM_NAME = re.compile(r"(sha256sums?|shasums256|\.sha256|checksums)", re.IGNORECASE)


def _github_lookup(page_url, filename, fetch):
    parsed = urlparse(page_url)
    m = _GH_RELEASE.match(parsed.path)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    api = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=10"
    try:
        body, _ = fetch(api)
    except FetchError as exc:
        return LookupResult("error", detail=f"Could not ask GitHub about that release: {exc}")
    try:
        releases = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return LookupResult("error", detail="GitHub's answer was not readable.")
    if not isinstance(releases, list):
        return LookupResult("error", detail="GitHub's answer was not readable.")
    sidecars = []
    for rel in releases:
        if not isinstance(rel, dict):
            continue
        for asset in rel.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            name = asset.get("name") or ""
            if name == filename:
                digest = asset.get("digest") or ""
                h = ""
                if digest.lower().startswith("sha256:"):
                    h = digest.split(":", 1)[1].lower()
                if HEX64.match(h):
                    return LookupResult(
                        "found", official_hash=h,
                        source=f"GitHub release ({owner}/{repo})",
                        detail="GitHub stored this fingerprint when the file was published.",
                        source_kind=STRONG)
                # Missing or malformed digest: do not trust it, fall back to
                # the checksum files attached to the release.
                dl = asset.get("browser_download_url")
                if isinstance(dl, str):
                    sidecars.append(("self-no-digest", dl))
            elif name.lower().endswith((".sha256", ".sha256sum", ".sha256sums")):
                dl = asset.get("browser_download_url")
                if isinstance(dl, str):
                    sidecars.append((name, dl))
    for _name, dl in sidecars[:5]:
        try:
            body, _ = fetch(dl)
        except FetchError:
            continue
        h, status, detail = parse_checksum_text(decode_text(body), filename)
        if status in ("found", "ambiguous"):
            return LookupResult(status, official_hash=h,
                                source=f"GitHub checksum file ({owner}/{repo})", detail=detail,
                                source_kind=STRONG)
    return LookupResult("not_found", source=f"GitHub release ({owner}/{repo})",
                        detail="GitHub has no stored fingerprint for this file name.")


def find_official(filename, page_url, fetch):
    """Look up the official SHA-256 for filename using page_url."""
    if not page_url or not page_url.strip():
        return LookupResult("not_found", detail="No page link was given.")
    page_url = page_url.strip()
    parsed = urlparse(page_url)
    host = (parsed.hostname or "").lower()
    if host in ("github.com", "www.github.com"):
        r = _github_lookup(page_url, filename, fetch)
        if r is not None:
            return r
    try:
        body, final_url = fetch(page_url)
    except FetchError as exc:
        return LookupResult("error", detail=str(exc))
    page = decode_text(body)[:MAX_PAGE_CHARS]

    # The pasted link can itself be a checksum file (SHASUMS256.txt, ...).
    basename = parsed.path.rsplit("/", 1)[-1]
    if _CHECKSUM_NAME.search(basename):
        h, status, detail = parse_checksum_text(page, filename)
        if status in ("found", "ambiguous"):
            return LookupResult(status, official_hash=h,
                                source=f"checksum file from {host}", detail=detail,
                                source_kind=STRONG)

    text = html.unescape(re.sub(r"<[^>]+>", " ", page))

    for link in find_sidecar_links(page, final_url)[:5]:
        try:
            sbody, _ = fetch(link)
        except FetchError:
            continue
        h, status, detail = parse_checksum_text(decode_text(sbody), filename)
        if status in ("found", "ambiguous"):
            host = urlparse(link).hostname or "the same site"
            return LookupResult(status, official_hash=h,
                                source=f"checksum file from {host}", detail=detail,
                                source_kind=STRONG)

    near = extract_hashes_near_name(text, filename)
    if len(near) == 1:
        return LookupResult("found", official_hash=next(iter(near)),
                            source="fingerprint printed on the page",
                            detail="Found next to the file name on the page.",
                            source_kind=WEAK)
    if len(near) > 1:
        return LookupResult("ambiguous", source_kind=WEAK,
                            detail="The page shows several different fingerprints near this file name.")
    return LookupResult("not_found",
                        detail="No official fingerprint for this file name was found on that page.")
