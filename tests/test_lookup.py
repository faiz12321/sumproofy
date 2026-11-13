import json
import unittest

from sumproofy.fetch import FetchError
from sumproofy.lookup import find_official, STRONG

H = "a" * 64
H2 = "b" * 64


class FakeFetcher:
    """Map url -> (body, ) or FetchError; records calls."""
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        r = self.routes.get(url)
        if r is None:
            raise FetchError("no route in fake")
        if isinstance(r, Exception):
            raise r
        body, final = r
        return (body if isinstance(body, bytes) else body.encode()), final or url


def gh_api_payload(assets):
    return json.dumps([{"tag_name": "v1", "assets": assets}])


class TestGitHub(unittest.TestCase):
    def test_asset_digest_match(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        f = FakeFetcher({api: (gh_api_payload([
            {"name": "app.exe", "digest": "sha256:" + H,
             "browser_download_url": "https://github.com/o/r/releases/download/v1/app.exe"}
        ]), None)})
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual((r.status, r.official_hash), ("found", H))
        self.assertIn("GitHub", r.source)

    def test_asset_digest_case_normalized(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        f = FakeFetcher({api: (gh_api_payload([
            {"name": "app.exe", "digest": "SHA256:" + H.upper()}]), None)})
        r = find_official("app.exe", "https://github.com/o/r/releases/tag/v1", f)
        self.assertEqual(r.official_hash, H)

    def test_sidecar_asset_fallback(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        dl = "https://github.com/o/r/releases/download/v1/app.exe"
        f = FakeFetcher({
            api: (gh_api_payload([
                {"name": "app.exe", "digest": None, "browser_download_url": dl},
                {"name": "app.exe.sha256", "digest": "sha256:" + H2,
                 "browser_download_url": dl + ".sha256"},
            ]), None),
            dl + ".sha256": (f"{H}  app.exe", None),
        })
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual((r.status, r.official_hash), ("found", H))

    def test_sidecar_own_digest_wins_over_sidecar_file(self):
        # the asset's stored digest belongs to the .sha256 file itself, not app.exe
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        dl = "https://github.com/o/r/releases/download/v1/app.exe"
        f = FakeFetcher({
            api: (gh_api_payload([
                {"name": "app.exe.sha256", "digest": "sha256:" + H2,
                 "browser_download_url": dl + ".sha256"},
            ]), None),
            dl + ".sha256": (f"{H}  app.exe", None),
        })
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual(r.official_hash, H)  # parsed from the file, not the digest

    def test_no_match_on_github(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        f = FakeFetcher({api: (gh_api_payload([
            {"name": "other.exe", "digest": "sha256:" + H}]), None)})
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual(r.status, "not_found")

    def test_github_api_error(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        f = FakeFetcher({api: FetchError("HTTP 404")})
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual(r.status, "error")

    def test_github_garbage_json(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        f = FakeFetcher({api: ("not json", None)})
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual(r.status, "error")


class TestGenericPage(unittest.TestCase):
    def test_sidecar_link(self):
        f = FakeFetcher({
            "https://maker.example/dl": ('<a href="app.exe.sha256">sum</a>', None),
            "https://maker.example/app.exe.sha256": (f"{H}  app.exe", None),
        })
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual((r.status, r.official_hash), ("found", H))

    def test_hash_printed_near_name(self):
        f = FakeFetcher({"https://maker.example/dl": (
            f"<p>Download app.exe</p><p>SHA-256: {H}</p>", None)})
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual((r.status, r.official_hash), ("found", H))

    def test_html_entities_unescaped(self):
        f = FakeFetcher({"https://maker.example/dl": (
            f"<p>app.exe &mdash; sha256&#58; {H}</p>", None)})
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual(r.status, "found")

    def test_hash_for_other_file_not_used(self):
        text = f"<p>other.exe {H}</p>" + "x" * 400 + "<p>app.exe</p>"
        f = FakeFetcher({"https://maker.example/dl": (text, None)})
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual(r.status, "not_found")

    def test_two_nearby_hashes_ambiguous(self):
        f = FakeFetcher({"https://maker.example/dl": (
            f"<p>app.exe SHA256: {H} or checksum {H2}</p>", None)})
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual(r.status, "ambiguous")

    def test_page_fetch_error(self):
        f = FakeFetcher({"https://maker.example/dl": FetchError("The site answered with an error (HTTP 500).")})
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual(r.status, "error")

    def test_sidecar_fails_falls_back_to_page(self):
        f = FakeFetcher({
            "https://maker.example/dl": (
                f'<a href="app.exe.sha256">sum</a><p>app.exe SHA256: {H}</p>', None),
            "https://maker.example/app.exe.sha256": FetchError("HTTP 404"),
        })
        r = find_official("app.exe", "https://maker.example/dl", f)
        self.assertEqual((r.status, r.official_hash), ("found", H))

    def test_no_url_given(self):
        r = find_official("app.exe", "", FakeFetcher({}))
        self.assertEqual(r.status, "not_found")

    def test_non_github_host_uses_page_path(self):
        api_like = "https://api.github.com/repos/o/r/releases?per_page=10"
        f = FakeFetcher({"https://notgithub.example/dl": (f"app.exe SHA256: {H}", None)})
        r = find_official("app.exe", "https://notgithub.example/dl", f)
        self.assertEqual(r.status, "found")
        self.assertNotIn(api_like, f.calls)



class ReviewLookupCase(unittest.TestCase):
    def test_sidecar_source_names_its_host(self):
        page = '<a href="https://files.example.com/app.exe.sha256">sums</a>'
        routes = {
            "https://example.com/get": page,
            "https://files.example.com/app.exe.sha256": H + "  app.exe",
        }
        r = find_official("app.exe", "https://example.com/get", FakeFetcher({u: (b, None) for u, b in routes.items()}))
        self.assertEqual(r.status, "found")
        self.assertIn("files.example.com", r.source)
        self.assertEqual(r.source_kind, "strong")

    def test_page_text_fingerprint_is_weak(self):
        page = "app.exe SHA256: " + H
        r = find_official("app.exe", "https://example.com/get",
                          FakeFetcher({"https://example.com/get": (page, None)}))
        self.assertEqual(r.status, "found")
        self.assertEqual(r.source_kind, "weak")

    def test_utf16_sidecar_body(self):
        body = (H + "  app.exe").encode("utf-16")
        routes = {
            "https://example.com/get": '<a href="/app.exe.sha256">sums</a>',
            "https://example.com/app.exe.sha256": body,
        }
        r = find_official("app.exe", "https://example.com/get", FakeFetcher({u: (b, None) for u, b in routes.items()}))
        self.assertEqual((r.status, r.official_hash), ("found", H))


if __name__ == "__main__":
    unittest.main()


class TestGitHubDigestRobustness(unittest.TestCase):
    def test_malformed_digest_falls_back_to_sidecar(self):
        # a digest that is not 64-hex must never be trusted as the answer
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        dl = "https://github.com/o/r/releases/download/v1/app.exe"
        f = FakeFetcher({
            api: (gh_api_payload([
                {"name": "app.exe", "digest": "sha256:nothex",
                 "browser_download_url": dl},
                {"name": "app.exe.sha256", "digest": None,
                 "browser_download_url": dl + ".sha256"},
            ]), None),
            dl + ".sha256": (f"{H}  app.exe", None),
        })
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertEqual((r.status, r.official_hash), ("found", H))

    def test_empty_digest_not_trusted(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        dl = "https://github.com/o/r/releases/download/v1/app.exe"
        f = FakeFetcher({
            api: (gh_api_payload([
                {"name": "app.exe", "digest": "sha256:",
                 "browser_download_url": dl},
            ]), None),
        })
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertNotEqual(r.status, "found")
        self.assertFalse(r.official_hash)

    def test_short_hex_digest_not_trusted(self):
        api = "https://api.github.com/repos/o/r/releases?per_page=10"
        dl = "https://github.com/o/r/releases/download/v1/app.exe"
        f = FakeFetcher({
            api: (gh_api_payload([
                {"name": "app.exe", "digest": "sha256:" + "a" * 40,
                 "browser_download_url": dl},
            ]), None),
        })
        r = find_official("app.exe", "https://github.com/o/r/releases", f)
        self.assertNotEqual(r.status, "found")

class TestPastedChecksumFile(unittest.TestCase):
    """The pasted link can itself be a checksum file (SHASUMS256.txt etc.)."""

    def _fetcher(self, body):
        def f(url):
            return body, url
        return f

    def test_shasums_file_found(self):
        body = (b"a" * 64 + b"  node-v26.12.0-x64.msi\n" + b"b" * 64 + b"  other-file.zip\n")
        r = find_official("node-v26.12.0-x64.msi",
                          "https://nodejs.org/dist/latest/SHASUMS256.txt", self._fetcher(body))
        self.assertEqual(r.status, "found")
        self.assertEqual(r.official_hash, b"a".decode() * 64)
        self.assertEqual(r.source_kind, STRONG)

    def test_sha256_file_found(self):
        body = (b"c" * 64 + b"  app.exe\n")
        r = find_official("app.exe", "https://example.com/app.exe.sha256", self._fetcher(body))
        self.assertEqual(r.status, "found")
        self.assertEqual(r.official_hash, "c" * 64)

    def test_checksum_file_without_name_falls_through(self):
        # a checksum-named link that does not name our file still ends honest
        body = (b"d" * 64 + b"  other.exe\n")
        r = find_official("app.exe", "https://example.com/SHA256SUMS", self._fetcher(body))
        self.assertEqual(r.status, "not_found")

    def test_plain_page_not_treated_as_checksum(self):
        body = (b"e" * 64 + b"  app.exe\n")
        r = find_official("app.exe", "https://example.com/download.html", self._fetcher(body))
        self.assertNotEqual(r.source, "checksum file from example.com")
