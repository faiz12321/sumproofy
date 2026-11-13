import json
import os
import unittest

from test_server import ServerHarness


class ServerSecurityCase(ServerHarness, unittest.TestCase):
    # -- hostile requests ----------------------------------------------------
    def test_api_without_token_forbidden(self):
        status, _, _ = self.req("GET", "/api/health")
        self.assertEqual(status, 403)

    def test_api_wrong_token_forbidden(self):
        status, _, _ = self.req("GET", "/api/health", token="wrong")
        self.assertEqual(status, 403)

    def test_wrong_host_forbidden(self):
        status, _, _ = self.req("GET", "/", host=f"evil.example.com:{self.port}", token=self.token)
        self.assertEqual(status, 403)

    def test_post_without_token_forbidden(self):
        status, _, _ = self.req("POST", "/api/check",
                                body=json.dumps({"path": self.file, "page_url": ""}))
        self.assertEqual(status, 403)

    def test_nonstring_fields_rejected(self):
        status, _, _ = self.req("POST", "/api/check",
                                body=json.dumps({"path": ["x"], "page_url": ""}), token=self.token)
        self.assertEqual(status, 400)

    def test_oversized_body_rejected(self):
        status, _, _ = self.req("POST", "/api/check",
                                body=json.dumps({"path": "x" * 70000, "page_url": ""}),
                                token=self.token)
        self.assertEqual(status, 400)

    def test_garbage_json_rejected(self):
        status, _, _ = self.req("POST", "/api/check", body="{not json", token=self.token)
        self.assertEqual(status, 400)

    def test_unknown_route_404(self):
        status, _, _ = self.req("GET", "/api/nope", token=self.token)
        self.assertEqual(status, 404)

    def test_xss_filename_stays_json(self):
        evil = os.path.join(self.dir.name, "x & 'onclick'=alert(1).exe")
        with open(evil, "wb") as fh:
            fh.write(b"x")
        out = self.check(evil, "")
        # the API answer is JSON; the UI inserts it with textContent
        self.assertEqual(out["file_name"], "x & 'onclick'=alert(1).exe")
        _, _, page = self.req("GET", "/")
        self.assertNotIn(b"onerror=alert", page)

    def test_check_never_writes(self):
        before = set(os.listdir(self.dir.name))
        self.check(self.file, "")
        self.assertEqual(set(os.listdir(self.dir.name)), before)



    def test_csp_allows_same_origin_api_calls(self):
        # Regression: the UI's own fetch() calls are subject to the page CSP.
        # Without connect-src 'self', default-src 'none' blocks every API call
        # and the app is dead in a real browser.
        status, headers, _ = self.req("GET", "/")
        self.assertEqual(status, 200)
        csp = headers.get("Content-Security-Policy", "")
        self.assertIn("connect-src 'self'", csp)



    def test_negative_content_length_rejected(self):
        import http.client as hc
        conn = hc.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/check")
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("X-Token", self.token)
        conn.putheader("Content-Length", "-1")
        conn.endheaders(b"")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 400)


if __name__ == "__main__":
    unittest.main()
