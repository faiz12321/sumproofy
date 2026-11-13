import hashlib
import http.client
import json
import os
import tempfile
import unittest

from sumproofy.server import serve

H = "a" * 64


class ServerHarness:
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.file = os.path.join(self.dir.name, "app.exe")
        self.data = b"fake installer bytes"
        with open(self.file, "wb") as fh:
            fh.write(self.data)
        self.local = hashlib.sha256(self.data).hexdigest()
        self.routes = {}
        self.httpd, self.port, self.token = serve(
            fetcher=self._fetch, browser=lambda: self.file)
        self.addCleanup(self.httpd.shutdown)

    def _fetch(self, url):
        from sumproofy.fetch import FetchError
        r = self.routes.get(url)
        if r is None:
            raise FetchError("no route")
        return (r.encode() if isinstance(r, str) else r), url

    def req(self, method, path, body=None, token=None, host=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token is not None:
            h["X-Token"] = token
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def check(self, path, page_url=""):
        status, _, data = self.req(
            "POST", "/api/check",
            body=json.dumps({"path": path, "page_url": page_url}), token=self.token)
        self.assertEqual(status, 200)
        return json.loads(data)

class ServerCase(ServerHarness, unittest.TestCase):
    # -- happy paths -------------------------------------------------------
    def test_match(self):
        self.routes["https://maker.example/dl"] = f"app.exe SHA256: {self.local}"
        out = self.check(self.file, "https://maker.example/dl")
        self.assertEqual(out["verdict"], "match")
        self.assertEqual(out["official"]["official_hash"], self.local)

    def test_mismatch(self):
        self.routes["https://maker.example/dl"] = f"app.exe SHA256: {'b' * 64}"
        out = self.check(self.file, "https://maker.example/dl")
        self.assertEqual(out["verdict"], "mismatch")

    def test_no_official(self):
        out = self.check(self.file, "")
        self.assertEqual(out["verdict"], "no_official")
        self.assertEqual(out["local_hash"], self.local)

    def test_missing_file(self):
        out = self.check(os.path.join(self.dir.name, "nope.exe"))
        self.assertIn("error", out)

    def test_browse_uses_injected_dialog(self):
        status, _, data = self.req("GET", "/api/browse", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["path"], self.file)

    def test_health(self):
        status, _, data = self.req("GET", "/api/health", token=self.token)
        self.assertEqual((status, json.loads(data)["ok"]), (200, True))

    def test_home_page_serves_ui_with_token(self):
        status, headers, data = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(self.token.encode(), data)
        self.assertNotIn(b"Access-Control-Allow-Origin", str(headers).encode())



class ReviewServerCase(ServerHarness, unittest.TestCase):
    def test_browse_without_picker_returns_null_fast(self):
        import time
        httpd, port, token = serve(fetcher=self._fetch, browser=None)
        self.addCleanup(httpd.shutdown)
        import http.client as hc
        start = time.time()
        conn = hc.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/api/browse", headers={"Host": f"127.0.0.1:{port}", "X-Token": token})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(data, {"path": None})
        self.assertLess(time.time() - start, 5)

    def test_check_deadline_stops_stuck_check(self):
        import time
        from sumproofy.server import make_handler
        from http.server import ThreadingHTTPServer
        import threading as th

        def slow_hash(path):
            time.sleep(30)
            return "x"

        handler = make_handler(self.token, 0, fetcher=self._fetch, hasher=slow_hash,
                               check_deadline=1)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        handler = make_handler(self.token, port, fetcher=self._fetch, hasher=slow_hash,
                               check_deadline=1)
        httpd.RequestHandlerClass = handler
        th.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        import http.client as hc
        start = time.time()
        conn = hc.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("POST", "/api/check", body=json.dumps({"path": self.file, "page_url": ""}),
                     headers={"Host": f"127.0.0.1:{port}", "X-Token": self.token,
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        self.assertLess(time.time() - start, 10)
        self.assertIn("too long", data.get("error", ""))



class TestDeadlineCancellation(unittest.TestCase):
    def test_cancelled_hash_read_stops_early(self):
        # after the deadline error, the file read is actually told to stop
        import threading as th
        from sumproofy import hashing
        from sumproofy.server import make_handler
        from sumproofy.fetch import FetchError
        from http.server import ThreadingHTTPServer

        token = "tok-cancel"
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"y" * (4 * 1024 * 1024))
            big = fh.name
        self.addCleanup(os.unlink, big)

        real_hasher = hashing.sha256_file
        progress_calls = []

        def slow_hasher(path, progress=None):
            # pretends to be the default hasher; takes 5s over the read
            def slow_progress(done, total):
                progress_calls.append(done)
                if progress:
                    progress(done, total)  # raises once cancelled
                time.sleep(1)
            return real_hasher(path, progress=slow_progress)

        def no_fetch(url):
            raise FetchError("no route")

        import time
        hashing.sha256_file = slow_hasher
        self.addCleanup(setattr, hashing, "sha256_file", real_hasher)
        handler = make_handler(token, 0, fetcher=no_fetch, check_deadline=1)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass = make_handler(token, port, fetcher=no_fetch, check_deadline=1)
        th.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)

        start = time.time()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("POST", "/api/check",
                     body=json.dumps({"path": big, "page_url": ""}),
                     headers={"Host": f"127.0.0.1:{port}", "X-Token": token,
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        self.assertLess(time.time() - start, 5)
        self.assertIn("too long", data.get("error", ""))
        time.sleep(1.5)  # let the cancelled worker try its next chunk
        self.assertLessEqual(len(progress_calls), 3)  # read stopped, not all 4 chunks


if __name__ == "__main__":
    unittest.main()
