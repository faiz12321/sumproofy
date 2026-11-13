import http.client
import io
import socket
import unittest

from sumproofy.fetch import fetch, FetchError, _is_public_ip


def resolver_for(*ips):
    def r(host, port, type=socket.SOCK_STREAM):
        return [(None, None, None, None, (ip, port)) for ip in ips]
    return r


class FakeResponse:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self._body = io.BytesIO(body)
        self._headers = headers or {}

    def getheader(self, name):
        return self._headers.get(name)

    def read(self, n=-1):
        return self._body.read(n if n and n > 0 else -1)


class FakeConn:
    responses = []
    requests = []

    def __init__(self, *a, **kw):
        pass

    def putrequest(self, method, target, skip_host, skip_accept_encoding):
        FakeConn.requests.append((method, target))

    def putheader(self, *a):
        pass

    def endheaders(self):
        pass

    def getresponse(self):
        return FakeConn.responses.pop(0)

    def close(self):
        pass


def connector(ip, port, tls, host, timeout):
    return FakeConn()


class TestFetch(unittest.TestCase):
    def setUp(self):
        FakeConn.responses = []
        FakeConn.requests = []

    def test_public_ip_check(self):
        for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1",
                    "0.0.0.0", "::1", "fc00::1", "224.0.0.1"):
            self.assertFalse(_is_public_ip(bad), bad)
        self.assertTrue(_is_public_ip("93.184.216.34"))
        self.assertTrue(_is_public_ip("2606:4700:4700::1111"))

    def test_private_ip_refused(self):
        with self.assertRaises(FetchError) as ctx:
            fetch("http://192.168.0.1/x", _resolver=resolver_for("192.168.0.1"), _connect=connector)
        self.assertIn("local or private", str(ctx.exception))

    def test_one_bad_ip_among_many_refused(self):
        with self.assertRaises(FetchError):
            fetch("http://x.test/", _resolver=resolver_for("93.184.216.34", "127.0.0.1"),
                  _connect=connector)

    def test_scheme_refused(self):
        for bad in ("file:///etc/passwd", "ftp://x.test/f", "gopher://x/"):
            with self.assertRaises(FetchError):
                fetch(bad, _resolver=resolver_for("93.184.216.34"), _connect=connector)

    def test_success(self):
        FakeConn.responses.append(FakeResponse(200, b"hello"))
        body, final = fetch("http://x.test/page", _resolver=resolver_for("93.184.216.34"),
                            _connect=connector)
        self.assertEqual(body, b"hello")
        self.assertEqual(final, "http://x.test/page")

    def test_oversize_refused(self):
        FakeConn.responses.append(FakeResponse(200, b"x" * (2 * 1024 * 1024 + 10)))
        with self.assertRaises(FetchError) as ctx:
            fetch("http://x.test/big", _resolver=resolver_for("93.184.216.34"), _connect=connector)
        self.assertIn("too large", str(ctx.exception))

    def test_redirect_followed_and_rechecked(self):
        FakeConn.responses.append(FakeResponse(302, headers={"Location": "http://x.test/2"}))
        FakeConn.responses.append(FakeResponse(200, b"ok"))
        body, final = fetch("http://x.test/1", _resolver=resolver_for("93.184.216.34"),
                            _connect=connector)
        self.assertEqual((body, final), (b"ok", "http://x.test/2"))

    def test_redirect_to_private_refused(self):
        def r2(host, port, type=socket.SOCK_STREAM):
            ip = "127.0.0.1" if host == "evil.test" else "93.184.216.34"
            return [(None, None, None, None, (ip, port))]
        FakeConn.responses.append(FakeResponse(302, headers={"Location": "http://evil.test/x"}))
        with self.assertRaises(FetchError) as ctx:
            fetch("http://x.test/1", _resolver=r2, _connect=connector)
        self.assertIn("local or private", str(ctx.exception))

    def test_too_many_redirects(self):
        for _ in range(6):
            FakeConn.responses.append(FakeResponse(302, headers={"Location": "http://x.test/next"}))
        with self.assertRaises(FetchError) as ctx:
            fetch("http://x.test/1", _resolver=resolver_for("93.184.216.34"), _connect=connector)
        self.assertIn("redirect", str(ctx.exception).lower())

    def test_http_error(self):
        FakeConn.responses.append(FakeResponse(404, b"nope"))
        with self.assertRaises(FetchError) as ctx:
            fetch("http://x.test/1", _resolver=resolver_for("93.184.216.34"), _connect=connector)
        self.assertIn("404", str(ctx.exception))

    def test_dns_failure(self):
        def bad(host, port, type=socket.SOCK_STREAM):
            raise socket.gaierror("no")
        with self.assertRaises(FetchError):
            fetch("http://x.test/", _resolver=bad, _connect=connector)



class TestContentEncoding(unittest.TestCase):
    def setUp(self):
        FakeConn.responses = []
        FakeConn.requests = []

    def _fetch(self, body, enc):
        FakeConn.responses.append(FakeResponse(200, body, {"Content-Encoding": enc}))
        return fetch("http://x.test/page", _resolver=resolver_for("93.184.216.34"),
                     _connect=connector)[0]

    def test_gzip_answer_is_decoded(self):
        import gzip
        body = gzip.compress(b"hello page")
        self.assertEqual(self._fetch(body, "gzip"), b"hello page")

    def test_deflate_answer_is_decoded(self):
        import zlib
        body = zlib.compress(b"hello page")
        self.assertEqual(self._fetch(body, "deflate"), b"hello page")

    def test_identity_unchanged(self):
        self.assertEqual(self._fetch(b"plain", "identity"), b"plain")
        self.assertEqual(self._fetch(b"plain2", None), b"plain2")

    def test_gzip_bomb_is_capped(self):
        import gzip
        body = gzip.compress(b"x" * (3 * 1024 * 1024))
        with self.assertRaises(FetchError) as ctx:
            self._fetch(body, "gzip")
        self.assertIn("too large", str(ctx.exception))

    def test_broken_gzip_is_fetch_error(self):
        with self.assertRaises(FetchError):
            self._fetch(b"not really gzip", "gzip")

    def test_unknown_encoding_is_fetch_error(self):
        with self.assertRaises(FetchError) as ctx:
            self._fetch(b"data", "br")
        self.assertIn("cannot read", str(ctx.exception))

    def test_identity_encoding_requested(self):
        recorded = []

        class HeaderConn(FakeConn):
            def putheader(self, name, value):
                recorded.append((name, value))

        FakeConn.responses.append(FakeResponse(200, b"ok"))
        fetch("http://x.test/page", _resolver=resolver_for("93.184.216.34"),
              _connect=lambda *a: HeaderConn())
        self.assertIn(("Accept-Encoding", "identity"), recorded)


class TrackingResponse(FakeResponse):
    def __init__(self, status, body=b"", headers=None):
        super().__init__(status, body, headers)
        self.bytes_read = 0

    def read(self, n=-1):
        data = super().read(n)
        self.bytes_read += len(data)
        return data


class ReviewFetchCase(unittest.TestCase):
    def setUp(self):
        FakeConn.responses = []
        FakeConn.requests = []

    def test_cgnat_refused(self):
        for ip in ("100.64.0.1", "100.127.255.254", "100.96.0.1"):
            self.assertFalse(_is_public_ip(ip), ip)
        with self.assertRaises(FetchError):
            fetch("http://100.64.0.1/x", _resolver=resolver_for("100.64.0.1"), _connect=connector)

    def test_site_local_v6_refused(self):
        for ip in ("fec0::1", "fec9::ffff"):
            self.assertFalse(_is_public_ip(ip), ip)

    def test_malformed_port_is_fetch_error(self):
        with self.assertRaises(FetchError) as ctx:
            fetch("http://example.com:abc/", _resolver=resolver_for("93.184.216.34"), _connect=connector)
        self.assertIn("port", str(ctx.exception).lower())

    def test_redirect_body_is_capped(self):
        big = TrackingResponse(301, body=b"x" * (3 * 1024 * 1024),
                               headers={"Location": "http://example.com/final"})
        FakeConn.responses = [big, FakeResponse(200, b"ok")]
        body, url = fetch("http://example.com/start",
                          _resolver=resolver_for("93.184.216.34"), _connect=connector)
        self.assertEqual(body, b"ok")
        self.assertLessEqual(big.bytes_read, 64 * 1024 + 65536)

    def test_error_body_is_capped(self):
        big = TrackingResponse(500, body=b"x" * (3 * 1024 * 1024))
        FakeConn.responses = [big]
        with self.assertRaises(FetchError):
            fetch("http://example.com/x", _resolver=resolver_for("93.184.216.34"), _connect=connector)
        self.assertLessEqual(big.bytes_read, 64 * 1024 + 65536)


if __name__ == "__main__":
    unittest.main()
