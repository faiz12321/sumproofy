"""Local-only web server for SumProofy.

Safety model (same as the proven pattern from our other local tools):
  - binds 127.0.0.1 only, on a random port
  - every request must carry the right Host header (blocks DNS rebinding)
  - every API call must carry a random per-run token in X-Token (blocks CSRF
    from other websites, which cannot set that header)
  - no CORS headers, small request bodies, read-only actions only
"""
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import hashing, lookup, signature, verdict
from .fetch import fetch as safe_fetch

MAX_BODY = 64 * 1024
_UI_PATH = os.path.join(os.path.dirname(__file__), "ui.html")


def load_ui():
    with open(_UI_PATH, "r", encoding="utf-8") as fh:
        return fh.read()


CHECK_DEADLINE = 60  # seconds; a single check must answer within this


def make_handler(token, port, fetcher=None, hasher=None, signer=None, browser=None,
                 check_deadline=CHECK_DEADLINE):
    fetcher = fetcher or safe_fetch
    hasher = hasher or hashing.sha256_file
    signer = signer or signature.check_signature
    ui_template = load_ui()

    class Handler(BaseHTTPRequestHandler):
        server_version = "SumProofy/0.1"
        protocol_version = "HTTP/1.1"

        # -- helpers -------------------------------------------------------
        def log_message(self, *args):  # keep the console quiet
            pass

        def _host_ok(self):
            host = self.headers.get("Host", "")
            return host in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}")

        def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj), "application/json; charset=utf-8")

        def _token_ok(self):
            return secrets.compare_digest(self.headers.get("X-Token", ""), token)

        # -- routes --------------------------------------------------------
        def do_GET(self):
            if not self._host_ok():
                self._send(403, "Forbidden")
                return
            path = self.path.split("?", 1)[0]
            if path == "/":
                page = ui_template.replace("window.__TOKEN__", json.dumps(token))
                self._send(200, page, "text/html; charset=utf-8")
            elif path == "/api/health":
                if not self._token_ok():
                    self._send(403, "Forbidden")
                    return
                self._json({"ok": True})
            elif path == "/api/browse":
                if not self._token_ok():
                    self._send(403, "Forbidden")
                    return
                self._json({"path": self._browse()})
            else:
                self._send(404, "Not found")

        def do_POST(self):
            if not self._host_ok():
                self._send(403, "Forbidden")
                return
            if self.path.split("?", 1)[0] != "/api/check":
                self._send(404, "Not found")
                return
            if not self._token_ok():
                self._send(403, "Forbidden")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send(400, "Bad request")
                return
            if length < 0 or length > MAX_BODY:
                self._send(400, "Bad request")
                return
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
                path = data.get("path")
                page_url = data.get("page_url") or ""
                if not isinstance(path, str) or not isinstance(page_url, str):
                    raise ValueError
                if len(path) > 4096 or len(page_url) > 4096:
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                self._json({"error": "The request was not readable."}, code=400)
                return
            self._json(self._check_with_deadline(path.strip(), page_url.strip()))

        # -- work ----------------------------------------------------------
        def _check_with_deadline(self, path, page_url):
            # A stuck hash, lookup or signature call must never pin the
            # request open: the whole check answers within check_deadline,
            # and the file read is then actually told to stop (the lookup
            # and signature calls carry their own timeouts).
            box = {}
            done = threading.Event()
            cancelled = threading.Event()

            def work():
                try:
                    box["out"] = self._check(path, page_url, cancelled)
                except Exception:
                    box["out"] = {"error": "The check failed unexpectedly."}
                finally:
                    done.set()

            threading.Thread(target=work, daemon=True).start()
            if done.wait(check_deadline):
                return box["out"]
            cancelled.set()
            return {"error": "The check was taking too long, so it was stopped. Try again."}
        def _browse(self):
            # The dialog itself runs on the main thread (see picker.py);
            # browser is None when there is no dialog loop, and the page
            # falls back to the manual path box.
            if browser is None:
                return None
            try:
                return browser()
            except Exception:
                return None

        def _check(self, path, page_url, cancelled=None):
            def stop_when_cancelled(_done, _total):
                if cancelled is not None and cancelled.is_set():
                    raise hashing.HashError("The check was taking too long, so it was stopped.")

            try:
                if cancelled is not None and hasher is hashing.sha256_file:
                    local = hasher(path, progress=stop_when_cancelled)
                else:
                    local = hasher(path)
            except hashing.HashError as exc:
                return {"error": str(exc)}
            except Exception:
                return {"error": "The file could not be read."}
            try:
                official = lookup.find_official(os.path.basename(path), page_url, fetcher)
            except Exception:
                official = lookup.LookupResult("error", detail="The lookup failed unexpectedly.")
            sig = {}
            try:
                sig = signer(path)
            except Exception:
                sig = {"status": "unknown", "signer": None, "detail": "Signature check failed."}
            v, explanation = verdict.compare(local, official)
            out = {"file_name": os.path.basename(path), "local_hash": local,
                   "official": official.as_dict(), "verdict": v,
                   "explanation": explanation, "signature": sig}
            if sig.get("status") == "HashMismatch" and v == "match":
                out["verdict"] = "mismatch"
                out["explanation"] = "The fingerprint matches, but Windows says the file was changed after signing. Do not trust it."
            return out

    return Handler


def serve(port=0, token=None, **kwargs):
    """Start the server; returns (httpd, port, token)."""
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(token, port, **kwargs))
    real_port = httpd.server_address[1]
    # Rebuild the handler with the real port so the Host check is exact,
    # before any request can be served.
    httpd.RequestHandlerClass = make_handler(token, real_port, **kwargs)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
    return httpd, real_port, token
