"""Careful fetching of a user-supplied URL.

The app runs on the user's own machine, so a pasted link must never be a
back door into the local network or oversized/hostile content:
  - http/https only
  - the host must resolve to public IP addresses only (no loopback,
    private, link-local, multicast or reserved ranges); every redirect
    hop is re-checked
  - response body is capped and read with a hard timeout
"""
import http.client
import ipaddress
import socket
import ssl
import zlib
from urllib.parse import urlparse

MAX_BYTES = 2 * 1024 * 1024  # pages and checksum files are small
TIMEOUT = 10
MAX_REDIRECTS = 3
USER_AGENT = "SumProofy/0.1 (+https://github.com/)"
DRAIN_CAP = 64 * 1024  # most we ever read of a redirect or error body


class FetchError(Exception):
    """The page could not be fetched safely."""


def _undress_body(body, encoding, max_bytes):
    """Undo gzip/deflate content encoding, with the same size cap as the wire.

    We ask for "identity", but some sites compress anyway. The decoded size
    is capped too: a small compressed bomb must not unpack into gigabytes.
    """
    enc = (encoding or "identity").lower().strip()
    if enc in ("identity", ""):
        return body
    if enc == "gzip":
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif enc == "deflate":
        decomp = zlib.decompressobj()
    else:
        raise FetchError(f"The site compressed its answer in a way this app cannot read ({enc}).")
    try:
        out = decomp.decompress(body, max_bytes + 1)
    except zlib.error:
        raise FetchError("The site's compressed answer was not readable.")
    if len(out) > max_bytes:
        raise FetchError("That page is too large to read safely.")
    return out


def _drain(resp, cap=DRAIN_CAP):
    """Read and discard at most cap bytes of a body we do not need."""
    remaining = cap
    while remaining > 0:
        block = resp.read(min(65536, remaining))
        if not block:
            break
        remaining -= len(block)


# Ranges the standard "is_private/is_global" flags have not covered
# consistently across Python versions: refuse them explicitly.
_REFUSED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / Tailscale
    ipaddress.ip_network("fec0::/10"),      # deprecated IPv6 site-local
)


def _is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if any(ip in net for net in _REFUSED_NETWORKS):
        return False
    # is_global is the primary gate; the explicit flags keep older Python
    # versions (with weaker is_global tables) honest too.
    if not ip.is_global:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def resolve_public_ips(host, port, resolver=socket.getaddrinfo):
    """Public IPs for host, or FetchError. All resolved addresses must be public."""
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError(f"Could not look up that address: {exc}")
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise FetchError("That address did not resolve.")
    for ip in ips:
        if not _is_public_ip(ip):
            raise FetchError("That link points at a local or private address. Refused.")
    return ips


def fetch(url, max_bytes=MAX_BYTES, timeout=TIMEOUT, _resolver=socket.getaddrinfo,
          _connect=None):
    """Fetch url and return (body_bytes, final_url).

    _resolver and _connect are injectable for tests. _connect(ip, port,
    use_tls, server_name, timeout) must return an http.client connection.
    """
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise FetchError("Only http and https links are allowed.")
        host = parsed.hostname
        if not host:
            raise FetchError("That link has no host.")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise FetchError("That link's host name is not valid.")
        try:
            explicit_port = parsed.port
        except ValueError:
            raise FetchError("That link's port is not valid.")
        port = explicit_port or (443 if scheme == "https" else 80)
        ips = resolve_public_ips(host, port, resolver=_resolver)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query

        last_exc = None
        conn = None
        for ip in ips:
            try:
                if _connect is not None:
                    conn = _connect(ip, port, scheme == "https", host, timeout)
                else:
                    if scheme == "https":
                        ctx = ssl.create_default_context()
                        raw = socket.create_connection((ip, port), timeout=timeout)
                        tls = ctx.wrap_socket(raw, server_hostname=host)
                        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
                        conn.sock = tls
                    else:
                        conn = http.client.HTTPConnection(host, port, timeout=timeout)
                        conn.sock = socket.create_connection((ip, port), timeout=timeout)
                break
            except OSError as exc:
                last_exc = exc
                conn = None
        if conn is None:
            raise FetchError(f"Could not connect: {last_exc}")
        try:
            conn.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host if explicit_port is None else f"{host}:{port}")
            conn.putheader("User-Agent", USER_AGENT)
            conn.putheader("Accept", "*/*")
            conn.putheader("Accept-Encoding", "identity")
            conn.endheaders()
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                _drain(resp)
                if not loc:
                    raise FetchError("The site sent a redirect with no target.")
                from urllib.parse import urljoin
                current = urljoin(current, loc)
                continue
            if resp.status != 200:
                _drain(resp)
                raise FetchError(f"The site answered with an error (HTTP {resp.status}).")
            chunks = []
            got = 0
            while True:
                block = resp.read(min(65536, max_bytes + 1 - got))
                if not block:
                    break
                chunks.append(block)
                got += len(block)
                if got > max_bytes:
                    raise FetchError("That page is too large to read safely.")
            return _undress_body(b"".join(chunks), resp.getheader("Content-Encoding"), max_bytes), current
        finally:
            try:
                conn.close()
            except Exception:
                pass
    raise FetchError("Too many redirects.")
