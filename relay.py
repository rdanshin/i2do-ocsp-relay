#!/usr/bin/env python3
"""OCSP staple relay for the RF prod VPS. Bind on an EU host; allow only prod IPs."""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ALLOW_IPS = tuple(
    part.strip()
    for part in os.environ.get("ALLOW_IPS", "").split(",")
    if part.strip()
)
RELAY_TOKEN = os.environ.get("RELAY_TOKEN", "").strip()
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
OCSP_TIMEOUT = int(os.environ.get("OCSP_TIMEOUT", "8"))
MAX_BODY = 100_000


def ip_allowed(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for raw in ALLOW_IPS:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if ip in network:
            return True
    return False


def ocsp_url_ok(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in (80, 443):
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def split_chain(pem: str, dest: str) -> tuple[str, str]:
    index = 0
    handle = None
    paths: list[str] = []
    for line in pem.splitlines(keepends=True):
        if "BEGIN CERTIFICATE" in line:
            index += 1
            path = os.path.join(dest, f"{index:02d}.pem")
            paths.append(path)
            if handle:
                handle.close()
            handle = open(path, "w", encoding="utf-8")
        if handle:
            handle.write(line)
    if handle:
        handle.close()
    if len(paths) < 2:
        raise ValueError("fullchain must include leaf and issuer")
    return paths[0], paths[1]


def fetch_staple(pem: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="ocsp-") as work:
        leaf, issuer = split_chain(pem, work)
        url = subprocess.check_output(
            ["openssl", "x509", "-in", leaf, "-noout", "-ocsp_uri"],
            text=True,
        ).strip()
        if not url or not ocsp_url_ok(url):
            raise ValueError(f"refusing OCSP URI {url!r}")
        host = urlparse(url).hostname or ""
        resp_path = os.path.join(work, "staple.der")
        completed = subprocess.run(
            [
                "openssl",
                "ocsp",
                "-no_nonce",
                "-issuer",
                issuer,
                "-cert",
                leaf,
                "-url",
                url,
                "-header",
                f"Host={host}",
                "-respout",
                resp_path,
                "-timeout",
                str(OCSP_TIMEOUT),
                "-verify_other",
                issuer,
                "-trust_other",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=OCSP_TIMEOUT + 4,
        )
        combined = (completed.stdout or "") + (completed.stderr or "")
        if completed.returncode != 0 or ": good" not in combined:
            raise RuntimeError(combined.strip() or "openssl ocsp failed")
        with open(resp_path, "rb") as fh:
            data = fh.read()
        if not data:
            raise RuntimeError("empty OCSP response")
        return data


class Handler(BaseHTTPRequestHandler):
    server_version = "i2do-ocsp-relay/1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"OCSP-relay {self.address_string()} {fmt % args}")

    def _deny(self, code: int, message: str) -> None:
        body = message.encode() + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/health":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._deny(404, "not found")

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/ocsp":
            self._deny(404, "not found")
            return
        peer = self.client_address[0]
        if not ALLOW_IPS:
            self._deny(500, "ALLOW_IPS is not set")
            return
        if not ip_allowed(peer):
            self._deny(403, "forbidden")
            return
        if RELAY_TOKEN:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {RELAY_TOKEN}":
                self._deny(401, "unauthorized")
                return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._deny(400, "bad content-length")
            return
        if length < 64 or length > MAX_BODY:
            self._deny(400, "bad body size")
            return
        pem = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            staple = fetch_staple(pem)
        except Exception as exc:
            self._deny(502, str(exc)[:300])
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(staple)))
        self.end_headers()
        self.wfile.write(staple)


def main() -> None:
    if not ALLOW_IPS:
        raise SystemExit("ALLOW_IPS must list prod public IPs or CIDRs")
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"OCSP-relay listen {LISTEN_HOST}:{LISTEN_PORT} allow {','.join(ALLOW_IPS)}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
