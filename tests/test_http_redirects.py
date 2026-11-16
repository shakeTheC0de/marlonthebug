"""Scope-safe redirect handling tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from marlonthebug.core.scope import ScopeConfig, ScopeGuard, ScopeViolation
from marlonthebug.http.client import AsyncHTTPClient


def _server(port_holder: dict[str, int]) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/redirect":
                location = f"http://127.0.0.1:{port_holder['port']}/final"
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/same-host":
                location = f"http://localhost:{port_holder['port']}/final"
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"<html><body>final</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


async def test_http_client_blocks_cross_host_redirect() -> None:
    holder: dict[str, int] = {}
    server = _server(holder)
    holder["port"] = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = AsyncHTTPClient(
        retries=0,
        follow_redirects=True,
        scope_guard=ScopeGuard(ScopeConfig(allowed_domains=["localhost"])),
    )
    try:
        with pytest.raises(ScopeViolation):
            await client.get(f"http://localhost:{holder['port']}/redirect")
    finally:
        await client.close()
        server.shutdown()


async def test_http_client_follows_same_host_redirect_and_keeps_scope() -> None:
    holder: dict[str, int] = {}
    server = _server(holder)
    holder["port"] = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = AsyncHTTPClient(
        retries=0,
        follow_redirects=True,
        scope_guard=ScopeGuard(ScopeConfig(allowed_domains=["localhost"])),
    )
    try:
        response = await client.get(f"http://localhost:{holder['port']}/same-host")
        assert response.status_code == 200
        assert "final" in response.body
        assert response.redirect_chain
    finally:
        await client.close()
        server.shutdown()
