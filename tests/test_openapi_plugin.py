"""Tests for OpenAPI/Swagger exposure discovery."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from marlonthebug.plugins.recon.openapi import OpenAPIDiscovery


def test_openapi_plugin_reports_spec_and_endpoints() -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Demo API", "version": "1.0.0"},
        "paths": {
            "/api/v1/me": {"get": {"security": [{"bearer": []}]}},
            "/api/v1/health": {"get": {}},
        },
        "components": {"securitySchemes": {"bearer": {"type": "http"}}},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/api/docs-json":
                body = json.dumps(spec).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        plugin = OpenAPIDiscovery()
        plugin._context = SimpleNamespace(endpoints=[])
        target = SimpleNamespace(host=f"127.0.0.1:{server.server_address[1]}")
        findings = []
        import asyncio

        async def collect() -> None:
            async for finding in plugin.run(
                target,
                {"base_url": f"http://127.0.0.1:{server.server_address[1]}"},
            ):
                findings.append(finding)

        asyncio.run(collect())
        assert len(findings) == 1
        finding = findings[0]
        assert "OpenAPI expuesta" in finding.title
        assert finding.evidence["path_count"] == 2
        assert finding.evidence["security_schemes"] == ["bearer"]
        assert any(url.endswith("/api/v1/me") for url in plugin._context.endpoints)
    finally:
        server.shutdown()
