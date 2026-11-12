"""OOB Collaborator server — async DNS + HTTP for blind vulnerability detection."""

import asyncio
import contextlib
import logging
import random
import socket
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger("marlonthebug.collaborator")


@dataclass
class CallbackRecord:
    token: str
    source_ip: str
    request_type: str
    data: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class CollaboratorServer:
    def __init__(
        self,
        http_host: str = "0.0.0.0",
        http_port: int = 8080,
        dns_host: str = "0.0.0.0",
        dns_port: int = 5353,
        token_length: int = 16,
    ) -> None:
        self.http_host = http_host
        self.http_port = http_port
        self.dns_host = dns_host
        self.dns_port = dns_port
        self.token_length = token_length
        self._callbacks: dict[str, list[CallbackRecord]] = {}
        self._http_server: asyncio.AbstractServer | None = None
        self._dns_transport: asyncio.DatagramTransport | None = None
        self._running = False

    @staticmethod
    def generate_token(length: int = 16) -> str:
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    def get_callbacks(self, token: str) -> list[CallbackRecord]:
        return self._callbacks.get(token, [])

    def has_callback(self, token: str) -> bool:
        return len(self.get_callbacks(token)) > 0

    def clear(self, token: str) -> None:
        self._callbacks.pop(token, None)

    def _record(self, token: str, source_ip: str, request_type: str, data: str) -> None:
        record = CallbackRecord(
            token=token,
            source_ip=source_ip,
            request_type=request_type,
            data=data,
        )
        if token not in self._callbacks:
            self._callbacks[token] = []
        self._callbacks[token].append(record)
        logger.info("[Collaborator] Callback from %s for token %s (%s): %s", source_ip, token, request_type, data[:100])

    async def start(self) -> None:
        self._running = True
        loop = asyncio.get_event_loop()

        self._http_server = await asyncio.start_server(self._handle_http, self.http_host, self.http_port)
        logger.info("[Collaborator] HTTP server on %s:%d", self.http_host, self.http_port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.dns_host, self.dns_port))
            sock.setblocking(False)
            self._dns_transport, _ = await loop.create_datagram_endpoint(lambda: self._DNSProtocol(self), sock=sock)
            logger.info("[Collaborator] DNS server on %s:%d", self.dns_host, self.dns_port)
        except PermissionError:
            logger.warning("[Collaborator] Cannot bind DNS on port %d (need root). DNS disabled.", self.dns_port)

    async def stop(self) -> None:
        self._running = False
        if self._http_server:
            self._http_server.close()
            await self._http_server.wait_closed()
        if self._dns_transport:
            self._dns_transport.close()

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            line = request_line.decode("utf-8", errors="replace").strip()
            parts = line.split()
            if len(parts) < 2:
                return

            method = parts[0]
            path = parts[1]

            headers: dict[str, str] = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=2)
                hl = header_line.decode("utf-8", errors="replace").strip()
                if not hl:
                    break
                if ":" in hl:
                    key, val = hl.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

            body = b""
            if "content-length" in headers:
                cl = int(headers["content-length"])
                body = await asyncio.wait_for(reader.readexactly(cl), timeout=5)

            peername = writer.get_extra_info("peername")
            source_ip = peername[0] if peername else "unknown"

            parts_path = path.strip("/").split("/")
            if parts_path:
                token = parts_path[0]
                self._record(token, source_ip, f"HTTP_{method}", body.decode("utf-8", errors="replace")[:500])

            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
            writer.write(response)
            await writer.drain()
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    class _DNSProtocol(asyncio.DatagramProtocol):
        def __init__(self, server: "CollaboratorServer") -> None:
            self._server = server
            self._transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport: asyncio.DatagramTransport) -> None:
            self._transport = transport

        def datagram_received(self, data: bytes, addr: tuple) -> None:
            try:
                domain = self._parse_query(data)
                if domain:
                    parts = domain.lower().rstrip(".").split(".")
                    if parts:
                        token = parts[0]
                        self._server._record(token, addr[0], "DNS", domain)
                    response = self._build_response(data, addr)
                    if self._transport:
                        self._transport.sendto(response, addr)
            except Exception as e:
                logger.debug("DNS handler error: %s", e)

        @staticmethod
        def _parse_query(data: bytes) -> str:
            if len(data) < 12:
                return ""
            try:
                domain_parts: list[str] = []
                pos = 12
                while pos < len(data):
                    length = data[pos]
                    if length == 0:
                        break
                    if length >= 64 or pos + 1 + length > len(data):
                        break
                    pos += 1
                    try:
                        domain_parts.append(data[pos : pos + length].decode("ascii", errors="ignore"))
                    except Exception:
                        domain_parts.append("unknown")
                    pos += length
                return ".".join(domain_parts) if domain_parts else ""
            except Exception:
                return ""

        @staticmethod
        def _build_response(query: bytes, addr: tuple) -> bytes:
            if len(query) < 12:
                return query[:2] + b"\x81\x82" + query[4:]
            response = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            response += query[12:]
            response += b"\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
            return response

        def error_received(self, exc: Exception) -> None:
            logger.debug("DNS protocol error: %s", exc)

        def connection_lost(self, exc: Exception | None) -> None:
            pass
