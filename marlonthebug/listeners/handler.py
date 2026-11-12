"""Exploit listeners — TCP/HTTP/DNS handlers for reverse connections."""

import asyncio
import contextlib
import logging
from dataclasses import dataclass

logger = logging.getLogger("marlonthebug.listeners")


@dataclass
class ListenerConfig:
    listener_type: str
    host: str = "0.0.0.0"
    port: int = 4444
    payload_type: str = ""


class ListenerHandler:
    def __init__(self, config: ListenerConfig) -> None:
        self.config = config
        self._server: asyncio.AbstractServer | None = None
        self._running = False
        self._connections: list[asyncio.StreamWriter] = []

    async def start(self) -> None:
        self._running = True
        if self.config.listener_type == "tcp":
            self._server = await asyncio.start_server(self._handle_tcp, self.config.host, self.config.port)
            logger.info("[Listener] TCP server on %s:%d", self.config.host, self.config.port)
        elif self.config.listener_type == "http":
            self._server = await asyncio.start_server(self._handle_http, self.config.host, self.config.port)
            logger.info("[Listener] HTTP server on %s:%d", self.config.host, self.config.port)

    async def stop(self) -> None:
        self._running = False
        for writer in self._connections:
            with contextlib.suppress(Exception):
                writer.close()
        self._connections.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        addr = f"{peername[0]}:{peername[1]}" if peername else "unknown"
        logger.info("[Listener] TCP connection from %s", addr)
        self._connections.append(writer)

        try:
            writer.write(b"Connected to MarlonTheBug listener.\n")
            await writer.drain()

            while self._running:
                data = await asyncio.wait_for(reader.readline(), timeout=300)
                if not data:
                    break
                logger.info("[Listener][%s] %s", addr, data.decode("utf-8", errors="replace").rstrip())
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if writer in self._connections:
                self._connections.remove(writer)
            if not writer.is_closing():
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            line = request_line.decode("utf-8", errors="replace").strip()

            headers: dict[str, str] = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=2)
                hl = header_line.decode("utf-8", errors="replace").strip()
                if not hl:
                    break
                if ":" in hl:
                    key, val = hl.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

            if "content-length" in headers:
                cl = int(headers["content-length"])
                await asyncio.wait_for(reader.readexactly(cl), timeout=5)

            peername = writer.get_extra_info("peername")
            addr = f"{peername[0]}:{peername[1]}" if peername else "unknown"
            logger.info("[Listener][HTTP][%s] %s", addr, line)

            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
            writer.write(response)
            await writer.drain()
        except (TimeoutError, ConnectionResetError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()


class ListenerPool:
    def __init__(self) -> None:
        self._listeners: dict[str, ListenerHandler] = {}

    async def start(self, name: str, config: ListenerConfig) -> None:
        if name in self._listeners:
            raise ValueError(f"Listener '{name}' already exists")
        handler = ListenerHandler(config)
        await handler.start()
        self._listeners[name] = handler

    async def stop(self, name: str) -> None:
        handler = self._listeners.pop(name, None)
        if handler:
            await handler.stop()

    async def stop_all(self) -> None:
        for name in list(self._listeners.keys()):
            await self.stop(name)

    def list(self) -> dict[str, bool]:
        return {name: h._running for name, h in self._listeners.items()}
