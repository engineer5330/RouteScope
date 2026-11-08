"""Loopback-only TLS fixtures, shared by integration and subprocess tests."""

import asyncio
import contextlib
import ssl
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "tls"


def client_context(trusted=True):
    # Explicit contexts make trust tests independent of the developer's machine.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trusted:
        context.load_verify_locations(cafile=str(FIXTURES / "ca.pem"))
    return context


class LocalServer:
    def __init__(self, mode="tls", host="127.0.0.1", version=None):
        self.mode = mode
        self.host = host
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(FIXTURES / "server.pem", FIXTURES / "server.key")
        if version is not None:
            self.context.minimum_version = version
            self.context.maximum_version = version
        self.names = []
        self.context.set_servername_callback(lambda session, name, context: self.names.append(name))
        self.connections = 0
        self.tasks = set()
        self.writers = set()
        self.received = asyncio.Event()
        self.closed = asyncio.Queue()
        self.application_data = []

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.handle, self.host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.connections += 1
        try:
            if self.mode == "tls":
                await writer.start_tls(self.context, ssl_handshake_timeout=5)
                self.application_data.append(await reader.read())
            elif self.mode == "plain":
                writer.write(b"This is a plain TCP service\r\n")
                await writer.drain()
            else:
                await reader.read(1)
                self.received.set()
                await reader.read()
        except (OSError, TimeoutError):
            # Untrusted certificates, cancellation and abrupt close are expected.
            pass
        finally:
            writer.transport.abort()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 5)
            self.writers.discard(writer)
            self.tasks.discard(task)
            self.closed.put_nowait(None)

    async def __aexit__(self, *args):
        self.server.close()
        await self.server.wait_closed()
        for writer in self.writers:
            writer.transport.abort()
        pending = list(self.tasks)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
