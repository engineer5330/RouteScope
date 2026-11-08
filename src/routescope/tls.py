"""Verified TLS over an existing nonblocking TCP socket; never connects or resolves."""

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from time import perf_counter

from .models import TlsResult


def server_identity(host: str) -> str:
    """Names supply SNI and hostname verification; IPs verify IP SAN without SNI."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    # A scope identifies a local interface, not part of the certificate identity.
    return str(address).partition("%")[0]


def _certificate_time(value: str | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc).isoformat().replace("+00:00", "Z")


async def _exchange(sock: socket.socket, host: str, context: ssl.SSLContext) -> ssl.SSLObject:
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    session = context.wrap_bio(incoming, outgoing, server_hostname=server_identity(host))
    loop = asyncio.get_running_loop()

    async def flush():
        while outgoing.pending:
            await loop.sock_sendall(sock, outgoing.read())

    # MemoryBIO keeps ownership of the socket with tcp.probe throughout. There
    # is no stream transport, second connect, application write or shutdown wait.
    while True:
        try:
            session.do_handshake()
        except ssl.SSLWantReadError:
            await flush()
            data = await loop.sock_recv(sock, 65536)
            if not data:
                incoming.write_eof()
            else:
                incoming.write(data)
        except ssl.SSLWantWriteError:
            await flush()
        else:
            await flush()
            return session


async def handshake(
    sock: socket.socket,
    host: str,
    timeout_s: float,
    context: ssl.SSLContext | None = None,
) -> TlsResult:
    """Perform only a handshake; caller always owns and closes the TCP socket."""
    started = perf_counter()
    try:
        context = context or ssl.create_default_context()
        # Loading local trust files is setup, not TLS handshake latency.
        started = perf_counter()
        session = await asyncio.wait_for(_exchange(sock, host, context), timeout_s)
        certificate = session.getpeercert()
        cipher = session.cipher()
        return TlsResult(
            "verified", (perf_counter() - started) * 1000,
            version=session.version(), cipher=cipher[0] if cipher else None,
            certificate_not_before=_certificate_time(certificate.get("notBefore")),
            certificate_not_after=_certificate_time(certificate.get("notAfter")),
        )
    except ssl.SSLCertVerificationError as exc:
        return TlsResult("certificate_error", (perf_counter() - started) * 1000,
                         error=exc.verify_message, verify_code=exc.verify_code)
    except TimeoutError:
        return TlsResult("timeout", (perf_counter() - started) * 1000, error="TLS handshake timed out")
    except Exception as exc:
        return TlsResult("handshake_error", (perf_counter() - started) * 1000, error=str(exc))
