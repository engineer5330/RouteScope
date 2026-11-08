"""TCP probes against numeric IP addresses only."""

import asyncio
import errno
import socket
import ssl
from collections.abc import Awaitable, Callable
from time import perf_counter

from .models import Address, TcpResult, TcpStatus, TlsResult
from .tls import handshake

Connector = Callable[[socket.socket, tuple], Awaitable[None]]


def _classify(exc: OSError) -> TcpStatus:
    if exc.errno == errno.ECONNREFUSED:
        return "refused"
    if exc.errno == errno.ETIMEDOUT:
        return "timeout"
    if exc.errno in {
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.EHOSTDOWN,
    }:
        return "unreachable"
    return "error"


async def probe(
    address: Address,
    port: int,
    timeout_s: float,
    connector: Connector | None = None,
    *,
    tls_host: str | None = None,
    tls_context: ssl.SSLContext | None = None,
) -> TcpResult:
    family = socket.AF_INET if address.family == "ipv4" else socket.AF_INET6
    started = perf_counter()
    sock: socket.socket | None = None
    skipped = TlsResult("skipped", 0.0, error="TCP connection was not established") if tls_host is not None else None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        connect = connector or asyncio.get_running_loop().sock_connect
        if family == socket.AF_INET6:
            host, separator, zone = address.value.partition("%")
            scope_id = (int(zone) if zone.isdecimal() else socket.if_nametoindex(zone)) if separator else 0
            # A %zone in host would make asyncio fall back to getaddrinfo.
            endpoint = (host, port, 0, scope_id)
        else:
            endpoint = (address.value, port)
        await asyncio.wait_for(connect(sock, endpoint), timeout=timeout_s)
        tcp_duration_ms = (perf_counter() - started) * 1000
        tls = await handshake(sock, tls_host, timeout_s, tls_context) if tls_host is not None else None
        return TcpResult(address.value, address.family, port, "connected", tcp_duration_ms, tls=tls)
    except TimeoutError:
        return TcpResult(address.value, address.family, port, "timeout", (perf_counter() - started) * 1000, "connection timed out", skipped)
    except OSError as exc:
        return TcpResult(address.value, address.family, port, _classify(exc), (perf_counter() - started) * 1000, str(exc), skipped)
    except Exception as exc:
        return TcpResult(address.value, address.family, port, "error", (perf_counter() - started) * 1000, str(exc), skipped)
    finally:
        if sock is not None:
            sock.close()
