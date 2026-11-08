"""TCP probes against numeric IP addresses only."""

import asyncio
import errno
import socket
from collections.abc import Awaitable, Callable
from time import perf_counter

from .models import Address, TcpResult, TcpStatus

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
) -> TcpResult:
    family = socket.AF_INET if address.family == "ipv4" else socket.AF_INET6
    started = perf_counter()
    sock: socket.socket | None = None
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
        return TcpResult(address.value, address.family, port, "connected", (perf_counter() - started) * 1000)
    except TimeoutError:
        return TcpResult(address.value, address.family, port, "timeout", (perf_counter() - started) * 1000, "connection timed out")
    except OSError as exc:
        return TcpResult(address.value, address.family, port, _classify(exc), (perf_counter() - started) * 1000, str(exc))
    except Exception as exc:
        return TcpResult(address.value, address.family, port, "error", (perf_counter() - started) * 1000, str(exc))
    finally:
        if sock is not None:
            sock.close()
