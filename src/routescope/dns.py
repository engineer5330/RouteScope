"""System resolver adapter. Its elapsed time may include local caches."""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from time import perf_counter

from .models import Address, DnsResult, FamilyChoice

MAX_ADDRESSES = 8
Resolver = Callable[..., Awaitable[list[tuple]]]


def _wanted(family: FamilyChoice, socket_family: int) -> bool:
    return family == "both" or (
        family == "ipv4" and socket_family == socket.AF_INET
    ) or (family == "ipv6" and socket_family == socket.AF_INET6)


async def resolve(
    host: str,
    family: FamilyChoice,
    timeout_s: float,
    resolver: Resolver | None = None,
) -> DnsResult:
    """Resolve a host without querying DNS for numeric IP literals.

    A timeout stops waiting; an OS resolver job already running in a thread may
    continue after cancellation.
    """
    started = perf_counter()
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        literal_family = "ipv4" if literal.version == 4 else "ipv6"
        if family != "both" and family != literal_family:
            return DnsResult(
                status="error",
                duration_ms=(perf_counter() - started) * 1000,
                error=f"{literal_family} address does not match requested {family} family",
            )
        return DnsResult(
            status="literal",
            duration_ms=(perf_counter() - started) * 1000,
            addresses=[Address(str(literal), literal_family)],
        )

    if resolver is None:
        resolver = asyncio.get_running_loop().getaddrinfo
    try:
        records = await asyncio.wait_for(
            resolver(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=timeout_s,
        )
    except TimeoutError:
        return DnsResult("timeout", (perf_counter() - started) * 1000, error="system resolution timed out")
    except Exception as exc:
        return DnsResult("error", (perf_counter() - started) * 1000, error=str(exc))

    addresses: list[Address] = []
    seen: set[tuple[str, str]] = set()
    truncated = False
    for record in records:
        socket_family = record[0]
        if not _wanted(family, socket_family):
            continue
        if socket_family not in (socket.AF_INET, socket.AF_INET6):
            continue
        value = record[4][0]
        # getaddrinfo may carry an IPv6 zone only in sockaddr's scope_id.
        if socket_family == socket.AF_INET6 and record[4][3] and "%" not in value:
            value = f"{value}%{record[4][3]}"
        label = "ipv4" if socket_family == socket.AF_INET else "ipv6"
        key = (value, label)
        if key in seen:
            continue
        seen.add(key)
        if len(addresses) < MAX_ADDRESSES:
            addresses.append(Address(value, label))
        else:
            truncated = True

    duration_ms = (perf_counter() - started) * 1000
    if not addresses:
        return DnsResult("error", duration_ms, error="no addresses for requested family")
    return DnsResult("resolved", duration_ms, addresses, truncated=truncated)
