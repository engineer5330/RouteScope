"""Typed, JSON-ready diagnostic results."""

from dataclasses import dataclass, field
from typing import Literal

FamilyChoice = Literal["ipv4", "ipv6", "both"]
DnsStatus = Literal["resolved", "literal", "error", "timeout"]
TcpStatus = Literal["connected", "refused", "timeout", "unreachable", "error"]
TlsStatus = Literal["verified", "certificate_error", "handshake_error", "timeout", "skipped"]
OverallStatus = Literal["ok", "partial", "failed"]


@dataclass(frozen=True)
class Options:
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    family: FamilyChoice = "both"
    timeout_s: float = 3.0
    concurrency: int = 32
    output_format: Literal["text", "json"] = "text"
    tls: bool = False

    def to_dict(self) -> dict:
        return {
            "hosts": list(self.hosts),
            "ports": list(self.ports),
            "family": self.family,
            "timeout_s": self.timeout_s,
            "concurrency": self.concurrency,
            "format": self.output_format,
            "tls": self.tls,
        }


@dataclass(frozen=True)
class Address:
    value: str
    family: Literal["ipv4", "ipv6"]

    def to_dict(self) -> dict:
        return {"address": self.value, "family": self.family}


@dataclass
class DnsResult:
    status: DnsStatus
    duration_ms: float
    addresses: list[Address] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "duration_ms": self.duration_ms,
            "addresses": [address.to_dict() for address in self.addresses],
            "error": self.error,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class TlsResult:
    status: TlsStatus
    duration_ms: float
    version: str | None = None
    cipher: str | None = None
    certificate_not_before: str | None = None
    certificate_not_after: str | None = None
    error: str | None = None
    verify_code: int | None = None

    def to_dict(self) -> dict:
        return dict(vars(self))


@dataclass(frozen=True)
class TcpResult:
    address: str
    family: Literal["ipv4", "ipv6"]
    port: int
    status: TcpStatus
    duration_ms: float
    error: str | None = None
    tls: TlsResult | None = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "family": self.family,
            "port": self.port,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "tls": self.tls.to_dict() if self.tls is not None else None,
        }


@dataclass
class TargetResult:
    host: str
    dns: DnsResult
    tcp: list[TcpResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "dns": self.dns.to_dict(),
            "tcp": [check.to_dict() for check in self.tcp],
        }


@dataclass
class DiagnosisReport:
    options: Options
    targets: list[TargetResult]
    status: OverallStatus
    duration_ms: float
    summary: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "schema_version": 2,
            "parameters": self.options.to_dict(),
            "status": self.status,
            "duration_ms": self.duration_ms,
            "targets": [target.to_dict() for target in self.targets],
            "summary": self.summary,
        }
