"""Models for the independent, opt-in route tracing command."""

from dataclasses import asdict, dataclass, field
from typing import Literal

from .models import DnsResult, FamilyChoice, OverallStatus

MAX_TRACE_HOSTS = 4
MAX_HOPS = 32
MAX_PROBES = 3
MAX_WAIT = 5


@dataclass(frozen=True)
class TraceOptions:
    hosts: tuple[str, ...]
    family: FamilyChoice = "ipv4"
    max_hops: int = 16
    probes: int = 1
    timeout_s: int = 2
    output_format: Literal["text", "json"] = "text"

    def to_dict(self) -> dict:
        values = asdict(self)
        values["hosts"] = list(self.hosts)
        values["format"] = values.pop("output_format")
        return values


@dataclass
class RouteProbe:
    status: Literal["reply", "no_response", "error"]
    address: str | None = None
    rtt_ms: float | None = None
    rtt_less_than: bool = False
    annotation: str | None = None
    error: str | None = None


@dataclass
class RouteHop:
    ttl: int
    probes: list[RouteProbe] = field(default_factory=list)


@dataclass
class RouteResult:
    address: str
    family: Literal["ipv4", "ipv6"]
    status: Literal["reached", "incomplete", "timeout", "unavailable", "error"]
    duration_ms: float = 0.0
    hops: list[RouteHop] = field(default_factory=list)
    error: str | None = None
    utility: str | None = None
    returncode: int | None = None
    diagnostics: str | None = None


@dataclass
class TraceTarget:
    host: str
    dns: DnsResult
    routes: list[RouteResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"host": self.host, "dns": self.dns.to_dict(),
                "routes": [asdict(route) for route in self.routes]}


@dataclass
class TraceReport:
    options: TraceOptions
    targets: list[TraceTarget]
    status: OverallStatus
    duration_ms: float
    summary: dict[str, int]

    def to_dict(self) -> dict:
        return {"command": "trace", "schema_version": 1,
                "parameters": self.options.to_dict(), "status": self.status,
                "duration_ms": self.duration_ms,
                "targets": [target.to_dict() for target in self.targets], "summary": self.summary}
