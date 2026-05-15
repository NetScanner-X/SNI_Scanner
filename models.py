# ══════════════════════════════════════════════════════════════════
#  models.py
#  Shared Data Models — ParsedConfig · ScanResult · ScanStats
#
#  This module defines all core dataclasses and enums shared
#  across the entire application.
#
#  Import from here:
#    from models import ParsedConfig, ScanResult, ScanStats
#
#  No other application module should be imported here.
#  This module must remain dependency-free (stdlib only).
#
#  Author  : see AUTHORS
#  License : MIT
# ══════════════════════════════════════════════════════════════════

from __future__ import annotations

# ── Standard library ──────────────────────────────────────────────
import time
import json
import hashlib

from dataclasses import dataclass, field, asdict
from datetime    import datetime
from enum        import Enum
from typing      import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)


# ══════════════════════════════════════════════════════════════════
#  ENUMS
# ══════════════════════════════════════════════════════════════════

class Protocol(str, Enum):
    """
    Supported proxy protocols.
    Inherits from str so values can be compared directly
    with raw strings without .value access.
    """
    VLESS  = "vless"
    VMESS  = "vmess"
    TROJAN = "trojan"
    SS     = "ss"
    TUIC   = "tuic"
    HY2    = "hy2"

    @classmethod
    def from_str(cls, value: str) -> "Protocol":
        """
        Case-insensitive lookup.

        Args:
            value : raw protocol string (e.g. "VLESS", "vmess")

        Returns:
            Matching Protocol enum member

        Raises:
            ValueError if no match found
        """
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown protocol: {value!r}")

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Returns True if value is a recognized protocol string."""
        try:
            cls.from_str(value)
            return True
        except ValueError:
            return False


class Security(str, Enum):
    """TLS / security layer types."""
    TLS     = "tls"
    REALITY = "reality"
    XTLS    = "xtls"
    NONE    = "none"

    @classmethod
    def from_str(cls, value: str) -> "Security":
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.NONE

    def requires_tls(self) -> bool:
        """Returns True if this security type performs a TLS handshake."""
        return self in (Security.TLS, Security.REALITY, Security.XTLS)


class Network(str, Enum):
    """Transport network / layer-4 protocol types."""
    TCP         = "tcp"
    WS          = "ws"
    GRPC        = "grpc"
    H2          = "h2"
    HTTP        = "http"
    HTTPUPGRADE = "httpupgrade"

    @classmethod
    def from_str(cls, value: str) -> "Network":
        normalized = value.strip().lower()
        _aliases = {
            "websocket" : cls.WS,
            "h2"        : cls.H2,
            "http"      : cls.HTTP,
        }
        if normalized in _aliases:
            return _aliases[normalized]
        for member in cls:
            if member.value == normalized:
                return member
        return cls.TCP

    def needs_http_probe(self) -> bool:
        """
        Returns True if this transport requires an HTTP/WS probe
        to fully validate the connection.
        """
        return self in (
            Network.WS,
            Network.H2,
            Network.HTTP,
            Network.HTTPUPGRADE,
            Network.GRPC,
        )


class ScanStatus(str, Enum):
    """
    Result status for a single SNI probe attempt.
    Used in ScanResult.status.
    """
    MATCH    = "match"     # handshake OK + cert matched SNI
    NO_MATCH = "no_match"  # handshake OK but cert did not match
    ERROR    = "error"     # socket / protocol error
    TIMEOUT  = "timeout"   # connect or handshake timed out
    SKIP     = "skip"      # probe bypassed (stop signal / early exit)

    def is_success(self) -> bool:
        """Returns True for statuses that represent a usable result."""
        return self == ScanStatus.MATCH

    def is_failure(self) -> bool:
        """Returns True for statuses that represent a definitive failure."""
        return self in (ScanStatus.ERROR, ScanStatus.TIMEOUT)


class ConfigType(str, Enum):
    """
    Detected connection topology of a parsed proxy config.
    Determined by config_tester.detect_config_type().
    """
    CDN_BASED     = "cdn_based"
    DIRECT_SERVER = "direct_server"
    PLAIN_HTTP    = "plain_http"
    UNKNOWN       = "unknown"


class ScoreTier(str, Enum):
    """
    Human-readable quality tier derived from a numeric score.
    Used by UITheme.colorize_score() and ScanDisplay.
    """
    EXCELLENT = "excellent"   # 90 – 100
    GOOD      = "good"        # 70 –  89
    FAIR      = "fair"        # 50 –  69
    POOR      = "poor"        # 30 –  49
    BAD       = "bad"         #  0 –  29

    @classmethod
    def from_score(cls, score: float) -> "ScoreTier":
        """
        Maps a numeric score to a ScoreTier.

        Args:
            score : float in range 0.0 – 100.0

        Returns:
            Matching ScoreTier
        """
        if score >= 90:
            return cls.EXCELLENT
        if score >= 70:
            return cls.GOOD
        if score >= 50:
            return cls.FAIR
        if score >= 30:
            return cls.POOR
        return cls.BAD


# ══════════════════════════════════════════════════════════════════
#  PROTOCOL CONSTANTS
# ══════════════════════════════════════════════════════════════════

# Protocol string literals
PROTO_VLESS  : str = Protocol.VLESS.value
PROTO_VMESS  : str = Protocol.VMESS.value
PROTO_TROJAN : str = Protocol.TROJAN.value
PROTO_SS     : str = Protocol.SS.value
PROTO_TUIC   : str = Protocol.TUIC.value
PROTO_HY2    : str = Protocol.HY2.value

ALL_PROTOCOLS : Tuple[str, ...] = tuple(p.value for p in Protocol)

# Security string literals
SEC_TLS     : str = Security.TLS.value
SEC_REALITY : str = Security.REALITY.value
SEC_XTLS    : str = Security.XTLS.value
SEC_NONE    : str = Security.NONE.value

ALL_SECURITIES : Tuple[str, ...] = tuple(s.value for s in Security)

# Network string literals
NET_TCP         : str = Network.TCP.value
NET_WS          : str = Network.WS.value
NET_GRPC        : str = Network.GRPC.value
NET_H2          : str = Network.H2.value
NET_HTTP        : str = Network.HTTP.value
NET_HTTPUPGRADE : str = Network.HTTPUPGRADE.value

ALL_NETWORKS : Tuple[str, ...] = tuple(n.value for n in Network)

# TLS fingerprint options
TLS_FINGERPRINTS : Tuple[str, ...] = (
    "chrome", "firefox", "safari",
    "ios", "android", "edge",
    "360", "qq", "random",
)

# Default port per protocol
DEFAULT_PORTS : Dict[str, int] = {
    PROTO_VLESS  : 443,
    PROTO_VMESS  : 443,
    PROTO_TROJAN : 443,
    PROTO_SS     : 8388,
    PROTO_TUIC   : 443,
    PROTO_HY2    : 443,
}

DEFAULT_PORT_VLESS  : int = 443
DEFAULT_PORT_VMESS  : int = 443
DEFAULT_PORT_TROJAN : int = 443
DEFAULT_PORT_SS     : int = 8388
DEFAULT_PORT_TUIC   : int = 443
DEFAULT_PORT_HY2    : int = 443
DEFAULT_PORT        : int = 443

DEFAULT_PATH        : str = "/"


# ══════════════════════════════════════════════════════════════════
#  PARSED CONFIG
# ══════════════════════════════════════════════════════════════════

@dataclass
class ParsedConfig:
    """
    Represents a fully parsed proxy configuration URI.

    Populated by parser.py — one instance per URI.
    Read by config_tester.py, scanner.py, and ui.py.

    Fields are intentionally flat (no nested objects) to make
    serialization, display, and diffing straightforward.

    Attributes:
        protocol          : proxy protocol  (vless/vmess/trojan/ss/tuic/hy2)
        raw               : original URI string before parsing
        host              : server IP or domain
        port              : server port
        uuid              : user ID / password / token
        network           : transport type  (tcp/ws/grpc/h2/httpupgrade)
        security          : TLS layer       (tls/reality/none)
        sni               : TLS Server Name Indication
        host_header       : HTTP Host header (CDN domain)
        path              : HTTP/WS request path
        fingerprint       : TLS client fingerprint
        alpn              : ALPN protocol string  (h2, http/1.1, …)
        remark            : human-readable label from URI fragment
        public_key        : Reality public key  (pbk param)
        short_id          : Reality short ID    (sid param)
        spider_x          : Reality SpiderX     (spx param)
        grpc_service_name : gRPC service name
        is_valid          : False if parsing failed
        parse_error       : error message if is_valid is False
        extra             : arbitrary extra fields (header_type, etc.)
    """

    # ── Identity ──────────────────────────────────────────────────
    protocol : str = ""
    raw      : str = ""

    # ── Connection ────────────────────────────────────────────────
    host : str = ""
    port : int = 0

    # ── Auth ──────────────────────────────────────────────────────
    uuid : str = ""

    # ── Transport ─────────────────────────────────────────────────
    network  : str = NET_TCP
    security : str = SEC_NONE

    # ── TLS / SNI ─────────────────────────────────────────────────
    sni         : str = ""
    host_header : str = ""
    path        : str = DEFAULT_PATH
    fingerprint : str = ""
    alpn        : str = ""

    # ── Meta ──────────────────────────────────────────────────────
    remark : str = ""

    # ── Reality ───────────────────────────────────────────────────
    public_key : str = ""
    short_id   : str = ""
    spider_x   : str = ""

    # ── gRPC ──────────────────────────────────────────────────────
    grpc_service_name : str = ""

    # ── Validity ──────────────────────────────────────────────────
    is_valid    : bool = True
    parse_error : str  = ""

    # ── Extras ────────────────────────────────────────────────────
    extra : Dict[str, Any] = field(default_factory=dict)

    # ── Computed Properties ───────────────────────────────────────

    @property
    def display_name(self) -> str:
        """
        Returns a short human-readable label.

        Priority:
            1. remark  (if set)
            2. host:port
            3. protocol only
        """
        if self.remark:
            return self.remark
        if self.host and self.port:
            return f"{self.host}:{self.port}"
        return self.protocol or "unknown"

    @property
    def address(self) -> str:
        """Returns 'host:port' string."""
        return f"{self.host}:{self.port}"

    @property
    def needs_tls(self) -> bool:
        """Returns True if security requires a TLS handshake."""
        return Security.from_str(self.security).requires_tls()

    @property
    def needs_http(self) -> bool:
        """Returns True if transport requires an HTTP/WS probe."""
        if self.protocol == PROTO_SS:
            return False
        if self.security == SEC_REALITY:
            return False
        return Network.from_str(self.network).needs_http_probe()

    @property
    def is_reality(self) -> bool:
        """Returns True if security is Reality."""
        return self.security == SEC_REALITY

    @property
    def is_grpc(self) -> bool:
        """Returns True if transport is gRPC."""
        return self.network == NET_GRPC

    @property
    def is_ws(self) -> bool:
        """Returns True if transport is WebSocket."""
        return self.network in (NET_WS, "websocket")

    @property
    def effective_sni(self) -> str:
        """
        Returns the SNI that will actually be used in TLS handshake.

        Priority:
            1. self.sni           (explicit SNI param)
            2. self.host          (only if host is a domain, not IP)
            3. ""                 (IP host — no SNI)
        """
        if self.sni:
            return self.sni
        import re
        _ip = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if self.host and not _ip.match(self.host):
            return self.host
        return ""

    @property
    def effective_host_header(self) -> str:
        """
        Returns the HTTP Host header that will be sent.

        Priority:
            1. self.host_header   (explicit host param)
            2. self.host          (server domain / IP)
        """
        return self.host_header or self.host

    @property
    def fingerprint_id(self) -> str:
        """
        Returns a short SHA-256 fingerprint of the raw URI.
        Useful for deduplication and change detection.

        Returns:
            First 12 hex characters of SHA-256(raw)
        """
        return hashlib.sha256(
            self.raw.encode("utf-8", errors="replace")
        ).hexdigest()[:12]

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes to a plain dict.
        Suitable for JSON export and logging.

        Returns:
            Dict with all fields as JSON-serializable values
        """
        return {
            "protocol"          : self.protocol,
            "host"              : self.host,
            "port"              : self.port,
            "uuid"              : self.uuid,
            "network"           : self.network,
            "security"          : self.security,
            "sni"               : self.sni,
            "host_header"       : self.host_header,
            "path"              : self.path,
            "fingerprint"       : self.fingerprint,
            "alpn"              : self.alpn,
            "remark"            : self.remark,
            "public_key"        : self.public_key,
            "short_id"          : self.short_id,
            "spider_x"          : self.spider_x,
            "grpc_service_name" : self.grpc_service_name,
            "is_valid"          : self.is_valid,
            "parse_error"       : self.parse_error,
            "extra"             : self.extra,
            "fingerprint_id"    : self.fingerprint_id,
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Serializes to a JSON string.

        Args:
            indent : JSON indentation level

        Returns:
            Formatted JSON string
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def summary(self) -> str:
        """
        Returns a single-line human-readable summary.

        Example:
            [vless] 1.2.3.4:443  ws/tls  sni=cdn.example.com
        """
        parts = [
            f"[{self.protocol}]",
            f"{self.address:<22}",
            f"{self.network}/{self.security}",
        ]
        if self.effective_sni:
            parts.append(f"sni={self.effective_sni}")
        if self.remark:
            parts.append(f"# {self.remark}")
        return "  ".join(parts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ParsedConfig):
            return NotImplemented
        return self.fingerprint_id == other.fingerprint_id

    def __hash__(self) -> int:
        return hash(self.fingerprint_id)

    def __repr__(self) -> str:
        return (
            f"<ParsedConfig {self.protocol} "
            f"{self.host}:{self.port} "
            f"valid={self.is_valid}>"
        )


# ══════════════════════════════════════════════════════════════════
#  CERT INFO
# ══════════════════════════════════════════════════════════════════

@dataclass
class CertInfo:
    """
    Stores parsed details extracted from a TLS certificate.

    Populated by sni_scanner.py and config_tester.py
    during TLS handshake inspection.

    Attributes:
        subject_cn    : Common Name from Subject field
        issuer_cn     : Common Name from Issuer field
        san_domains   : DNS names in Subject Alternative Name
        san_ips       : IP addresses in Subject Alternative Name
        not_before    : certificate validity start (ISO string)
        not_after     : certificate validity end   (ISO string)
        fingerprint   : SHA-256 of DER-encoded certificate
        tls_version   : negotiated TLS version  (TLSv1.2 / TLSv1.3)
        cipher        : negotiated cipher suite
        is_self_signed: True if Subject == Issuer
        is_expired    : True if current time > not_after
        is_wildcard   : True if any SAN starts with "*."
    """

    subject_cn   : str       = ""
    issuer_cn    : str       = ""
    san_domains  : List[str] = field(default_factory=list)
    san_ips      : List[str] = field(default_factory=list)
    not_before   : str       = ""
    not_after    : str       = ""
    fingerprint  : str       = ""
    tls_version  : str       = ""
    cipher       : str       = ""

    # ── Flags ─────────────────────────────────────────────────────
    is_self_signed : bool = False
    is_expired     : bool = False
    is_wildcard    : bool = False

    # ── Computed ──────────────────────────────────────────────────

    @property
    def all_names(self) -> List[str]:
        """
        Returns all domain names associated with this certificate.
        Combines subject_cn and san_domains (deduplicated).
        """
        seen  = set()
        names = []
        for name in [self.subject_cn] + self.san_domains:
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        return names

    def matches_sni(self, sni: str) -> bool:
        """
        Returns True if the certificate covers the given SNI.

        Checks:
            1. Exact match against all_names
            2. Wildcard match  (*.example.com vs sub.example.com)

        Args:
            sni : domain to check

        Returns:
            True if certificate is valid for this SNI
        """
        if not sni:
            return False

        sni_lower = sni.strip().lower()

        for name in self.all_names:
            name_lower = name.strip().lower()

            # exact match
            if name_lower == sni_lower:
                return True

            # wildcard match
            if name_lower.startswith("*."):
                base = name_lower[2:]
                # sni must have exactly one more label than base
                if sni_lower.endswith(f".{base}"):
                    prefix = sni_lower[: -(len(base) + 1)]
                    if prefix and "." not in prefix:
                        return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serializes to a plain dict."""
        return {
            "subject_cn"    : self.subject_cn,
            "issuer_cn"     : self.issuer_cn,
            "san_domains"   : self.san_domains,
            "san_ips"       : self.san_ips,
            "not_before"    : self.not_before,
            "not_after"     : self.not_after,
            "fingerprint"   : self.fingerprint,
            "tls_version"   : self.tls_version,
            "cipher"        : self.cipher,
            "is_self_signed": self.is_self_signed,
            "is_expired"    : self.is_expired,
            "is_wildcard"   : self.is_wildcard,
        }

    def __repr__(self) -> str:
        return (
            f"<CertInfo cn={self.subject_cn!r} "
            f"wildcard={self.is_wildcard} "
            f"expired={self.is_expired}>"
        )


# ══════════════════════════════════════════════════════════════════
#  TLS PROBE RESULT
# ══════════════════════════════════════════════════════════════════

@dataclass
class TLSProbeResult:
    """
    Result of a single TLS probe attempt against one
    (target, sni) pair.

    Produced by sni_scanner.TLSProber.probe()
    Consumed by sni_scanner.SNIScanner and scanner.py

    Attributes:
        sni           : SNI domain that was tested
        target        : IP or hostname that was connected to
        port          : TCP port used
        status        : outcome  (match/no_match/error/timeout/skip)
        latency_ms    : TLS handshake round-trip in milliseconds
        score         : confidence score  0.0 – 100.0
        cert          : parsed certificate details
        tls_version   : negotiated TLS version string
        cipher        : negotiated cipher suite
        error         : error message if status is error/timeout
        retries       : number of retry attempts made
        timestamp     : Unix timestamp when probe completed
    """

    sni        : str   = ""
    target     : str   = ""
    port       : int   = 443
    status     : str   = ScanStatus.ERROR.value
    latency_ms : float = -1.0
    score      : float = 0.0

    cert       : Optional[CertInfo] = field(default=None)

    tls_version : str = ""
    cipher      : str = ""
    error       : str = ""
    retries     : int = 0
    timestamp   : float = field(default_factory=time.time)

    # ── Computed ──────────────────────────────────────────────────

    @property
    def is_match(self) -> bool:
        """True if probe resulted in a confirmed SNI match."""
        return self.status == ScanStatus.MATCH.value

    @property
    def is_success(self) -> bool:
        """True if probe completed without error (match or no_match)."""
        return self.status in (
            ScanStatus.MATCH.value,
            ScanStatus.NO_MATCH.value,
        )

    @property
    def score_tier(self) -> ScoreTier:
        """Returns the quality tier for this probe's score."""
        return ScoreTier.from_score(self.score)

    @property
    def datetime_str(self) -> str:
        """Returns timestamp as a formatted datetime string."""
        return datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serializes to a plain dict."""
        return {
            "sni"        : self.sni,
            "target"     : self.target,
            "port"       : self.port,
            "status"     : self.status,
            "latency_ms" : round(self.latency_ms, 2),
            "score"      : round(self.score, 1),
            "tls_version": self.tls_version,
            "cipher"     : self.cipher,
            "error"      : self.error,
            "retries"    : self.retries,
            "timestamp"  : self.timestamp,
            "cert"       : self.cert.to_dict() if self.cert else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TLSProbeResult sni={self.sni!r} "
            f"status={self.status} "
            f"score={self.score:.1f} "
            f"latency={self.latency_ms:.0f}ms>"
        )


# ══════════════════════════════════════════════════════════════════
#  SCAN RESULT
# ══════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    """
    Represents the aggregated result of scanning one SNI domain
    against a proxy configuration.

    Produced by scanner.py — one instance per (config, sni) pair.
    Consumed by ui.py (ScanDisplay, StatusBar) and file_manager.py.

    Attributes:
        sni              : SNI domain that was tested
        config           : proxy config this result belongs to
        status           : final outcome (match/no_match/error/timeout/skip)
        score            : composite quality score  0.0 – 100.0
        latency_ms       : TLS handshake latency in milliseconds
        tcp_latency_ms   : TCP connection latency in milliseconds
        tcp_reachable    : True if TCP connection succeeded
        tls_version      : negotiated TLS version string
        cipher           : negotiated cipher suite
        alpn_negotiated  : negotiated ALPN protocol
        cert             : parsed certificate details
        ip_resolved      : IP address resolved for this SNI
        error            : error message if status is error/timeout
        warnings         : non-fatal issues detected during scan
        retries          : number of retry attempts made
        timestamp        : Unix timestamp when result was recorded
        test_duration_ms : total test time in milliseconds
        probe_results    : individual TLSProbeResult per attempt
        rebuilt_uri      : reconstructed URI with new SNI applied
    """

    # ── Core ──────────────────────────────────────────────────────
    sni    : str                    = ""
    config : Optional[ParsedConfig] = field(default=None)

    # ── Outcome ───────────────────────────────────────────────────
    status     : str   = ScanStatus.ERROR.value
    score      : float = 0.0
    latency_ms : float = -1.0

    # ── TCP ───────────────────────────────────────────────────────
    tcp_latency_ms : float = -1.0
    tcp_reachable  : bool  = False

    # ── TLS ───────────────────────────────────────────────────────
    tls_version     : str                = ""
    cipher          : str                = ""
    alpn_negotiated : str                = ""
    cert            : Optional[CertInfo] = field(default=None)

    # ── DNS ───────────────────────────────────────────────────────
    ip_resolved : str = ""

    # ── Diagnostics ───────────────────────────────────────────────
    error    : str       = ""
    warnings : List[str] = field(default_factory=list)
    retries  : int       = 0

    # ── Timing ────────────────────────────────────────────────────
    timestamp        : float = field(default_factory=time.time)
    test_duration_ms : float = 0.0

    # ── Detail ────────────────────────────────────────────────────
    probe_results : List[TLSProbeResult] = field(default_factory=list)
    rebuilt_uri   : str                  = ""

    # ── Computed Properties ───────────────────────────────────────

    @property
    def passed(self) -> bool:
        """True if this result represents a successful SNI match."""
        return self.status == ScanStatus.MATCH.value

    @property
    def failed(self) -> bool:
        """True if this result is a definitive failure."""
        return self.status in (
            ScanStatus.ERROR.value,
            ScanStatus.TIMEOUT.value,
        )

    @property
    def is_match(self) -> bool:
        """Alias for passed — cert matched the SNI."""
        return self.passed

    @property
    def score_tier(self) -> ScoreTier:
        """Returns the quality tier for this result's score."""
        return ScoreTier.from_score(self.score)

    @property
    def datetime_str(self) -> str:
        """Returns timestamp as a formatted datetime string."""
        return datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    @property
    def latency_display(self) -> str:
        """
        Returns latency as a human-readable string.

        Examples:
            "120ms"
            "1.2s"
            "—"      (if latency unavailable)
        """
        if self.latency_ms < 0:
            return "—"
        if self.latency_ms >= 1000:
            return f"{self.latency_ms / 1000:.1f}s"
        return f"{self.latency_ms:.0f}ms"

    @property
    def score_display(self) -> str:
        """
        Returns score as a formatted string.

        Examples:
            "92.4"
            "—"   (if score is 0 and status is not match)
        """
        if self.score <= 0 and not self.passed:
            return "—"
        return f"{self.score:.1f}"

    @property
    def protocol(self) -> str:
        """Returns protocol string from attached config, or empty."""
        return self.config.protocol if self.config else ""

    @property
    def host(self) -> str:
        """Returns host from attached config, or empty."""
        return self.config.host if self.config else ""

    @property
    def port(self) -> int:
        """Returns port from attached config, or 0."""
        return self.config.port if self.config else 0

    @property
    def has_warnings(self) -> bool:
        """True if any non-fatal warnings were recorded."""
        return len(self.warnings) > 0

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes to a plain dict.
        Suitable for JSON export, CSV export, and logging.
        """
        return {
            "sni"             : self.sni,
            "status"          : self.status,
            "score"           : round(self.score, 1),
            "latency_ms"      : round(self.latency_ms, 2),
            "tcp_latency_ms"  : round(self.tcp_latency_ms, 2),
            "tcp_reachable"   : self.tcp_reachable,
            "tls_version"     : self.tls_version,
            "cipher"          : self.cipher,
            "alpn_negotiated" : self.alpn_negotiated,
            "ip_resolved"     : self.ip_resolved,
            "error"           : self.error,
            "warnings"        : self.warnings,
            "retries"         : self.retries,
            "timestamp"       : self.timestamp,
            "datetime"        : self.datetime_str,
            "test_duration_ms": round(self.test_duration_ms, 2),
            "rebuilt_uri"     : self.rebuilt_uri,
            "score_tier"      : self.score_tier.value,
            "cert"            : self.cert.to_dict() if self.cert else None,
            "config"          : self.config.to_dict() if self.config else None,
        }

    def to_csv_row(self) -> List[str]:
        """
        Returns a flat list of values for CSV export.
        Column order matches ScanResult.csv_headers().
        """
        return [
            self.sni,
            self.status,
            str(round(self.score, 1)),
            str(round(self.latency_ms, 2)),
            str(round(self.tcp_latency_ms, 2)),
            str(self.tcp_reachable),
            self.tls_version,
            self.ip_resolved,
            self.error,
            self.datetime_str,
            self.rebuilt_uri,
            self.protocol,
            self.host,
            str(self.port),
        ]

    @staticmethod
    def csv_headers() -> List[str]:
        """
        Returns the CSV column header list.
        Must match the order in to_csv_row().
        """
        return [
            "sni",
            "status",
            "score",
            "latency_ms",
            "tcp_latency_ms",
            "tcp_reachable",
            "tls_version",
            "ip_resolved",
            "error",
            "datetime",
            "rebuilt_uri",
            "protocol",
            "host",
            "port",
        ]

    def __repr__(self) -> str:
        return (
            f"<ScanResult sni={self.sni!r} "
            f"status={self.status} "
            f"score={self.score:.1f} "
            f"latency={self.latency_ms:.0f}ms>"
        )


# ══════════════════════════════════════════════════════════════════
#  SCAN STATS
# ══════════════════════════════════════════════════════════════════

@dataclass
class ScanStats:
    """
    Aggregated statistics for a completed or in-progress scan session.

    Updated in real-time by scanner.py as results arrive.
    Consumed by ui.py (StatusBar, ScanDisplay) for live display.

    Attributes:
        total       : total number of SNI domains to test
        tested      : number of probes completed so far
        matched     : number of successful SNI matches
        failed      : number of errors + timeouts
        skipped     : number of skipped probes
        start_time  : Unix timestamp when scan started
        end_time    : Unix timestamp when scan finished (0 if running)
        best_result : highest-scoring ScanResult so far
        results     : all ScanResult instances collected
    """

    # ── Counters ──────────────────────────────────────────────────
    total   : int = 0
    tested  : int = 0
    matched : int = 0
    failed  : int = 0
    skipped : int = 0

    # ── Timing ────────────────────────────────────────────────────
    start_time : float = field(default_factory=time.time)
    end_time   : float = 0.0

    # ── Results ───────────────────────────────────────────────────
    best_result : Optional[ScanResult] = field(default=None)
    results     : List[ScanResult]     = field(default_factory=list)

    # ── Computed Properties ───────────────────────────────────────

    @property
    def remaining(self) -> int:
        """Number of probes not yet completed."""
        return max(0, self.total - self.tested)

    @property
    def progress_pct(self) -> float:
        """
        Completion percentage  0.0 – 100.0.
        Returns 0.0 if total is 0.
        """
        if self.total == 0:
            return 0.0
        return min(100.0, (self.tested / self.total) * 100.0)

    @property
    def success_rate(self) -> float:
        """
        Percentage of tested probes that matched  0.0 – 100.0.
        Returns 0.0 if nothing has been tested yet.
        """
        if self.tested == 0:
            return 0.0
        return (self.matched / self.tested) * 100.0

    @property
    def elapsed_seconds(self) -> float:
        """Seconds elapsed since scan started."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def eta_seconds(self) -> float:
        """
        Estimated seconds remaining based on current rate.
        Returns -1.0 if rate cannot be calculated.
        """
        elapsed = self.elapsed_seconds
        if self.tested == 0 or elapsed == 0:
            return -1.0
        rate = self.tested / elapsed        # probes per second
        return self.remaining / rate

    @property
    def rate(self) -> float:
        """
        Current scan rate in probes per second.
        Returns 0.0 if no probes completed yet.
        """
        elapsed = self.elapsed_seconds
        if elapsed == 0 or self.tested == 0:
            return 0.0
        return self.tested / elapsed

    @property
    def avg_latency_ms(self) -> float:
        """
        Average latency across all matched results.
        Returns -1.0 if no matches yet.
        """
        matched = [
            r.latency_ms
            for r in self.results
            if r.passed and r.latency_ms >= 0
        ]
        if not matched:
            return -1.0
        return sum(matched) / len(matched)

    @property
    def best_score(self) -> float:
        """Highest score seen so far. Returns 0.0 if no results."""
        if self.best_result:
            return self.best_result.score
        return 0.0

    @property
    def best_sni(self) -> str:
        """SNI of the best result so far. Returns empty if none."""
        if self.best_result:
            return self.best_result.sni
        return ""

    @property
    def is_running(self) -> bool:
        """True if scan has not yet finished."""
        return self.end_time == 0.0

    @property
    def is_finished(self) -> bool:
        """True if scan has completed."""
        return self.end_time > 0.0

    @property
    def duration_display(self) -> str:
        """
        Returns elapsed time as a human-readable string.

        Examples:
            "42s"
            "2m 15s"
            "1h 03m"
        """
        s = int(self.elapsed_seconds)
        if s < 60:
            return f"{s}s"
        m, s = divmod(s, 60)
        if m < 60:
            return f"{m}m {s:02d}s"
        h, m = divmod(m, 60)
        return f"{h}h {m:02d}m"

    @property
    def eta_display(self) -> str:
        """
        Returns ETA as a human-readable string.

        Examples:
            "~30s"
            "~2m 10s"
            "—"   (if ETA cannot be estimated)
        """
        eta = self.eta_seconds
        if eta < 0:
            return "—"
        s = int(eta)
        if s < 60:
            return f"~{s}s"
        m, s = divmod(s, 60)
        return f"~{m}m {s:02d}s"

    @property
    def rate_display(self) -> str:
        """
        Returns scan rate as a human-readable string.

        Examples:
            "12.4/s"
            "—"
        """
        if self.rate <= 0:
            return "—"
        return f"{self.rate:.1f}/s"

    @property
    def avg_latency_display(self) -> str:
        """
        Returns average latency as a human-readable string.

        Examples:
            "84ms"
            "1.2s"
            "—"
        """
        if self.avg_latency_ms < 0:
            return "—"
        if self.avg_latency_ms >= 1000:
            return f"{self.avg_latency_ms / 1000:.1f}s"
        return f"{self.avg_latency_ms:.0f}ms"

    # ── Mutation ──────────────────────────────────────────────────

    def record(self, result: ScanResult) -> None:
        """
        Records a new ScanResult and updates all counters.

        This is the ONLY way to add results to ScanStats.
        Handles counter updates, best_result tracking,
        and skip/fail classification automatically.

        Args:
            result : completed ScanResult to register
        """
        self.results.append(result)
        self.tested += 1

        if result.passed:
            self.matched += 1
            if (
                self.best_result is None
                or result.score > self.best_result.score
            ):
                self.best_result = result

        elif result.status == ScanStatus.SKIP.value:
            self.skipped += 1

        else:
            self.failed += 1

    def finish(self) -> None:
        """
        Marks the scan as completed by recording end_time.
        After calling this, is_finished returns True
        and elapsed_seconds becomes fixed.
        """
        self.end_time = time.time()

    def reset(self) -> None:
        """
        Resets all counters and results for a fresh scan.
        Preserves total so it can be reused.
        """
        self.tested      = 0
        self.matched     = 0
        self.failed      = 0
        self.skipped     = 0
        self.start_time  = time.time()
        self.end_time    = 0.0
        self.best_result = None
        self.results     = []

    def top_results(
        self,
        n        : int   = 10,
        min_score: float = 0.0,
    ) -> List[ScanResult]:
        """
        Returns the top-N results sorted by score descending.

        Args:
            n         : maximum number of results to return
            min_score : minimum score threshold to include

        Returns:
            Sorted list of up to N matched ScanResult instances
        """
        filtered = [
            r for r in self.results
            if r.passed and r.score >= min_score
        ]
        return sorted(
            filtered,
            key     = lambda r: r.score,
            reverse = True,
        )[:n]

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes summary statistics to a plain dict.
        Does NOT include full results list.

        Returns:
            Dict with all counters and computed metrics
        """
        return {
            "total"           : self.total,
            "tested"          : self.tested,
            "matched"         : self.matched,
            "failed"          : self.failed,
            "skipped"         : self.skipped,
            "remaining"       : self.remaining,
            "progress_pct"    : round(self.progress_pct, 1),
            "success_rate"    : round(self.success_rate, 1),
            "elapsed_seconds" : round(self.elapsed_seconds, 1),
            "eta_seconds"     : round(self.eta_seconds, 1),
            "rate"            : round(self.rate, 2),
            "avg_latency_ms"  : round(self.avg_latency_ms, 2),
            "best_score"      : round(self.best_score, 1),
            "best_sni"        : self.best_sni,
            "is_finished"     : self.is_finished,
            "start_time"      : self.start_time,
            "end_time"        : self.end_time,
        }

    def __repr__(self) -> str:
        return (
            f"<ScanStats "
            f"{self.tested}/{self.total} "
            f"matched={self.matched} "
            f"rate={self.rate:.1f}/s>"
        )


# ══════════════════════════════════════════════════════════════════
#  SCAN CONFIG
# ══════════════════════════════════════════════════════════════════

@dataclass
class ScanConfig:
    """
    Runtime configuration for a single scan session.

    Created by AppUI._flow_scan() and passed to Scanner.run().
    Controls concurrency, timeouts, retry behavior, and filters.

    Attributes:
        threads          : number of concurrent worker threads
        timeout_connect  : TCP connect timeout in seconds
        timeout_tls      : TLS handshake timeout in seconds
        retries          : number of retry attempts per SNI
        retry_delay      : seconds to wait between retries
        min_score        : minimum score to include in results
        top_n            : maximum results to keep after scan
        sni_list         : SNI domains to test
        target_config    : the proxy config being tested
        stop_on_first    : stop after first successful match
        shuffle_sni      : randomize SNI list order before scan
        tls_versions     : TLS versions to probe (1.2 / 1.3)
    """

    # ── Concurrency ───────────────────────────────────────────────
    threads : int = 20

    # ── Timeouts ──────────────────────────────────────────────────
    timeout_connect : float = 3.0
    timeout_tls     : float = 5.0

    # ── Retries ───────────────────────────────────────────────────
    retries     : int   = 2
    retry_delay : float = 0.5

    # ── Filters ───────────────────────────────────────────────────
    min_score : float = 0.0
    top_n     : int   = 200

    # ── Input ─────────────────────────────────────────────────────
    sni_list      : List[str]              = field(default_factory=list)
    target_config : Optional[ParsedConfig] = field(default=None)

    # ── Behavior ──────────────────────────────────────────────────
    stop_on_first : bool      = False
    shuffle_sni   : bool      = False
    tls_versions  : List[str] = field(
        default_factory=lambda: ["TLSv1.2", "TLSv1.3"]
    )

    # ── Computed Properties ───────────────────────────────────────

    @property
    def sni_count(self) -> int:
        """Number of SNI domains loaded for this scan."""
        return len(self.sni_list)

    @property
    def is_ready(self) -> bool:
        """
        Returns True if this config has everything needed to run.

        Requires:
            - at least one SNI domain
            - a valid target_config
        """
        return (
            len(self.sni_list) > 0
            and self.target_config is not None
            and self.target_config.is_valid
        )

    @property
    def total_timeout(self) -> float:
        """
        Returns worst-case timeout per probe in seconds.
        Accounts for retries and both connect + TLS timeouts.
        """
        per_attempt = self.timeout_connect + self.timeout_tls
        return per_attempt * (self.retries + 1) + self.retry_delay * self.retries

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes to a plain dict.
        Excludes full sni_list to keep output compact.
        """
        return {
            "threads"         : self.threads,
            "timeout_connect" : self.timeout_connect,
            "timeout_tls"     : self.timeout_tls,
            "retries"         : self.retries,
            "retry_delay"     : self.retry_delay,
            "min_score"       : self.min_score,
            "top_n"           : self.top_n,
            "sni_count"       : self.sni_count,
            "stop_on_first"   : self.stop_on_first,
            "shuffle_sni"     : self.shuffle_sni,
            "tls_versions"    : self.tls_versions,
            "total_timeout"   : round(self.total_timeout, 2),
            "is_ready"        : self.is_ready,
        }

    def __repr__(self) -> str:
        return (
            f"<ScanConfig "
            f"threads={self.threads} "
            f"sni_count={self.sni_count} "
            f"ready={self.is_ready}>"
        )


# ══════════════════════════════════════════════════════════════════
#  APP STATE
# ══════════════════════════════════════════════════════════════════

@dataclass
class AppState:
    """
    Global mutable state of the running application.

    Single instance created in main.py and passed to AppUI.
    Acts as the single source of truth for the entire session.

    Attributes:
        configs         : all parsed proxy configs loaded this session
        active_config   : config currently selected for scanning
        scan_config     : runtime scan parameters
        stats           : live scan statistics
        sni_pool        : full SNI domain list loaded from file/url
        is_scanning     : True while a scan is in progress
        is_paused       : True if scan has been paused by user
        stop_requested  : True if user requested scan stop
        session_id      : unique ID for this app session
        config_path     : path to last loaded config file
        sni_path        : path to last loaded SNI file
        output_dir      : directory where results are saved
        last_error      : last unhandled error message
        history         : list of past ScanStats (one per scan run)
    """

    # ── Configs ───────────────────────────────────────────────────
    configs       : List[ParsedConfig]     = field(default_factory=list)
    active_config : Optional[ParsedConfig] = field(default=None)

    # ── Scan ──────────────────────────────────────────────────────
    scan_config : ScanConfig = field(default_factory=ScanConfig)
    stats       : ScanStats  = field(default_factory=ScanStats)

    # ── SNI ───────────────────────────────────────────────────────
    sni_pool : List[str] = field(default_factory=list)

    # ── Control Flags ─────────────────────────────────────────────
    is_scanning    : bool = False
    is_paused      : bool = False
    stop_requested : bool = False

    # ── Paths ─────────────────────────────────────────────────────
    config_path : str = ""
    sni_path    : str = ""
    output_dir  : str = ""

    # ── Meta ──────────────────────────────────────────────────────
    session_id : str = field(
        default_factory=lambda: hashlib.sha256(
            str(time.time()).encode()
        ).hexdigest()[:8]
    )
    last_error : str             = ""
    history    : List[ScanStats] = field(default_factory=list)

    # ── Computed Properties ───────────────────────────────────────

    @property
    def config_count(self) -> int:
        """Number of parsed configs currently loaded."""
        return len(self.configs)

    @property
    def sni_count(self) -> int:
        """Number of SNI domains currently in pool."""
        return len(self.sni_pool)

    @property
    def has_active_config(self) -> bool:
        """True if a config is selected and valid."""
        return (
            self.active_config is not None
            and self.active_config.is_valid
        )

    @property
    def has_sni(self) -> bool:
        """True if SNI pool is non-empty."""
        return len(self.sni_pool) > 0

    @property
    def can_scan(self) -> bool:
        """
        True if all prerequisites for starting a scan are met.

        Requires:
            - valid active config
            - non-empty SNI pool
            - no scan currently running
        """
        return (
            self.has_active_config
            and self.has_sni
            and not self.is_scanning
        )

    @property
    def best_result(self) -> Optional[ScanResult]:
        """Shortcut to stats.best_result."""
        return self.stats.best_result

    @property
    def total_matched(self) -> int:
        """Total matched results in current scan."""
        return self.stats.matched

    @property
    def scan_runs(self) -> int:
        """Number of completed scan runs in this session."""
        return len(self.history)

    # ── Mutation ──────────────────────────────────────────────────

    def start_scan(self) -> None:
        """
        Transitions state to scanning mode.

        Resets stats, applies sni_pool to scan_config,
        and sets control flags.
        """
        self.stats.reset()
        self.stats.total               = len(self.sni_pool)
        self.scan_config.sni_list      = list(self.sni_pool)
        self.scan_config.target_config = self.active_config
        self.is_scanning               = True
        self.is_paused                 = False
        self.stop_requested            = False
        self.last_error                = ""

    def finish_scan(self) -> None:
        """
        Transitions state back to idle mode.
        Records completed stats into history.
        """
        self.stats.finish()
        self.history.append(self.stats)
        self.is_scanning    = False
        self.is_paused      = False
        self.stop_requested = False

    def request_stop(self) -> None:
        """Signals the scanner to stop after current probe."""
        self.stop_requested = True

    def toggle_pause(self) -> bool:
        """
        Toggles pause state.

        Returns:
            New value of is_paused after toggle
        """
        self.is_paused = not self.is_paused
        return self.is_paused

    def set_error(self, message: str) -> None:
        """
        Records an error message and clears scanning flags.

        Args:
            message : human-readable error description
        """
        self.last_error  = message
        self.is_scanning = False
        self.is_paused   = False

    def clear_results(self) -> None:
        """
        Clears current scan results without touching configs or SNI.
        Useful for running a fresh scan on same config.
        """
        self.stats = ScanStats()

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes current app state summary to a plain dict.
        Suitable for debug dumps and session logging.
        """
        return {
            "session_id"        : self.session_id,
            "config_count"      : self.config_count,
            "sni_count"         : self.sni_count,
            "has_active_config" : self.has_active_config,
            "is_scanning"       : self.is_scanning,
            "is_paused"         : self.is_paused,
            "stop_requested"    : self.stop_requested,
            "config_path"       : self.config_path,
            "sni_path"          : self.sni_path,
            "output_dir"        : self.output_dir,
            "last_error"        : self.last_error,
            "scan_runs"         : self.scan_runs,
            "stats"             : self.stats.to_dict(),
            "active_config"     : (
                self.active_config.to_dict()
                if self.active_config else None
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<AppState session={self.session_id} "
            f"configs={self.config_count} "
            f"sni={self.sni_count} "
            f"scanning={self.is_scanning}>"
        )


# ══════════════════════════════════════════════════════════════════
#  EXPORT DATA
# ══════════════════════════════════════════════════════════════════

@dataclass
class ExportData:
    """
    Bundles all data needed for a single export operation.

    Created by file_manager.py before writing output files.
    Contains both the raw results and the metadata needed
    to reconstruct the export context.

    Attributes:
        results      : list of ScanResult to export
        stats        : scan statistics summary
        config       : proxy config that was scanned
        scan_config  : runtime scan parameters used
        format       : export format  (json / csv / txt / uri)
        output_path  : destination file path
        timestamp    : when this export was created
        app_version  : application version string
        session_id   : session ID from AppState
    """

    # ── Data ──────────────────────────────────────────────────────
    results     : List[ScanResult]       = field(default_factory=list)
    stats       : Optional[ScanStats]    = field(default=None)
    config      : Optional[ParsedConfig] = field(default=None)
    scan_config : Optional[ScanConfig]   = field(default=None)

    # ── Export Meta ───────────────────────────────────────────────
    format      : str   = "json"
    output_path : str   = ""
    timestamp   : float = field(default_factory=time.time)
    app_version : str   = ""
    session_id  : str   = ""

    # ── Computed ──────────────────────────────────────────────────

    @property
    def result_count(self) -> int:
        """Number of results in this export."""
        return len(self.results)

    @property
    def datetime_str(self) -> str:
        """Returns export timestamp as a formatted string."""
        return datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    @property
    def matched_results(self) -> List[ScanResult]:
        """Returns only the matched (passed) results."""
        return [r for r in self.results if r.passed]

    @property
    def failed_results(self) -> List[ScanResult]:
        """Returns only the failed results."""
        return [r for r in self.results if r.failed]

    @property
    def top_uris(self) -> List[str]:
        """
        Returns rebuilt URIs of matched results sorted by score.
        Filters out empty rebuilt_uri values.
        """
        matched = [
            r for r in self.results
            if r.passed and r.rebuilt_uri
        ]
        return [
            r.rebuilt_uri
            for r in sorted(
                matched,
                key     = lambda r: r.score,
                reverse = True,
            )
        ]

    @property
    def has_results(self) -> bool:
        """True if at least one result exists."""
        return len(self.results) > 0

    @property
    def has_matched(self) -> bool:
        """True if at least one matched result exists."""
        return len(self.matched_results) > 0

    @property
    def match_rate(self) -> float:
        """
        Percentage of matched results over total.

        Returns:
            float between 0.0 and 100.0
            0.0 if no results exist
        """
        if not self.result_count:
            return 0.0
        return round(
            len(self.matched_results) / self.result_count * 100,
            1,
        )

    @property
    def avg_score(self) -> float:
        """
        Average score of matched results.

        Returns:
            float between 0.0 and 100.0
            0.0 if no matched results exist
        """
        matched = self.matched_results
        if not matched:
            return 0.0
        return round(
            sum(r.score for r in matched) / len(matched),
            2,
        )

    @property
    def avg_latency(self) -> float:
        """
        Average latency (ms) of matched results.

        Returns:
            float >= 0.0
            0.0 if no matched results exist
        """
        matched = self.matched_results
        if not matched:
            return 0.0
        return round(
            sum(r.latency_ms for r in matched) / len(matched),
            1,
        )

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the full export bundle to a plain dict.
        Used as the root object for JSON export files.
        """
        return {
            "meta": {
                "session_id"  : self.session_id,
                "app_version" : self.app_version,
                "format"      : self.format,
                "datetime"    : self.datetime_str,
                "timestamp"   : self.timestamp,
                "output_path" : self.output_path,
                "result_count": self.result_count,
                "match_rate"  : self.match_rate,
                "avg_score"   : self.avg_score,
                "avg_latency" : self.avg_latency,
            },
            "stats"      : self.stats.to_dict()       if self.stats       else None,
            "config"     : self.config.to_dict()      if self.config      else None,
            "scan_config": self.scan_config.to_dict() if self.scan_config else None,
            "results"    : [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Serializes to a formatted JSON string.

        Args:
            indent : JSON indentation level

        Returns:
            UTF-8 safe JSON string
        """
        return json.dumps(
            self.to_dict(),
            ensure_ascii = False,
            indent       = indent,
        )

    def to_csv(self) -> str:
        """
        Serializes matched results to CSV format.

        Returns:
            CSV string with header row
            Empty string if no results
        """
        if not self.has_results:
            return ""

        rows   = [",".join(ScanResult.csv_headers())]
        rows  += [
            ",".join(str(v) for v in r.to_csv_row())
            for r in self.results
        ]
        return "\n".join(rows)

    def to_uri_list(self) -> str:
        """
        Serializes matched results to a plain URI list.

        Returns:
            Newline-separated rebuilt URIs
            Empty string if no matched results
        """
        return "\n".join(self.top_uris)

    def __repr__(self) -> str:
        return (
            f"<ExportData format={self.format!r} "
            f"results={self.result_count} "
            f"matched={len(self.matched_results)} "
            f"path={self.output_path!r}>"
        )


# ══════════════════════════════════════════════════════════════════
#  MODULE EXPORTS
# ══════════════════════════════════════════════════════════════════

__all__ = [
    # ── Enums ─────────────────────────────────────────────────────
    "Protocol",
    "Security",
    "Network",
    "ScanStatus",
    "ConfigType",
    "ScoreTier",

    # ── Protocol Constants ────────────────────────────────────────
    "PROTO_VLESS",
    "PROTO_VMESS",
    "PROTO_TROJAN",
    "PROTO_SS",
    "PROTO_TUIC",
    "PROTO_HY2",
    "ALL_PROTOCOLS",

    # ── Security Constants ────────────────────────────────────────
    "SEC_TLS",
    "SEC_REALITY",
    "SEC_XTLS",
    "SEC_NONE",
    "ALL_SECURITIES",

    # ── Network Constants ─────────────────────────────────────────
    "NET_TCP",
    "NET_WS",
    "NET_GRPC",
    "NET_H2",
    "NET_HTTP",
    "NET_HTTPUPGRADE",
    "ALL_NETWORKS",

    # ── Misc Constants ────────────────────────────────────────────
    "TLS_FINGERPRINTS",
    "DEFAULT_PORTS",
    "DEFAULT_PORT",
    "DEFAULT_PATH",

    # ── Dataclasses ───────────────────────────────────────────────
    "ParsedConfig",
    "CertInfo",
    "TLSProbeResult",
    "ScanResult",
    "ScanStats",
    "ScanConfig",
    "AppState",
    "ExportData",
]


# ══════════════════════════════════════════════════════════════════
#  SELF-TEST  (python models.py)
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    _PASS   = "✓"
    _FAIL   = "✗"
    _errors : List[str] = []

    def _check(label: str, expr: bool) -> None:
        """Prints pass/fail and records failures."""
        if expr:
            print(f"  {_PASS}  {label}")
        else:
            print(f"  {_FAIL}  {label}  ← FAILED")
            _errors.append(label)

    # ──────────────────────────────────────────────────────────────
    print()
    print("══════════════════════════════════════════════════════")
    print("  models.py  —  self-test")
    print("══════════════════════════════════════════════════════")

    # ── Enums ─────────────────────────────────────────────────────
    print("\n── Enums ────────────────────────────────────────────")

    _check(
        "Protocol.from_str('VLESS') == VLESS",
        Protocol.from_str("VLESS") == Protocol.VLESS,
    )
    _check(
        "Protocol.is_valid('trojan') is True",
        Protocol.is_valid("trojan") is True,
    )
    _check(
        "Protocol.is_valid('unknown') is False",
        Protocol.is_valid("unknown") is False,
    )
    _check(
        "Security.TLS.requires_tls() is True",
        Security.TLS.requires_tls() is True,
    )
    _check(
        "Security.NONE.requires_tls() is False",
        Security.NONE.requires_tls() is False,
    )
    _check(
        "Network.from_str('websocket') == WS",
        Network.from_str("websocket") == Network.WS,
    )
    _check(
        "Network.WS.needs_http_probe() is True",
        Network.WS.needs_http_probe() is True,
    )
    _check(
        "Network.TCP.needs_http_probe() is False",
        Network.TCP.needs_http_probe() is False,
    )
    _check(
        "ScanStatus.MATCH.is_success() is True",
        ScanStatus.MATCH.is_success() is True,
    )
    _check(
        "ScanStatus.TIMEOUT.is_failure() is True",
        ScanStatus.TIMEOUT.is_failure() is True,
    )
    _check(
        "ScoreTier.from_score(95.0) == EXCELLENT",
        ScoreTier.from_score(95.0) == ScoreTier.EXCELLENT,
    )
    _check(
        "ScoreTier.from_score(25.0) == BAD",
        ScoreTier.from_score(25.0) == ScoreTier.BAD,
    )

    # ── ParsedConfig ──────────────────────────────────────────────
    print("\n── ParsedConfig ─────────────────────────────────────")

    _cfg = ParsedConfig(
        protocol = PROTO_VLESS,
        host     = "1.2.3.4",
        port     = 443,
        uuid     = "test-uuid-1234",
        network  = NET_WS,
        security = SEC_TLS,
        sni      = "cdn.example.com",
        remark   = "test-node",
        raw      = (
            "vless://test-uuid-1234@1.2.3.4:443"
            "?type=ws&security=tls&sni=cdn.example.com"
            "#test-node"
        ),
    )
    _check("needs_tls is True",          _cfg.needs_tls is True)
    _check("needs_http is True",         _cfg.needs_http is True)
    _check("is_reality is False",        _cfg.is_reality is False)
    _check("is_ws is True",              _cfg.is_ws is True)
    _check("effective_sni correct",      _cfg.effective_sni == "cdn.example.com")
    _check("address correct",            _cfg.address == "1.2.3.4:443")
    _check("display_name == remark",     _cfg.display_name == "test-node")
    _check("fingerprint_id len == 12",   len(_cfg.fingerprint_id) == 12)
    _check("to_dict has 'protocol'",     "protocol" in _cfg.to_dict())
    _check("__hash__ works in set",      len({_cfg, _cfg}) == 1)

    # ── CertInfo ──────────────────────────────────────────────────
    print("\n── CertInfo ─────────────────────────────────────────")

    _cert = CertInfo(
        subject_cn  = "cdn.example.com",
        issuer_cn   = "Let's Encrypt",
        san_domains = ["cdn.example.com", "*.example.com"],
        tls_version = "TLSv1.3",
        is_wildcard = True,
    )
    _check("matches exact SNI",          _cert.matches_sni("cdn.example.com"))
    _check("matches wildcard SNI",       _cert.matches_sni("sub.example.com"))
    _check("rejects unrelated domain",   not _cert.matches_sni("other.com"))
    _check("rejects empty SNI",          not _cert.matches_sni(""))
    _check("to_dict has 'subject_cn'",   "subject_cn" in _cert.to_dict())

    # ── TLSProbeResult ────────────────────────────────────────────
    print("\n── TLSProbeResult ───────────────────────────────────")

    _probe = TLSProbeResult(
        sni         = "cdn.example.com",
        target      = "1.2.3.4",
        port        = 443,
        status      = ScanStatus.MATCH.value,
        latency_ms  = 85.0,
        score       = 91.5,
        cert        = _cert,
        tls_version = "TLSv1.3",
    )
    _check("is_match is True",           _probe.is_match is True)
    _check("is_success is True",         _probe.is_success is True)
    _check("score_tier == EXCELLENT",    _probe.score_tier == ScoreTier.EXCELLENT)
    _check("to_dict has 'latency_ms'",   "latency_ms" in _probe.to_dict())

    # ── ScanResult ────────────────────────────────────────────────
    print("\n── ScanResult ───────────────────────────────────────")

    _result = ScanResult(
        sni         = "cdn.example.com",
        config      = _cfg,
        status      = ScanStatus.MATCH.value,
        score       = 91.5,
        latency_ms  = 85.0,
        cert        = _cert,
        rebuilt_uri = (
            "vless://test-uuid@1.2.3.4:443"
            "?sni=cdn.example.com"
        ),
    )
    _check("passed is True",             _result.passed is True)
    _check("failed is False",            _result.failed is False)
    _check("score_tier == EXCELLENT",    _result.score_tier == ScoreTier.EXCELLENT)
    _check("latency_display == '85ms'",  _result.latency_display == "85ms")
    _check("score_display == '91.5'",    _result.score_display == "91.5")
    _check("protocol == vless",          _result.protocol == PROTO_VLESS)
    _check("host == 1.2.3.4",            _result.host == "1.2.3.4")
    _check("port == 443",                _result.port == 443)
    _check("csv_row len matches hdr",    (
        len(_result.to_csv_row()) == len(ScanResult.csv_headers())
    ))

    # ── ScanStats ─────────────────────────────────────────────────
    print("\n── ScanStats ────────────────────────────────────────")

    _stats = ScanStats(total=4)
    _stats.record(_result)
    _stats.record(ScanResult(
        sni    = "good2.example.com",
        status = ScanStatus.MATCH.value,
        score  = 70.0,
    ))
    _stats.record(ScanResult(
        sni    = "bad.example.com",
        status = ScanStatus.ERROR.value,
    ))
    _stats.record(ScanResult(
        sni    = "skip.example.com",
        status = ScanStatus.SKIP.value,
    ))
    _check("tested == 4",                _stats.tested  == 4)
    _check("matched == 2",               _stats.matched == 2)
    _check("failed == 1",                _stats.failed  == 1)
    _check("skipped == 1",               _stats.skipped == 1)
    _check("best_sni correct",           _stats.best_sni == "cdn.example.com")
    _check("best_score == 91.5",         _stats.best_score == 91.5)
    _check("progress_pct == 100.0",      _stats.progress_pct == 100.0)
    _check("success_rate == 50.0",       _stats.success_rate == 50.0)
    _check("top_results(1) len == 1",    len(_stats.top_results(1)) == 1)
    _stats.finish()
    _check("is_finished is True",        _stats.is_finished is True)
    _stats.reset()
    _check("reset clears tested",        _stats.tested == 0)
    _check("reset clears results",       len(_stats.results) == 0)

    # ── ScanConfig ────────────────────────────────────────────────
    print("\n── ScanConfig ───────────────────────────────────────")

    _sc = ScanConfig(
        threads         = 10,
        timeout_connect = 2.0,
        timeout_tls     = 4.0,
        retries         = 1,
        retry_delay     = 0.3,
        sni_list        = ["cdn.example.com", "sub.example.com"],
        target_config   = _cfg,
    )
    _check("is_ready is True",           _sc.is_ready is True)
    _check("sni_count == 2",             _sc.sni_count == 2)
    _check("total_timeout > 0",          _sc.total_timeout > 0)
    _check("to_dict has 'threads'",      "threads" in _sc.to_dict())
    _check("empty config not ready",     ScanConfig().is_ready is False)

    # ── AppState ──────────────────────────────────────────────────
    print("\n── AppState ─────────────────────────────────────────")

    _app = AppState(
        configs       = [_cfg],
        active_config = _cfg,
        sni_pool      = ["cdn.example.com", "sub.example.com"],
    )
    _check("config_count == 1",          _app.config_count == 1)
    _check("sni_count == 2",             _app.sni_count == 2)
    _check("can_scan is True",           _app.can_scan is True)
    _app.start_scan()
    _check("is_scanning after start",    _app.is_scanning is True)
    _check("can_scan False mid-scan",    _app.can_scan is False)
    _app.toggle_pause()
    _check("is_paused after toggle",     _app.is_paused is True)
    _app.toggle_pause()
    _check("is_paused toggled back",     _app.is_paused is False)
    _app.request_stop()
    _check("stop_requested is True",     _app.stop_requested is True)
    _app.finish_scan()
    _check("is_scanning after finish",   _app.is_scanning is False)
    _check("scan_runs == 1",             _app.scan_runs == 1)
    _app.set_error("test error")
    _check("last_error set",             _app.last_error == "test error")
    _check("session_id len == 8",        len(_app.session_id) == 8)

    # ── ExportData ────────────────────────────────────────────────
    print("\n── ExportData ───────────────────────────────────────")

    _export = ExportData(
        results     = [_result],
        stats       = _stats,
        config      = _cfg,
        scan_config = _sc,
        format      = "json",
        session_id  = _app.session_id,
        app_version = "1.0.0",
    )
    _check("result_count == 1",          _export.result_count == 1)
    _check("matched_results len == 1",   len(_export.matched_results) == 1)
    _check("top_uris len == 1",          len(_export.top_uris) == 1)
    _check("match_rate == 100.0",        _export.match_rate == 100.0)
    _check("avg_score == 91.5",          _export.avg_score == 91.5)
    _check("avg_latency == 85.0",        _export.avg_latency == 85.0)
    _check("has_matched is True",        _export.has_matched is True)
    _json = _export.to_json()
    _check("to_json has 'results'",      '"results"' in _json)
    _check("to_json has 'meta'",         '"meta"'    in _json)
    _check("to_json valid JSON",         bool(json.loads(_json)))
    _check("to_csv not empty",           len(_export.to_csv()) > 0)
    _check("to_uri_list not empty",      len(_export.to_uri_list()) > 0)

    # ── __all__ completeness ──────────────────────────────────────
    print("\n── __all__ completeness ─────────────────────────────")

    for _cls in [
        "ParsedConfig", "CertInfo", "TLSProbeResult",
        "ScanResult", "ScanStats", "ScanConfig",
        "AppState", "ExportData",
    ]:
        _check(f"{_cls} in __all__", _cls in __all__)

    # ── Final Report ──────────────────────────────────────────────
    print()
    print("══════════════════════════════════════════════════════")
    if _errors:
        print(f"  FAILED — {len(_errors)} test(s):")
        for _e in _errors:
            print(f"    • {_e}")
        print("══════════════════════════════════════════════════════")
        sys.exit(1)
    else:
        print("  All tests passed ✓")
        print("══════════════════════════════════════════════════════")
        sys.exit(0)


# ══════════════════════════════════════════════════════════════════
#  END OF FILE
# ══════════════════════════════════════════════════════════════════