#!/usr/bin/env python3
"""
config.py — Application Configuration Manager
Handles loading, saving, validation, and runtime access to all settings.
"""

from __future__ import annotations

import os
import json
import copy
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Version & Identity ────────────────────────────────────────────

APP_NAME     = "SNI Scanner"
APP_SUBTITLE = "Proxy Config Tester & SNI Finder"
VERSION      = "2.0.0"
THEME        = "default"


# ── Base Paths ────────────────────────────────────────────────────

BASE_DIR     = Path(__file__).parent.resolve()
DATA_DIR     = BASE_DIR / "data"
SNI_LIST_DIR = DATA_DIR / "sni_lists"
RESULTS_DIR  = DATA_DIR / "results"
LOGS_DIR     = DATA_DIR / "logs"
BACKUP_DIR   = DATA_DIR / "backups"


# ── File Paths ────────────────────────────────────────────────────

CONFIG_FILE      = BASE_DIR  / "config.json"
DEFAULT_SNI_FILE = SNI_LIST_DIR / "default.txt"
CUSTOM_SNI_FILE  = SNI_LIST_DIR / "custom.txt"
IRAN_SNI_FILE    = SNI_LIST_DIR / "iran.txt"
RESULTS_FILE     = RESULTS_DIR  / "results.json"
LAST_SCAN_FILE   = RESULTS_DIR  / "last_scan.json"
LOG_FILE         = LOGS_DIR     / "app.log"


# ── Protocol Constants ────────────────────────────────────────────

SUPPORTED_PROTOCOLS = ["vless", "vmess", "trojan", "ss", "tuic", "hy2"]

PROTO_VLESS  = "vless"
PROTO_VMESS  = "vmess"
PROTO_TROJAN = "trojan"
PROTO_SS     = "ss"
PROTO_TUIC   = "tuic"
PROTO_HY2    = "hy2"


# ── Security Constants ────────────────────────────────────────────

SEC_TLS     = "tls"
SEC_REALITY = "reality"
SEC_NONE    = "none"


# ── Network Constants ─────────────────────────────────────────────

NET_TCP         = "tcp"
NET_WS          = "ws"
NET_GRPC        = "grpc"
NET_H2          = "h2"
NET_HTTPUPGRADE = "httpupgrade"
NET_HTTP        = "http"


# ── TLS Fingerprints ──────────────────────────────────────────────

TLS_FINGERPRINTS = [
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
]


# ── DNS Servers ───────────────────────────────────────────────────

IRAN_DNS_SERVERS = [
    "178.22.122.100",
    "185.51.200.2",
    "10.202.10.10",
    "10.202.10.11",
]

DEFAULT_DNS_SERVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
]


# ── Default Settings ──────────────────────────────────────────────

DEFAULTS: Dict[str, Any] = {
    # Network
    "timeout":          6,
    "max_workers":      10,
    "retry_count":      2,
    "retry_delay":      1.0,
    "smart_retry":      1,   # 0=Off/Fast, 1=Normal, 2=Accurate, 3=Max
    "use_cache":        True,
    "cache_ttl":        900,  # seconds
    "stability_runs":   1,    # 1=off/fast, 2-5=repeat successful probes

    # TLS
    "tls_fingerprint":  "chrome",
    "verify_cert":      False,
    "min_tls_version":  "TLSv1.2",

    # DNS
    "use_iran_dns":     False,
    "custom_dns":       [],
    "dns_timeout":      3,

    # SNI Scanner
    "sni_threads":      20,
    "sni_timeout":      5.0,
    "sni_retry":        1,
    "sni_min_conf":     30,

    # Results
    "save_results":     True,
    "results_dir":      str(RESULTS_DIR),
    "max_saved":        500,

    # Config rebuild
    "auto_rebuild":     True,
    "rebuild_on_best":  True,

    # Display
    "show_cert_info":   True,
    "show_ip":          True,
    "theme":            "default",
    "log_level":        "INFO",

    # Scoring weights
    "score_tcp":        20,
    "score_tls":        30,
    "score_http":       30,
    "score_proxy":      20,
}


# ── Validation Rules ──────────────────────────────────────────────

VALIDATORS: Dict[str, Any] = {
    "timeout":          lambda v: isinstance(v, int)   and 1   <= v <= 60,
    "max_workers":      lambda v: isinstance(v, int)   and 1   <= v <= 200,
    "retry_count":      lambda v: isinstance(v, int)   and 0   <= v <= 10,
    "retry_delay":      lambda v: isinstance(v, float) and 0.0 <= v <= 10.0,
    "smart_retry":      lambda v: isinstance(v, int)   and 0   <= v <= 3,
    "use_cache":        lambda v: isinstance(v, bool),
    "cache_ttl":        lambda v: isinstance(v, int)   and 30  <= v <= 86400,
    "stability_runs":   lambda v: isinstance(v, int)   and 1   <= v <= 5,
    "tls_fingerprint":  lambda v: v in TLS_FINGERPRINTS,
    "verify_cert":      lambda v: isinstance(v, bool),
    "min_tls_version":  lambda v: v in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
    "use_iran_dns":     lambda v: isinstance(v, bool),
    "custom_dns":       lambda v: isinstance(v, list),
    "dns_timeout":      lambda v: isinstance(v, int)   and 1   <= v <= 30,
    "sni_threads":      lambda v: isinstance(v, int)   and 1   <= v <= 200,
    "sni_timeout":      lambda v: isinstance(v, float) and 0.5 <= v <= 30.0,
    "sni_retry":        lambda v: isinstance(v, int)   and 0   <= v <= 10,
    "sni_min_conf":     lambda v: isinstance(v, int)   and 0   <= v <= 100,
    "save_results":     lambda v: isinstance(v, bool),
    "results_dir":      lambda v: isinstance(v, str)   and len(v) > 0,
    "max_saved":        lambda v: isinstance(v, int)   and 1   <= v <= 10000,
    "auto_rebuild":     lambda v: isinstance(v, bool),
    "rebuild_on_best":  lambda v: isinstance(v, bool),
    "show_cert_info":   lambda v: isinstance(v, bool),
    "show_ip":          lambda v: isinstance(v, bool),
    "theme":            lambda v: isinstance(v, str),
    "log_level":        lambda v: v in ("DEBUG", "INFO", "WARNING", "ERROR"),
    "score_tcp":        lambda v: isinstance(v, int)   and 0   <= v <= 100,
    "score_tls":        lambda v: isinstance(v, int)   and 0   <= v <= 100,
    "score_http":       lambda v: isinstance(v, int)   and 0   <= v <= 100,
    "score_proxy":      lambda v: isinstance(v, int)   and 0   <= v <= 100,
}


# ── Type Coercion Map ─────────────────────────────────────────────

TYPE_MAP: Dict[str, type] = {
    "timeout":          int,
    "max_workers":      int,
    "retry_count":      int,
    "retry_delay":      float,
    "smart_retry":      int,
    "use_cache":        bool,
    "cache_ttl":        int,
    "stability_runs":   int,
    "tls_fingerprint":  str,
    "verify_cert":      bool,
    "min_tls_version":  str,
    "use_iran_dns":     bool,
    "custom_dns":       list,
    "dns_timeout":      int,
    "sni_threads":      int,
    "sni_timeout":      float,
    "sni_retry":        int,
    "sni_min_conf":     int,
    "save_results":     bool,
    "results_dir":      str,
    "max_saved":        int,
    "auto_rebuild":     bool,
    "rebuild_on_best":  bool,
    "show_cert_info":   bool,
    "show_ip":          bool,
    "theme":            str,
    "log_level":        str,
    "score_tcp":        int,
    "score_tls":        int,
    "score_http":       int,
    "score_proxy":      int,
}


# ── ConfigManager ─────────────────────────────────────────────────

class ConfigManager:
    """
    Singleton-style configuration manager.

    Responsibilities:
      - Load settings from config.json on startup
      - Merge with DEFAULTS (missing keys filled automatically)
      - Validate and coerce values on set()
      - Persist changes to disk immediately
      - Provide typed helper accessors
    """

    def __init__(self, config_file: Path = CONFIG_FILE):
        self._file:     Path           = config_file
        self._data:     Dict[str, Any] = {}
        self._defaults: Dict[str, Any] = copy.deepcopy(DEFAULTS)
        self._load()

    # ── Internal Load ─────────────────────────────────────────────

    def _load(self) -> None:
        """Load config from disk and merge with defaults."""
        base = copy.deepcopy(self._defaults)

        if self._file.exists():
            try:
                with open(self._file, "r", encoding="utf-8") as f:
                    on_disk: Dict[str, Any] = json.load(f)

                for key, val in on_disk.items():
                    if key in base:
                        coerced = self._coerce(key, val)
                        if coerced is not None:
                            base[key] = coerced

            except (json.JSONDecodeError, OSError):
                pass   # silently fall back to defaults

        self._data = base

    # ── Type Coercion ─────────────────────────────────────────────

    def _coerce(self, key: str, value: Any) -> Optional[Any]:
        """
        Coerces value to the expected type for key.
        Returns None if coercion fails.
        """
        expected = TYPE_MAP.get(key)
        if expected is None:
            return value

        try:
            if expected is bool:
                if isinstance(value, bool): return value
                if isinstance(value, str):  return value.lower() in ("true", "1", "yes")
                return bool(value)

            if expected is int:   return int(value)
            if expected is float: return float(value)
            if expected is str:   return str(value)
            if expected is list:
                return list(value) if not isinstance(value, list) else value

        except (ValueError, TypeError):
            return None

        return value

    # ── Public Read API ───────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """Returns config value for key, or default if not found."""
        return self._data.get(key, default)

    def all(self) -> Dict[str, Any]:
        """Returns a full copy of current settings."""
        return copy.deepcopy(self._data)

    def is_valid_key(self, key: str) -> bool:
        """Returns True if key is a known config key."""
        return key in self._defaults

    # ── Public Write API ──────────────────────────────────────────

    def set(self, key: str, value: Any) -> bool:
        """
        Sets a config value after validation and coercion.

        Returns:
            True  — value accepted and saved
            False — invalid key, type mismatch, or validation failure
        """
        if key not in self._defaults:
            return False

        coerced = self._coerce(key, value)
        if coerced is None:
            return False

        validator = VALIDATORS.get(key)
        if validator and not validator(coerced):
            return False

        self._data[key] = coerced
        self._save()
        return True

    def set_many(self, updates: Dict[str, Any]) -> Dict[str, bool]:
        """
        Sets multiple keys at once.

        Returns:
            dict mapping key → True/False (success per key)
        """
        results: Dict[str, bool] = {}
        for key, value in updates.items():
            results[key] = self.set(key, value)
        return results

    def reset_key(self, key: str) -> bool:
        """
        Resets a single key to its factory default.

        Returns:
            True  — key found and reset
            False — key not found
        """
        if key not in self._defaults:
            return False
        self._data[key] = copy.deepcopy(self._defaults[key])
        self._save()
        return True

    def reset_defaults(self) -> None:
        """Resets ALL settings to factory defaults and saves."""
        self._data = copy.deepcopy(self._defaults)
        self._save()

    def reload(self) -> None:
        """Re-reads config from disk (discards unsaved in-memory changes)."""
        self._load()

    # ── Persistence ───────────────────────────────────────────────

    def _save(self) -> None:
        """Writes current config to disk as JSON."""
        try:
            self._file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    # ── Typed Helpers ─────────────────────────────────────────────

    def get_dns_servers(self) -> List[str]:
        """
        Returns the active DNS server list.

        Priority:
          1. custom_dns  (if set)
          2. IRAN_DNS_SERVERS  (if use_iran_dns=True)
          3. DEFAULT_DNS_SERVERS
        """
        custom = self.get("custom_dns", [])
        if custom:
            return custom
        if self.get("use_iran_dns", False):
            return IRAN_DNS_SERVERS
        return DEFAULT_DNS_SERVERS

    def get_effective_retry(self) -> int:
        """Return the global retry attempts used by all scanner sections.

        smart_retry levels:
          0 = Off/Fast   -> 1 attempt
          1 = Normal     -> 1 retry level / 1 attempt in probe loops
          2 = Accurate   -> 2 attempts
          3 = Max        -> 3 attempts
        The value is mirrored to sni_retry/retry_count by the settings menu.
        """
        try:
            level = int(self.get("smart_retry", self.get("sni_retry", 1)))
        except Exception:
            level = 1
        return max(1, min(3, level if level > 0 else 1))

    def get_score_weights(self) -> Dict[str, int]:
        """Returns scoring weights as a dict."""
        return {
            "tcp":   self.get("score_tcp",   20),
            "tls":   self.get("score_tls",   30),
            "http":  self.get("score_http",  30),
            "proxy": self.get("score_proxy", 20),
        }

    def get_sni_config(self) -> Dict[str, Any]:
        """Returns SNI scanner related settings as a dict."""
        return {
            "threads":    self.get("sni_threads",  20),
            "timeout":    self.get("sni_timeout",  5.0),
            "retry":      self.get_effective_retry(),
            "min_conf":   self.get("sni_min_conf", 30),
        }

    def get_tls_config(self) -> Dict[str, Any]:
        """Returns TLS related settings as a dict."""
        return {
            "fingerprint": self.get("tls_fingerprint", "chrome"),
            "verify_cert": self.get("verify_cert",     False),
            "min_version": self.get("min_tls_version", "TLSv1.2"),
        }

    def get_network_config(self) -> Dict[str, Any]:
        """Returns general network settings as a dict."""
        return {
            "timeout":     self.get("timeout",     6),
            "max_workers": self.get("max_workers", 10),
            "retry_count": self.get_effective_retry(),
            "retry_delay": self.get("retry_delay", 1.0),
            "smart_retry": self.get("smart_retry", 1),
        }

    def ensure_dirs(self) -> None:
        """Creates all required data directories if they don't exist."""
        for directory in (DATA_DIR, SNI_LIST_DIR, RESULTS_DIR, LOGS_DIR, BACKUP_DIR):
            directory.mkdir(parents=True, exist_ok=True)

    def __repr__(self) -> str:
        return (
            f"<ConfigManager "
            f"file={self._file.name} "
            f"keys={len(self._data)}>"
        )


# ── Singleton Instance ────────────────────────────────────────────

config_manager = ConfigManager()


# ── Score Calculator ──────────────────────────────────────────────

class ScoreCalculator:
    """
    Calculates a 0-100 score for a ConfigTestResult
    based on weighted stage results and quality bonuses.

    Weights (configurable via config_manager):
      tcp   : 20  — basic reachability
      tls   : 30  — TLS handshake quality
      http  : 30  — HTTP/WS probe response
      proxy : 20  — overall proxy behaviour

    Bonuses:
      TLS 1.3       : +5
      HTTP 2xx      : +5
      Low latency   : up to +5

    Penalties:
      High latency  : up to -10
      Cert warnings : -5 per warning
    """

    def __init__(self, weights: Optional[Dict[str, int]] = None):
        self._weights = weights or config_manager.get_score_weights()

    def calculate(self, result: "ConfigTestResult") -> float:
        """
        Computes score from test result stages.

        Returns:
            float in range [0.0, 100.0]
        """
        score = 0.0
        w     = self._weights

        # ── TCP ───────────────────────────────────────────────────
        if result.tcp_ok:
            score += w.get("tcp", 20)

        # ── TLS ───────────────────────────────────────────────────
        if result.tls_ok:
            tls_score = w.get("tls", 30)
            if result.tls_version == "TLSv1.3":
                tls_score = min(tls_score + 5, 35)
            score += tls_score

        # ── HTTP ──────────────────────────────────────────────────
        if result.http_ok:
            http_score = w.get("http", 30)
            if result.http_status and 200 <= result.http_status < 300:
                http_score = min(http_score + 5, 35)
            score += http_score

        # ── Proxy / Overall ───────────────────────────────────────
        if result.overall_ok:
            score += w.get("proxy", 20)

        # ── Latency Bonus ─────────────────────────────────────────
        lat = result.tcp_latency_ms
        if result.tcp_ok and lat > 0:
            if   lat <= 100:  score += 5
            elif lat <= 300:  score += 3
            elif lat <= 600:  score += 1

        # ── Latency Penalty ───────────────────────────────────────
        if result.tcp_ok and lat > 0:
            if   lat > 2000:  score = max(0.0, score - 10)
            elif lat > 1000:  score = max(0.0, score - 5)
            elif lat >  500:  score = max(0.0, score - 2)

        # ── Cert Bonus ────────────────────────────────────────────
        if result.tls_ok and result.cert_valid:
            score = min(score + 3, 100.0)

        # ── Warning Penalty ───────────────────────────────────────
        if result.warnings:
            score = max(0.0, score - len(result.warnings) * 2)

        return round(min(score, 100.0), 1)


# ── ParsedConfig ──────────────────────────────────────────────────

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class ParsedConfig:
    """
    Represents a fully parsed proxy configuration.

    Populated by parser.py.
    Consumed by config_tester.py and sni_scanner.py.

    Field naming rules (strictly enforced):
      sni         → TLS SNI field ONLY
      host_header → HTTP Host header ONLY
      host        → remote server address
      These three are NEVER interchangeable.
    """

    # ── Core identity ─────────────────────────────────────────────
    raw:          Optional[str] = None   # original input URI
    protocol:     Optional[str] = None   # vless / vmess / trojan / ss / tuic / hy2
    tag:          Optional[str] = None   # human-readable label (#tag)
    is_valid:     bool          = False  # set True after successful parse
    parse_error:  str           = ""     # non-empty if parse failed

    # ── Connection ────────────────────────────────────────────────
    host:         Optional[str] = None   # remote server address (IP or domain)
    port:         Optional[int] = None   # remote server port
    uuid:         Optional[str] = None   # UUID (vless/vmess/trojan)
    password:     Optional[str] = None   # password alias (trojan/ss)

    # ── TLS ───────────────────────────────────────────────────────
    security:     Optional[str] = None   # tls / reality / none
    sni:          Optional[str] = None   # TLS SNI — ONLY used for TLS handshake
    alpn:         Optional[str] = None   # h2 / http/1.1 / h2,http/1.1
    fingerprint:  Optional[str] = None   # TLS client fingerprint
    allow_insecure: bool        = False  # skip cert verification

    # ── Transport ─────────────────────────────────────────────────
    network:      Optional[str] = None   # tcp / ws / grpc / h2 / httpupgrade
    path:         Optional[str] = None   # WebSocket / HTTP path
    host_header:  Optional[str] = None   # HTTP Host header — ONLY used in HTTP requests
    grpc_service_name: Optional[str] = None  # gRPC service name

    # ── Reality ───────────────────────────────────────────────────
    public_key:   Optional[str] = None   # Reality public key
    short_id:     Optional[str] = None   # Reality short ID
    spider_x:     Optional[str] = None   # Reality spider X

    # ── VMess extras ─────────────────────────────────────────────
    aid:          Optional[int] = None   # AlterID
    cipher:       Optional[str] = None   # cipher method

    # ── SS extras ────────────────────────────────────────────────
    method:       Optional[str] = None   # SS encryption method
    plugin:       Optional[str] = None   # SS plugin

    # ── TUIC extras ──────────────────────────────────────────────
    congestion:   Optional[str] = None   # TUIC congestion control

    # ── Runtime ───────────────────────────────────────────────────
    ip_resolved:  Optional[str] = None   # resolved IP after DNS lookup

    # ── Catch-all ─────────────────────────────────────────────────
    extra:        Dict[str, str] = field(default_factory=dict)

    # ── Computed Properties ───────────────────────────────────────

    @property
    def effective_sni(self) -> str:
        """
        Best available SNI for TLS handshake.
        Priority: sni → host (domain only, never IP)
        host_header is NEVER used as SNI.
        """
        if self.sni and self.sni.strip():
            return self.sni.strip()
        if self.host and not _is_ip_address(self.host):
            return self.host.strip()
        return ""

    @property
    def effective_host_header(self) -> str:
        """
        Best available HTTP Host header value.
        Priority: host_header → host
        sni is NEVER used as Host header.
        """
        if self.host_header and self.host_header.strip():
            return self.host_header.strip()
        return (self.host or "").strip()

    @property
    def effective_password(self) -> str:
        """Returns password or uuid — whichever is set."""
        return self.password or self.uuid or ""

    @property
    def alpn_list(self) -> List[str]:
        """Returns ALPN string as a parsed list."""
        if not self.alpn:
            return []
        return [a.strip() for a in self.alpn.split(",") if a.strip()]

    @property
    def is_tls(self) -> bool:
        return (self.security or "").lower() in (SEC_TLS, SEC_REALITY)

    @property
    def is_reality(self) -> bool:
        return (self.security or "").lower() == SEC_REALITY

    @property
    def is_cdn(self) -> bool:
        """
        Heuristic: config is CDN-routed if
        host_header differs from host.
        """
        if not self.host_header or not self.host:
            return False
        return self.host_header.lower() != self.host.lower()

    @property
    def display_name(self) -> str:
        """Short human-readable label."""
        proto = (self.protocol or "?").upper()
        host  = self.host or "?"
        port  = self.port or 0
        tag   = f" [{self.tag}]" if self.tag else ""
        return f"{proto}  {host}:{port}{tag}"

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol":          self.protocol,
            "tag":               self.tag,
            "host":              self.host,
            "port":              self.port,
            "uuid":              self.uuid,
            "password":          self.password,
            "security":          self.security,
            "sni":               self.sni,
            "alpn":              self.alpn,
            "fingerprint":       self.fingerprint,
            "allow_insecure":    self.allow_insecure,
            "network":           self.network,
            "path":              self.path,
            "host_header":       self.host_header,
            "grpc_service_name": self.grpc_service_name,
            "public_key":        self.public_key,
            "short_id":          self.short_id,
            "spider_x":          self.spider_x,
            "method":            self.method,
            "plugin":            self.plugin,
            "congestion":        self.congestion,
            "ip_resolved":       self.ip_resolved,
            "is_valid":          self.is_valid,
            "parse_error":       self.parse_error,
        }


# ── Helper ────────────────────────────────────────────────────────

def _is_ip_address(host: str) -> bool:
    """Returns True if host is an IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ── SNIResult ─────────────────────────────────────────────────────

@dataclass
class SNIResult:
    """
    Result of a single SNI probe performed by SNIScanner.

    Lifecycle:
      1. SNIScanner creates one SNIResult per SNI candidate
      2. TCP connect → tls handshake → cert inspection
      3. Scoring and ranking done by SNIResultAnalyzer
    """

    # ── Identity ──────────────────────────────────────────────────
    sni:              Optional[str]  = None   # SNI domain tested
    ip_resolved:      Optional[str]  = None   # IP used for connection

    # ── TCP ───────────────────────────────────────────────────────
    tcp_ok:           bool           = False
    tcp_latency_ms:   float          = 0.0

    # ── TLS ───────────────────────────────────────────────────────
    tls_ok:           bool           = False
    tls_version:      Optional[str]  = None   # TLSv1.2 / TLSv1.3
    alpn_negotiated:  Optional[str]  = None   # negotiated ALPN protocol
    cert_cn:          Optional[str]  = None   # certificate CN
    cert_san:         List[str]      = field(default_factory=list)
    cert_expiry:      Optional[str]  = None   # ISO date string
    cert_issuer:      Optional[str]  = None
    cert_valid:       bool           = False  # not expired + CN matches

    # ── Handshake ─────────────────────────────────────────────────
    handshake_ok:     bool           = False  # tcp_ok AND tls_ok
    latency_ms:       float          = 0.0    # total round-trip latency

    # ── Scoring ───────────────────────────────────────────────────
    score:            float          = 0.0    # 0.0 – 100.0
    confidence:       int            = 0      # 0 – 100 match confidence
    iran_friendly:    bool           = False  # passes Iran DPI heuristic

    # ── Error ─────────────────────────────────────────────────────
    error:            Optional[str]  = None
    error_stage:      Optional[str]  = None   # tcp / tls / cert

    # ── Computed Properties ───────────────────────────────────────

    @property
    def is_reachable(self) -> bool:
        return self.tcp_ok

    @property
    def short_status(self) -> str:
        """One-line status string for display."""
        if self.handshake_ok:
            return f"OK  {self.latency_ms:.0f}ms  {self.tls_version or '?'}"
        if self.tcp_ok:
            return f"TCP_OK  TLS_FAIL  {self.error or ''}"
        return f"FAIL  {self.error or 'unreachable'}"

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sni":             self.sni,
            "ip_resolved":     self.ip_resolved,
            "tcp_ok":          self.tcp_ok,
            "tcp_latency_ms":  self.tcp_latency_ms,
            "tls_ok":          self.tls_ok,
            "tls_version":     self.tls_version,
            "alpn_negotiated": self.alpn_negotiated,
            "cert_cn":         self.cert_cn,
            "cert_san":        self.cert_san,
            "cert_expiry":     self.cert_expiry,
            "cert_issuer":     self.cert_issuer,
            "cert_valid":      self.cert_valid,
            "handshake_ok":    self.handshake_ok,
            "latency_ms":      self.latency_ms,
            "score":           self.score,
            "confidence":      self.confidence,
            "iran_friendly":   self.iran_friendly,
            "error":           self.error,
            "error_stage":     self.error_stage,
        }


# ── ConfigTestResult ──────────────────────────────────────────────

@dataclass
class ConfigTestResult:
    """
    Full result of a ConfigTester run on a single ParsedConfig.

    Test pipeline:
      DNS → TCP → TLS → HTTP → (Proxy)

    Each stage sets its own ok/latency fields.
    stage_failed is set to the name of the first failing stage.
    score is computed by ScoreCalculator after all stages complete.
    """

    # ── Source config ─────────────────────────────────────────────
    config:           Optional[ParsedConfig] = None
    config_type:      Optional[str]          = None   # vless/vmess/trojan/ss

    # ── Active SNI used in this test ──────────────────────────────
    sni:              Optional[str]          = None

    # ── DNS ───────────────────────────────────────────────────────
    dns_ok:           bool                   = False
    ip_resolved:      Optional[str]          = None
    dns_latency_ms:   float                  = 0.0

    # ── TCP ───────────────────────────────────────────────────────
    tcp_ok:           bool                   = False
    tcp_reachable:    bool                   = False
    tcp_latency_ms:   float                  = 0.0

    # ── TLS ───────────────────────────────────────────────────────
    tls_ok:           bool                   = False
    tls_version:      Optional[str]          = None
    alpn_negotiated:  Optional[str]          = None
    cert_cn:          Optional[str]          = None
    cert_valid:       bool                   = False
    cert_expiry:      Optional[str]          = None
    tls_latency_ms:   float                  = 0.0

    # ── HTTP ──────────────────────────────────────────────────────
    http_ok:          bool                   = False
    http_status:      int                    = 0
    http_latency_ms:  float                  = 0.0
    http_body_sample: Optional[str]          = None

    # ── CDN detection ─────────────────────────────────────────────
    is_cdn:           bool                   = False
    cdn_provider:     Optional[str]          = None

    # ── Score & verdict ───────────────────────────────────────────
    score:            float                  = 0.0
    overall_ok:       bool                   = False

    # ── Rebuilt config ────────────────────────────────────────────
    rebuilt_config:   Optional[str]          = None

    # ── Test metadata ─────────────────────────────────────────────
    test_duration_ms: float                  = 0.0
    test_stages:      Dict[str, str]         = field(default_factory=dict)
    # test_stages example:
    #   {"dns": "PASS", "tcp": "PASS", "tls": "FAIL", "http": "SKIP"}

    # ── Warnings & errors ─────────────────────────────────────────
    warnings:         List[str]              = field(default_factory=list)
    error:            Optional[str]          = None
    stage_failed:     Optional[str]          = None   # dns/tcp/tls/http

    # ── Computed Properties ───────────────────────────────────────

    @property
    def host(self) -> str:
        return self.config.host if self.config else ""

    @property
    def port(self) -> int:
        return self.config.port if self.config else 0

    @property
    def score_label(self) -> str:
        """Human-readable score label."""
        if self.score >= 80: return "Excellent"
        if self.score >= 60: return "Good"
        if self.score >= 40: return "Fair"
        if self.score >= 20: return "Poor"
        return "Failed"

    @property
    def score_color(self) -> str:
        """Rich color name for score display."""
        if self.score >= 70: return "green"
        if self.score >= 40: return "yellow"
        return "red"

    @property
    def stage_summary(self) -> str:
        """
        Compact one-line stage summary.
        Example: DNS:OK  TCP:OK  TLS:FAIL  HTTP:SKIP
        """
        parts = []
        for stage in ("dns", "tcp", "tls", "http"):
            status = self.test_stages.get(stage, "SKIP")
            parts.append(f"{stage.upper()}:{status}")
        return "  ".join(parts)

    def set_stage(self, stage: str, passed: bool) -> None:
        """
        Records a stage result.

        Args:
            stage  : one of dns / tcp / tls / http / proxy
            passed : True → PASS, False → FAIL
        """
        self.test_stages[stage] = "PASS" if passed else "FAIL"
        if not passed and self.stage_failed is None:
            self.stage_failed = stage

    def add_warning(self, msg: str) -> None:
        """Appends a warning message."""
        if msg and msg not in self.warnings:
            self.warnings.append(msg)

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config_type":      self.config_type,
            "host":             self.host,
            "port":             self.port,
            "sni":              self.sni,
            "dns_ok":           self.dns_ok,
            "ip_resolved":      self.ip_resolved,
            "dns_latency_ms":   self.dns_latency_ms,
            "tcp_ok":           self.tcp_ok,
            "tcp_reachable":    self.tcp_reachable,
            "tcp_latency_ms":   self.tcp_latency_ms,
            "tls_ok":           self.tls_ok,
            "tls_version":      self.tls_version,
            "alpn_negotiated":  self.alpn_negotiated,
            "cert_cn":          self.cert_cn,
            "cert_valid":       self.cert_valid,
            "cert_expiry":      self.cert_expiry,
            "tls_latency_ms":   self.tls_latency_ms,
            "http_ok":          self.http_ok,
            "http_status":      self.http_status,
            "http_latency_ms":  self.http_latency_ms,
            "is_cdn":           self.is_cdn,
            "cdn_provider":     self.cdn_provider,
            "score":            self.score,
            "score_label":      self.score_label,
            "overall_ok":       self.overall_ok,
            "rebuilt_config":   self.rebuilt_config,
            "test_duration_ms": self.test_duration_ms,
            "stage_summary":    self.stage_summary,
            "test_stages":      self.test_stages,
            "warnings":         self.warnings,
            "error":            self.error,
            "stage_failed":     self.stage_failed,
        }


# ── CDN Provider Signatures ───────────────────────────────────────

CDN_PROVIDERS: Dict[str, List[str]] = {
    "Cloudflare": [
        "cloudflare.com", "cdn.cloudflare.com",
        "104.16.", "104.17.", "104.18.", "104.19.",
        "172.64.", "172.65.", "172.66.", "172.67.",
        "162.158.", "198.41.",
    ],
    "Fastly": [
        "fastly.com", "fastly.net",
        "151.101.", "199.232.",
    ],
    "Akamai": [
        "akamai.com", "akamaiedge.net", "akamaized.net",
        "edgekey.net", "edgesuite.net",
    ],
    "Amazon CloudFront": [
        "cloudfront.net", "amazonaws.com",
        "13.32.", "13.35.", "52.84.", "52.85.",
    ],
    "Google": [
        "google.com", "googleapis.com", "googleusercontent.com",
        "gstatic.com", "googlevideo.com",
        "142.250.", "172.217.", "216.58.",
    ],
    "Microsoft Azure": [
        "azureedge.net", "azure.com", "msecnd.net",
        "trafficmanager.net",
    ],
    "ArvanCloud": [
        "arvancloud.com", "arvancloud.ir",
        "185.143.232.", "185.143.233.",
        "185.143.234.", "185.143.235.",
    ],
    "Iranserver": [
        "iranserver.com",
    ],
    "Parspack": [
        "parspack.com", "parspack.net",
    ],
}


def detect_cdn_provider(host: str, ip: Optional[str] = None) -> Optional[str]:
    """
    Detects CDN provider from host or resolved IP.

    Args:
        host : domain name or hostname
        ip   : resolved IP address (optional)

    Returns:
        Provider name string, or None if not detected.
    """
    targets = []
    if host: targets.append(host.lower())
    if ip:   targets.append(ip)

    for provider, signatures in CDN_PROVIDERS.items():
        for sig in signatures:
            for target in targets:
                if sig.lower() in target:
                    return provider
    return None


# ── ScanConfig ────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """
    Runtime configuration snapshot passed to SNIScanner.

    Created once per scan session from config_manager values.
    Immutable after creation — never modified during scan.

    Usage:
        scan_cfg = ScanConfig.from_manager()
        scanner  = SNIScanner(parsed_config, scan_cfg)
    """

    # ── Network ───────────────────────────────────────────────────
    timeout:        float        = 6.0
    max_workers:    int          = 10
    retry_count:    int          = 2
    retry_delay:    float        = 1.0

    # ── TLS ───────────────────────────────────────────────────────
    tls_fingerprint: str         = "chrome"
    verify_cert:    bool         = False
    min_tls_version: str         = "TLSv1.2"

    # ── DNS ───────────────────────────────────────────────────────
    dns_servers:    List[str]    = field(default_factory=lambda: DEFAULT_DNS_SERVERS.copy())
    dns_timeout:    int          = 3

    # ── SNI Scanner ───────────────────────────────────────────────
    sni_threads:    int          = 20
    sni_timeout:    float        = 5.0
    sni_retry:      int          = 2
    sni_min_conf:   int          = 30

    # ── Results ───────────────────────────────────────────────────
    save_results:   bool         = True
    results_dir:    Path         = field(default_factory=lambda: RESULTS_DIR)
    max_saved:      int          = 500

    # ── Rebuild ───────────────────────────────────────────────────
    auto_rebuild:   bool         = True
    rebuild_on_best: bool        = True

    # ── Display ───────────────────────────────────────────────────
    show_cert_info: bool         = True
    show_ip:        bool         = True
    log_level:      str          = "INFO"

    # ── Score weights ─────────────────────────────────────────────
    score_weights:  Dict[str, int] = field(
        default_factory=lambda: {
            "tcp": 20, "tls": 30, "http": 30, "proxy": 20
        }
    )

    # ── Factory ───────────────────────────────────────────────────

    @classmethod
    def from_manager(cls, mgr: Optional[ConfigManager] = None) -> "ScanConfig":
        """
        Creates a ScanConfig snapshot from config_manager.

        Args:
            mgr : ConfigManager instance (defaults to global config_manager)

        Returns:
            Fully populated ScanConfig instance.
        """
        m = mgr or config_manager
        return cls(
            timeout         = float(m.get("timeout",          6)),
            max_workers     = m.get("max_workers",            10),
            retry_count     = m.get("retry_count",            2),
            retry_delay     = m.get("retry_delay",            1.0),
            tls_fingerprint = m.get("tls_fingerprint",        "chrome"),
            verify_cert     = m.get("verify_cert",            False),
            min_tls_version = m.get("min_tls_version",        "TLSv1.2"),
            dns_servers     = m.get_dns_servers(),
            dns_timeout     = m.get("dns_timeout",            3),
            sni_threads     = m.get("sni_threads",            20),
            sni_timeout     = m.get("sni_timeout",            5.0),
            sni_retry       = m.get("sni_retry",              2),
            sni_min_conf    = m.get("sni_min_conf",           30),
            save_results    = m.get("save_results",           True),
            results_dir     = Path(m.get("results_dir",       str(RESULTS_DIR))),
            max_saved       = m.get("max_saved",              500),
            auto_rebuild    = m.get("auto_rebuild",           True),
            rebuild_on_best = m.get("rebuild_on_best",        True),
            show_cert_info  = m.get("show_cert_info",         True),
            show_ip         = m.get("show_ip",                True),
            log_level       = m.get("log_level",              "INFO"),
            score_weights   = m.get_score_weights(),
        )

    @classmethod
    def default(cls) -> "ScanConfig":
        """Creates a ScanConfig with pure factory defaults."""
        return cls()

    # ── Helpers ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeout":          self.timeout,
            "max_workers":      self.max_workers,
            "retry_count":      self.retry_count,
            "retry_delay":      self.retry_delay,
            "tls_fingerprint":  self.tls_fingerprint,
            "verify_cert":      self.verify_cert,
            "min_tls_version":  self.min_tls_version,
            "dns_servers":      self.dns_servers,
            "dns_timeout":      self.dns_timeout,
            "sni_threads":      self.sni_threads,
            "sni_timeout":      self.sni_timeout,
            "sni_retry":        self.sni_retry,
            "sni_min_conf":     self.sni_min_conf,
            "save_results":     self.save_results,
            "results_dir":      str(self.results_dir),
            "max_saved":        self.max_saved,
            "auto_rebuild":     self.auto_rebuild,
            "rebuild_on_best":  self.rebuild_on_best,
            "show_cert_info":   self.show_cert_info,
            "show_ip":          self.show_ip,
            "log_level":        self.log_level,
            "score_weights":    self.score_weights,
        }

    def __repr__(self) -> str:
        return (
            f"<ScanConfig "
            f"workers={self.max_workers} "
            f"timeout={self.timeout}s "
            f"sni_threads={self.sni_threads}>"
        )


# ── Module Init ───────────────────────────────────────────────────

def _bootstrap() -> None:
    """
    Called once at import time.

    Responsibilities:
      1. Create all required directories
      2. Create default SNI files if missing
      3. Validate config integrity
    """
    # Create directories
    for directory in (DATA_DIR, SNI_LIST_DIR, RESULTS_DIR, LOGS_DIR, BACKUP_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    # Create default SNI file if missing
    if not DEFAULT_SNI_FILE.exists():
        DEFAULT_SNI_FILE.write_text(
            "# Default SNI List\n"
            "# Add one domain per line\n\n"
            "cloudflare.com\n"
            "www.cloudflare.com\n"
            "cdn.cloudflare.com\n"
            "workers.dev\n"
            "pages.dev\n"
            "discord.com\n"
            "www.discord.com\n"
            "telegram.org\n"
            "web.telegram.org\n"
            "google.com\n"
            "www.google.com\n"
            "googleapis.com\n"
            "github.com\n"
            "raw.githubusercontent.com\n"
            "fastly.com\n"
            "cdn.fastly.com\n",
            encoding="utf-8",
        )

    # Create custom SNI file if missing
    if not CUSTOM_SNI_FILE.exists():
        CUSTOM_SNI_FILE.write_text(
            "# Custom SNI List\n"
            "# Add your own domains here\n\n",
            encoding="utf-8",
        )

    # Create Iran-optimized SNI file if missing
    if not IRAN_SNI_FILE.exists():
        IRAN_SNI_FILE.write_text(
            "# Iran-Optimized SNI List\n"
            "# Domains known to work well from Iran\n\n"
            "www.speedtest.net\n"
            "cdnjs.cloudflare.com\n"
            "ajax.cloudflare.com\n"
            "www.aparat.com\n",
            encoding="utf-8",
        )


# Run bootstrap on import
_bootstrap()


# ── Public Exports ────────────────────────────────────────────────

__all__ = [
    # Identity
    "APP_NAME", "APP_SUBTITLE", "VERSION", "THEME",

    # Paths
    "BASE_DIR", "DATA_DIR", "SNI_LIST_DIR", "RESULTS_DIR",
    "LOGS_DIR", "BACKUP_DIR", "CONFIG_FILE",
    "DEFAULT_SNI_FILE", "CUSTOM_SNI_FILE", "IRAN_SNI_FILE",
    "RESULTS_FILE", "LAST_SCAN_FILE", "LOG_FILE",

    # Constants
    "SUPPORTED_PROTOCOLS", "TLS_FINGERPRINTS",
    "IRAN_DNS_SERVERS", "DEFAULT_DNS_SERVERS",
    "SEC_TLS", "SEC_REALITY", "SEC_NONE",
    "NET_TCP", "NET_WS", "NET_GRPC", "NET_H2",
    "NET_HTTPUPGRADE", "NET_HTTP",
    "CDN_PROVIDERS",

    # Config
    "DEFAULTS", "VALIDATORS", "TYPE_MAP",

    # Classes & instances
    "ConfigManager", "config_manager",
    "ScoreCalculator",
    "ScanConfig",

    # Data models
    "ParsedConfig",
    "SNIResult",
    "ConfigTestResult",

    # Helpers
    "detect_cdn_provider",
    "_is_ip_address",
]