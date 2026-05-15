from __future__ import annotations

import ssl
import socket
import time
import re
import threading
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, TYPE_CHECKING

from config import config_manager

# Only for type hints — never runs at runtime
if TYPE_CHECKING:
    from parser import ParsedConfig


# -----------------------------------------------------------------
# Lazy Imports — prevent circular import
# -----------------------------------------------------------------

def _get_tls_prober():
    from sni_scanner import TLSProber
    return TLSProber

def _get_dns_resolver():
    from sni_scanner import DNSResolver
    return DNSResolver

def _get_sni_result():
    from sni_scanner import SNIResult
    return SNIResult


# -----------------------------------------------------------------
# Config Type Detection
# -----------------------------------------------------------------

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def _is_ip(value: str) -> bool:
    return bool(_IP_PATTERN.match(value.strip()))


def _needs_tls(parsed_config: ParsedConfig) -> bool:
    sec = (parsed_config.security or "").strip().lower()
    if sec in ("tls", "reality", "xtls"):
        return True
    if sec in ("none", ""):
        return parsed_config.port == 443
    return False


def detect_config_type(parsed_config: ParsedConfig) -> str:
    """
    cdn_based:
        host_header != sni
        e.g. host_header=relay.vercel.app  sni=react.dev

    direct_server:
        direct IP or host_header == sni
        e.g. 185.143.233.5  or  sni=example.com

    plain_http:
        no TLS, port 80
    """
    if not _needs_tls(parsed_config):
        return "plain_http"

    server   = (parsed_config.host        or "").strip()
    sni      = (parsed_config.sni         or "").strip()
    cdn_host = (parsed_config.host_header or "").strip()

    if _is_ip(server):
        return "direct_server"

    if cdn_host and sni and cdn_host != sni:
        return "cdn_based"

    if cdn_host and server and cdn_host != server:
        return "cdn_based"

    return "direct_server"


# -----------------------------------------------------------------
# Proxy OK Status Codes by Config Type
# -----------------------------------------------------------------

PROXY_OK_STATUSES: Dict[str, set] = {
    "cdn_based":     {101, 200, 404},
    "direct_server": {101, 200, 400},
    "plain_http":    {101, 200, 404},
}

ALIVE_STATUSES = {200, 301, 302, 400, 403, 404, 429, 101}


def is_proxy_ok(status: int, config_type: str) -> bool:
    return status in PROXY_OK_STATUSES.get(config_type, set())


def is_alive(status: int) -> bool:
    return status in ALIVE_STATUSES


# -----------------------------------------------------------------
# ConfigTestResult
# -----------------------------------------------------------------

@dataclass
class ConfigTestResult:
    config:           Optional[ParsedConfig] = None
    config_type:      str   = ""
    sni:              str   = ""
    original_sni:     str   = ""
    rebuilt_config:   str   = ""

    # TCP
    tcp_reachable:    bool  = False
    tcp_latency_ms:   float = -1

    # TLS
    tls_ok:           bool  = False
    tls_latency_ms:   float = -1
    tls_version:      str   = ""
    cert_cn:          str   = ""
    cert_issuer:      str   = ""
    cert_expiry:      str   = ""
    alpn_negotiated:  str   = ""
    ip_resolved:      str   = ""

    # HTTP
    http_ok:          bool  = False
    http_status:      int   = -1
    http_latency_ms:  float = -1

    # Final
    proxy_ok:         bool  = False
    overall_ok:       bool  = False
    score:            float = 0.0
    error:            str   = ""
    warnings:         List[str]       = field(default_factory=list)
    test_stages:      Dict[str, str]  = field(default_factory=dict)
    test_duration_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "config_type":      self.config_type,
            "sni":              self.sni,
            "original_sni":     self.original_sni,
            "rebuilt_config":   (
                self.rebuilt_config[:80] + "..."
                if len(self.rebuilt_config) > 80
                else self.rebuilt_config
            ),
            "tcp_reachable":    self.tcp_reachable,
            "tcp_latency_ms":   round(self.tcp_latency_ms, 2),
            "tls_ok":           self.tls_ok,
            "tls_latency_ms":   round(self.tls_latency_ms, 2),
            "tls_version":      self.tls_version,
            "cert_cn":          self.cert_cn,
            "cert_issuer":      self.cert_issuer,
            "http_ok":          self.http_ok,
            "http_status":      self.http_status,
            "proxy_ok":         self.proxy_ok,
            "overall_ok":       self.overall_ok,
            "score":            round(self.score, 2),
            "error":            self.error,
            "warnings":         self.warnings,
            "test_stages":      self.test_stages,
            "test_duration_ms": round(self.test_duration_ms, 2),
        }


# -----------------------------------------------------------------
# Score Calculator
# -----------------------------------------------------------------

class ConfigScoreCalculator:
    def calculate(self, result: ConfigTestResult) -> float:
        score = 0.0

        if result.tcp_reachable:
            score += 15.0

        if result.tls_ok:
            score += 25.0
        elif result.test_stages.get("tls") == "SKIP":
            if result.tcp_reachable:
                score += 15.0

        if result.http_ok:
            score += 10.0

        if result.proxy_ok:
            score += 30.0

        lat = result.tcp_latency_ms
        if lat > 0:
            if   lat < 100:  score += 10.0
            elif lat < 300:  score += 7.0
            elif lat < 600:  score += 4.0
            elif lat < 1500: score += 2.0

        if result.tls_version == "TLSv1.3":
            score += 5.0
        elif result.tls_version == "TLSv1.2":
            score += 3.0

        if result.alpn_negotiated in ("h2", "h3"):
            score += 3.0

        if result.cert_cn:
            score += 2.0

        return min(score, 100.0)


# -----------------------------------------------------------------
# Stage 1 — TCP Connectivity Test
# -----------------------------------------------------------------

class TCPTester:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def test(
        self,
        host:        str,
        port:        int,
        resolved_ip: Optional[str] = None,
    ) -> Tuple[bool, float]:
        connect_host = resolved_ip if resolved_ip else host
        try:
            start = time.perf_counter()
            with socket.create_connection(
                (connect_host, port), timeout=self.timeout
            ):
                end = time.perf_counter()
                return True, (end - start) * 1000
        except Exception:
            return False, -1


# -----------------------------------------------------------------
# Stage 2 — TLS Handshake Test
# -----------------------------------------------------------------

class TLSTester:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def test(
        self,
        host:           str,
        port:           int,
        sni:            str,
        fingerprint:    str                 = "chrome",
        alpn:           Optional[List[str]] = None,
        allow_insecure: bool                = True,
        resolved_ip:    Optional[str]       = None,
    ) -> Tuple[bool, float, Dict]:
        TLSProber = _get_tls_prober()
        prober    = TLSProber(timeout=self.timeout)

        result = prober.probe(
            host           = host,
            port           = port,
            sni            = sni,
            fingerprint    = fingerprint,
            alpn           = alpn,
            allow_insecure = allow_insecure,
            resolved_ip    = resolved_ip,
        )

        info = {
            "tls_version":     result.tls_version,
            "cert_cn":         result.cert_cn,
            "cert_issuer":     result.cert_issuer,
            "cert_expiry":     result.cert_expiry,
            "alpn_negotiated": result.alpn_negotiated,
            "ip_resolved":     result.ip_resolved,
            "latency_ms":      result.latency_ms,
        }

        return result.tls_ok, result.latency_ms, info


# -----------------------------------------------------------------
# Stage 3 — HTTP Probe Test
# -----------------------------------------------------------------

class HTTPTester:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def test(
        self,
        host:        str,
        port:        int,
        sni:         str,
        path:        str           = "/",
        host_header: Optional[str] = None,
        use_tls:     bool          = True,
        resolved_ip: Optional[str] = None,
    ) -> Tuple[bool, int, float]:
        """
        Returns: (success, http_status_code, latency_ms)
        """
        connect_host = resolved_ip if resolved_ip else host
        h_header     = host_header if host_header else host

        try:
            start = time.perf_counter()

            raw_sock = socket.create_connection(
                (connect_host, port), timeout=self.timeout
            )

            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                except AttributeError:
                    pass
                sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
            else:
                sock = raw_sock

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {h_header}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/120.0.0.0 Safari/537.36\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )

            sock.sendall(request.encode())
            sock.settimeout(self.timeout)

            response = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break

            end     = time.perf_counter()
            latency = (end - start) * 1000

            sock.close()

            if response:
                first_line = response.split(b"\r\n")[0].decode(errors="ignore")
                parts      = first_line.split(" ")
                if len(parts) >= 2:
                    status = int(parts[1])
                    return True, status, latency

            return False, -1, latency

        except Exception:
            return False, -1, -1


# -----------------------------------------------------------------
# Stage 4 — DNS Resolver Stage
# -----------------------------------------------------------------

class DNSStage:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def resolve(self, host: str) -> Optional[str]:
        """
        Resolve host to IP.
        Returns IP string or None if failed.
        """
        DNSResolver = _get_dns_resolver()
        resolver    = DNSResolver(use_iran_dns=False)
        return resolver.resolve(host)


# -----------------------------------------------------------------
# Config Rebuilder — rebuild config link with new SNI
# -----------------------------------------------------------------

class ConfigRebuilder:
    @staticmethod
    def rebuild(parsed_config: ParsedConfig, new_sni: str) -> str:
        """
        Rebuild the raw config link with a new SNI value.
        Returns the new raw config string.
        """
        try:
            from parser import rebuild_config
            return rebuild_config(parsed_config, new_sni=new_sni)
        except Exception:
            return parsed_config.raw or ""

    @staticmethod
    def apply_sni(parsed_config: ParsedConfig, new_sni: str) -> ParsedConfig:
        """
        Return a copy of parsed_config with sni replaced.
        """
        import copy
        cfg     = copy.deepcopy(parsed_config)
        cfg.sni = new_sni
        if cfg.host_header:
            pass  # keep host_header as-is (CDN mode)
        return cfg


# -----------------------------------------------------------------
# ConfigTester — main single-config tester
# -----------------------------------------------------------------

class ConfigTester:
    def __init__(
        self,
        timeout:    int  = 6,
        test_proxy: bool = False,
    ):
        self.timeout    = timeout
        self.test_proxy = test_proxy

        self._tcp_tester  = TCPTester(timeout=timeout)
        self._tls_tester  = TLSTester(timeout=timeout)
        self._http_tester = HTTPTester(timeout=timeout)
        self._dns_stage   = DNSStage(timeout=timeout)
        self._scorer      = ConfigScoreCalculator()

    # ----------------------------------------------------------
    def test(self, parsed_config: ParsedConfig) -> ConfigTestResult:
        """
        Run full test pipeline on a single parsed config.
        Stages: DNS → TCP → TLS → HTTP
        Returns a ConfigTestResult.
        """
        from parser import rebuild_config

        result              = ConfigTestResult(config=parsed_config)
        result.config_type  = detect_config_type(parsed_config)
        result.original_sni = parsed_config.sni or ""
        result.sni          = parsed_config.sni or ""

        start_time = time.perf_counter()

        host = parsed_config.host or ""
        port = parsed_config.port or 443
        sni  = parsed_config.sni  or host

        # ── Stage 0: DNS ──────────────────────────────────────
        resolved_ip = self._dns_stage.resolve(host)
        result.ip_resolved          = resolved_ip or ""
        result.test_stages["dns"]   = "PASS" if resolved_ip else "FAIL"

        # ── Stage 1: TCP ──────────────────────────────────────
        tcp_ok, tcp_lat = self._tcp_tester.test(
            host        = host,
            port        = port,
            resolved_ip = resolved_ip,
        )
        result.tcp_reachable        = tcp_ok
        result.tcp_latency_ms       = tcp_lat
        result.test_stages["tcp"]   = "PASS" if tcp_ok else "FAIL"

        if not tcp_ok:
            result.error            = "TCP connection failed"
            result.test_stages["tls"]  = "SKIP"
            result.test_stages["http"] = "SKIP"
            result.score = self._scorer.calculate(result)
            result.test_duration_ms = (time.perf_counter() - start_time) * 1000
            return result

        # ── Stage 2: TLS ──────────────────────────────────────
        needs_tls = _needs_tls(parsed_config)

        if needs_tls:
            tls_ok, tls_lat, tls_info = self._tls_tester.test(
                host           = host,
                port           = port,
                sni            = sni,
                resolved_ip    = resolved_ip,
                allow_insecure = True,
            )
            result.tls_ok           = tls_ok
            result.tls_latency_ms   = tls_lat
            result.tls_version      = tls_info.get("tls_version",     "")
            result.cert_cn          = tls_info.get("cert_cn",          "")
            result.cert_issuer      = tls_info.get("cert_issuer",      "")
            result.cert_expiry      = tls_info.get("cert_expiry",      "")
            result.alpn_negotiated  = tls_info.get("alpn_negotiated",  "")
            result.ip_resolved      = tls_info.get("ip_resolved", "") or result.ip_resolved
            result.test_stages["tls"] = "PASS" if tls_ok else "FAIL"

            if not tls_ok:
                result.warnings.append("TLS handshake failed — server may still work")
        else:
            result.test_stages["tls"] = "SKIP"

        # ── Stage 3: HTTP ─────────────────────────────────────
        use_tls     = needs_tls
        host_header = parsed_config.host_header or host

        http_ok, http_status, http_lat = self._http_tester.test(
            host        = host,
            port        = port,
            sni         = sni,
            host_header = host_header,
            use_tls     = use_tls,
            resolved_ip = resolved_ip,
        )

        result.http_ok          = http_ok
        result.http_status      = http_status
        result.http_latency_ms  = http_lat
        result.test_stages["http"] = "PASS" if http_ok else "FAIL"

        # ── Final: proxy_ok & overall_ok ──────────────────────
        result.proxy_ok   = is_proxy_ok(http_status, result.config_type)
        result.overall_ok = result.tcp_reachable and (
            result.proxy_ok or is_alive(http_status)
        )

        # ── Warnings ──────────────────────────────────────────
        if result.tcp_latency_ms > 800:
            result.warnings.append(
                f"High latency: {result.tcp_latency_ms:.0f}ms"
            )

        if result.tls_version == "TLSv1.2":
            result.warnings.append("TLS 1.2 detected — TLS 1.3 preferred")

        if not result.cert_cn and needs_tls:
            result.warnings.append("Could not retrieve certificate CN")

        # ── Rebuild config ────────────────────────────────────
        try:
            result.rebuilt_config = rebuild_config(parsed_config, new_sni=sni)
        except Exception:
            result.rebuilt_config = parsed_config.raw or ""

        # ── Score ─────────────────────────────────────────────
        result.score            = self._scorer.calculate(result)
        result.test_duration_ms = (time.perf_counter() - start_time) * 1000

        return result


# -----------------------------------------------------------------
# Quick Validator — fast single-stage check (TCP + TLS only)
# -----------------------------------------------------------------

class QuickValidator:
    def __init__(self, timeout: int = 5):
        self.timeout     = timeout
        self._tcp_tester = TCPTester(timeout=timeout)
        self._tls_tester = TLSTester(timeout=timeout)
        self._dns_stage  = DNSStage(timeout=timeout)
        self._scorer     = ConfigScoreCalculator()

    def validate(self, parsed_config: ParsedConfig) -> ConfigTestResult:
        """
        Fast validation — runs DNS + TCP + TLS only.
        Skips HTTP stage for speed.
        Returns a ConfigTestResult.
        """
        result             = ConfigTestResult(config=parsed_config)
        result.config_type = detect_config_type(parsed_config)
        result.sni         = parsed_config.sni or ""
        result.original_sni = parsed_config.sni or ""

        start_time = time.perf_counter()

        host = parsed_config.host or ""
        port = parsed_config.port or 443
        sni  = parsed_config.sni  or host

        # ── DNS ───────────────────────────────────────────────
        resolved_ip = self._dns_stage.resolve(host)
        result.ip_resolved        = resolved_ip or ""
        result.test_stages["dns"] = "PASS" if resolved_ip else "FAIL"

        # ── TCP ───────────────────────────────────────────────
        tcp_ok, tcp_lat = self._tcp_tester.test(
            host        = host,
            port        = port,
            resolved_ip = resolved_ip,
        )
        result.tcp_reachable      = tcp_ok
        result.tcp_latency_ms     = tcp_lat
        result.test_stages["tcp"] = "PASS" if tcp_ok else "FAIL"

        if not tcp_ok:
            result.error              = "TCP connection failed"
            result.test_stages["tls"]  = "SKIP"
            result.test_stages["http"] = "SKIP"
            result.score = self._scorer.calculate(result)
            result.test_duration_ms = (time.perf_counter() - start_time) * 1000
            return result

        # ── TLS ───────────────────────────────────────────────
        needs_tls = _needs_tls(parsed_config)

        if needs_tls:
            tls_ok, tls_lat, tls_info = self._tls_tester.test(
                host           = host,
                port           = port,
                sni            = sni,
                resolved_ip    = resolved_ip,
                allow_insecure = True,
            )
            result.tls_ok          = tls_ok
            result.tls_latency_ms  = tls_lat
            result.tls_version     = tls_info.get("tls_version",    "")
            result.cert_cn         = tls_info.get("cert_cn",         "")
            result.cert_issuer     = tls_info.get("cert_issuer",     "")
            result.alpn_negotiated = tls_info.get("alpn_negotiated", "")
            result.ip_resolved     = tls_info.get("ip_resolved", "") or result.ip_resolved
            result.test_stages["tls"] = "PASS" if tls_ok else "FAIL"
        else:
            result.test_stages["tls"] = "SKIP"

        # ── HTTP skipped ──────────────────────────────────────
        result.test_stages["http"] = "SKIP"

        # ── proxy_ok based on TCP + TLS only ──────────────────
        if needs_tls:
            result.proxy_ok   = result.tls_ok
            result.overall_ok = result.tcp_reachable and result.tls_ok
        else:
            result.proxy_ok   = result.tcp_reachable
            result.overall_ok = result.tcp_reachable

        # ── Warnings ──────────────────────────────────────────
        if result.tcp_latency_ms > 800:
            result.warnings.append(
                f"High latency: {result.tcp_latency_ms:.0f}ms"
            )

        if result.tls_version == "TLSv1.2":
            result.warnings.append("TLS 1.2 detected — TLS 1.3 preferred")

        if not result.cert_cn and needs_tls and result.tls_ok:
            result.warnings.append("Could not retrieve certificate CN")

        # ── Score ─────────────────────────────────────────────
        result.score            = self._scorer.calculate(result)
        result.test_duration_ms = (time.perf_counter() - start_time) * 1000

        return result


# -----------------------------------------------------------------
# SNI Switcher — test config with multiple SNIs
# -----------------------------------------------------------------

class SNISwitcher:
    def __init__(
        self,
        tester:      ConfigTester,
        max_workers: int = 10,
    ):
        self.tester      = tester
        self.max_workers = max_workers

    def run(
        self,
        parsed_config: ParsedConfig,
        sni_list:      List[str],
        on_result:     Optional[callable] = None,
    ) -> List[ConfigTestResult]:
        """
        Test one config against multiple SNIs in parallel.
        Returns list of ConfigTestResult sorted by score descending.
        """
        results = []

        def _test_with_sni(sni: str) -> ConfigTestResult:
            cfg     = ConfigRebuilder.apply_sni(parsed_config, sni)
            result  = self.tester.test(cfg)
            result.sni = sni
            return result

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_map = {
                executor.submit(_test_with_sni, sni): sni
                for sni in sni_list
            }

            for future in concurrent.futures.as_completed(future_map):
                sni = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    result       = ConfigTestResult(config=parsed_config)
                    result.sni   = sni
                    result.error = str(e)

                results.append(result)

                if on_result:
                    on_result(result)

        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def best(
        self,
        parsed_config: ParsedConfig,
        sni_list:      List[str],
    ) -> Optional[ConfigTestResult]:
        """
        Return the best result (highest score) from SNI list.
        """
        results = self.run(parsed_config, sni_list)
        if results and results[0].score > 0:
            return results[0]
        return None


# -----------------------------------------------------------------
# Batch Tester — test multiple configs in parallel
# -----------------------------------------------------------------

class BatchTester:
    def __init__(
        self,
        tester:      ConfigTester,
        max_workers: int = 10,
    ):
        self.tester      = tester
        self.max_workers = max_workers

    def run(
        self,
        configs:   List[ParsedConfig],
        on_result: Optional[callable] = None,
    ) -> List[ConfigTestResult]:
        """
        Run full tests in parallel for a list of configs.
        Returns list of ConfigTestResult sorted by score descending.
        """
        results = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_map = {
                executor.submit(self.tester.test, cfg): cfg
                for cfg in configs
            }

            for future in concurrent.futures.as_completed(future_map):
                cfg = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    result        = ConfigTestResult(config=cfg)
                    result.error  = str(e)

                results.append(result)

                if on_result:
                    on_result(result)

        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def run_quick(
        self,
        configs:   List[ParsedConfig],
        on_result: Optional[callable] = None,
    ) -> List[ConfigTestResult]:
        """
        Run quick validation in parallel for a list of configs.
        Returns list of ConfigTestResult sorted by score descending.
        """
        validator = QuickValidator(timeout=self.tester.timeout)
        results   = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_map = {
                executor.submit(validator.validate, cfg): cfg
                for cfg in configs
            }

            for future in concurrent.futures.as_completed(future_map):
                cfg = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    result       = ConfigTestResult(config=cfg)
                    result.error = str(e)

                results.append(result)

                if on_result:
                    on_result(result)

        results.sort(key=lambda r: r.score, reverse=True)
        return results


# -----------------------------------------------------------------
# Result Formatter — format_result & format_summary
# -----------------------------------------------------------------

_TYPE_LABEL = {
    "cdn_based":     "CDN-Based",
    "direct_server": "Direct Server",
    "plain_http":    "Plain HTTP",
}

_STAGE_ICON = {
    "PASS": "OK  ",
    "FAIL": "FAIL",
    "SKIP": "SKIP",
}


def format_result(result: ConfigTestResult) -> str:
    """
    Format a single ConfigTestResult as plain text.
    """
    cfg   = result.config
    host  = cfg.host if cfg else "unknown"
    port  = cfg.port if cfg else 0

    lines = []

    # Header
    proto = (cfg.protocol.upper() if cfg and cfg.protocol else "UNKNOWN")
    lines.append(f"[{proto}] {host}:{port}")

    if result.sni:
        lines.append(f"  SNI          : {result.sni}")

    lines.append(
        f"  Config Type  : {_TYPE_LABEL.get(result.config_type, result.config_type)}"
    )
    lines.append(f"  Score        : {result.score:.1f}/100")

    # Stages
    lines.append("")
    lines.append("  Stages:")

    for stage in ("dns", "tcp", "tls", "http"):
        status = result.test_stages.get(stage, "---")
        icon   = _STAGE_ICON.get(status, status)
        extra  = ""

        if stage == "tcp" and result.tcp_latency_ms > 0:
            extra = f"  {result.tcp_latency_ms:.1f}ms"
        elif stage == "tls" and result.tls_latency_ms > 0:
            extra = f"  {result.tls_latency_ms:.1f}ms  {result.tls_version}  ALPN={result.alpn_negotiated}"
        elif stage == "http" and result.http_status > 0:
            extra = f"  HTTP {result.http_status}"

        lines.append(f"    {stage.upper():<6} [{icon}]{extra}")

    # Details
    lines.append("")
    if result.cert_cn:
        lines.append(f"  Cert CN      : {result.cert_cn}")
    if result.cert_issuer:
        lines.append(f"  Cert Issuer  : {result.cert_issuer}")
    if result.ip_resolved:
        lines.append(f"  IP Resolved  : {result.ip_resolved}")
    if result.proxy_ok:
        lines.append(f"  Proxy        : OK")
    if result.overall_ok:
        lines.append(f"  Overall      : PASS")
    else:
        lines.append(f"  Overall      : FAIL")

    lines.append(f"  Duration     : {result.test_duration_ms:.0f}ms")

    # Warnings
    if result.warnings:
        lines.append("")
        lines.append("  Warnings:")
        for w in result.warnings:
            lines.append(f"    ! {w}")

    # Error
    if result.error:
        lines.append("")
        lines.append(f"  Error        : {result.error}")

    lines.append("-" * 55)
    return "\n".join(lines)


def format_summary(results: List[ConfigTestResult]) -> str:
    """
    Format a summary of all ConfigTestResult objects as plain text.
    """
    if not results:
        return "No results to display."

    lines = []
    lines.append("=" * 55)
    lines.append(f"  Test Summary  —  {len(results)} config(s)")
    lines.append("=" * 55)

    for i, r in enumerate(results, 1):
        lines.append(f"\n#{i}")
        lines.append(format_result(r))

    # Stats
    total      = len(results)
    tcp_ok     = sum(1 for r in results if r.tcp_reachable)
    tls_ok     = sum(1 for r in results if r.tls_ok)
    proxy_ok   = sum(1 for r in results if r.proxy_ok)
    overall_ok = sum(1 for r in results if r.overall_ok)
    avg_score  = sum(r.score for r in results) / total
    avg_lat    = sum(
        r.tcp_latency_ms for r in results if r.tcp_latency_ms > 0
    )
    lat_count  = sum(1 for r in results if r.tcp_latency_ms > 0)
    avg_lat    = avg_lat / lat_count if lat_count else 0

    lines.append("")
    lines.append("=" * 55)
    lines.append("  STATISTICS")
    lines.append("=" * 55)
    lines.append(f"  Total Configs  : {total}")
    lines.append(f"  TCP OK         : {tcp_ok}/{total}")
    lines.append(f"  TLS OK         : {tls_ok}/{total}")
    lines.append(f"  Proxy OK       : {proxy_ok}/{total}")
    lines.append(f"  Overall OK     : {overall_ok}/{total}")
    lines.append(f"  Avg Score      : {avg_score:.1f}/100")
    lines.append(f"  Avg Latency    : {avg_lat:.1f}ms")

    # Best result
    if results:
        best = results[0]
        cfg  = best.config
        lines.append("")
        lines.append("  Best Config:")
        if cfg:
            lines.append(f"    {cfg.host}:{cfg.port}  SNI={best.sni}")
        lines.append(f"    Score={best.score:.1f}  Latency={best.tcp_latency_ms:.1f}ms")

    lines.append("=" * 55)
    return "\n".join(lines)


# -----------------------------------------------------------------
# __all__ — public API
# -----------------------------------------------------------------

__all__ = [
    # Data
    "ConfigTestResult",

    # Helpers
    "detect_config_type",
    "is_proxy_ok",
    "is_alive",

    # Testers
    "TCPTester",
    "TLSTester",
    "HTTPTester",
    "DNSStage",
    "ConfigRebuilder",
    "ConfigScoreCalculator",

    # Main classes
    "ConfigTester",
    "QuickValidator",
    "SNISwitcher",
    "BatchTester",

    # Formatters
    "format_result",
    "format_summary",
]