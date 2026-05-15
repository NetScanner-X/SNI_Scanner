# ============================================================
# sni_scanner.py  — SNI Scanner Core  (v9-fixed)
# SNIResult · DualModeSNIResult · DNSResolver · CertParser
# TLSProber · HTTPReachChecker · ProxyPathVerifier
# SNIScanner · BatchSNIScanner · EnhancedSNIScanner
# DualModeSNIScanner · SNIListLoader · SNIAutoCollector
# ============================================================
from __future__ import annotations

import csv, io, json, socket, ssl, time, logging, os, hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SNIWordlist = List[str]
logger = logging.getLogger(__name__)

# ─────────────────────────── Persistent Scan Cache ───────────────────────────
class ScanCache:
    """Tiny JSON cache for repeated DNS/probe results.

    The cache is conservative: keys include domain/IP/port/security/transport/host/path
    so old results do not leak between different config types. It only avoids repeating
    identical probes for a short TTL and can be disabled from Settings.
    """
    def __init__(self, enabled: bool = True, ttl_seconds: int = 900):
        self.enabled = bool(enabled)
        self.ttl_seconds = max(30, int(ttl_seconds or 900))
        base = os.path.dirname(os.path.abspath(__file__))
        self.path = os.path.join(base, "data", "cache", "scan_cache.json")
        self._data = {}
        if self.enabled:
            self._load()

    def _load(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self._data = json.load(f) if f else {}
        except Exception:
            self._data = {}

    def _save(self):
        if not self.enabled:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            # keep file small
            now = time.time()
            self._data = {k:v for k,v in self._data.items() if now - float(v.get("ts", 0)) <= self.ttl_seconds}
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def key(self, *parts) -> str:
        raw = "|".join(str(x or "") for x in parts)
        return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()

    def get(self, key):
        if not self.enabled:
            return None
        item = self._data.get(key)
        if not item:
            return None
        if time.time() - float(item.get("ts", 0)) > self.ttl_seconds:
            self._data.pop(key, None)
            return None
        return item.get("value")

    def set(self, key, value):
        if not self.enabled:
            return
        self._data[key] = {"ts": time.time(), "value": value}
        # save opportunistically; small JSON file only
        self._save()

DEFAULT_TIMEOUT     = 5.0
DEFAULT_MAX_WORKERS = 50
DEFAULT_RETRY_COUNT = 2
DEFAULT_MAX_LATENCY = 3000.0
DEFAULT_SORT_BY     = "latency"

IRAN_DNS_SERVERS  = ["178.22.122.100","185.51.200.2","10.202.10.202","10.202.10.10"]
CLEAN_DNS_SERVERS = ["8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1"]

CDN_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "103.21.244.","103.22.200.","103.31.4.",
        "104.16.","104.17.","104.18.","104.19.","104.20.","104.21.","104.22.",
        "108.162.","131.0.72.","141.101.",
        "162.158.","172.64.","172.65.","172.66.","172.67.",
        "173.245.","188.114.","190.93.","197.234.","198.41.",
    ],
    "Fastly":     ["151.101.","199.232.","23.235.","23.236.","103.244.","185.31."],
    "Akamai":     ["23.0.","23.1.","23.2.","23.3.","23.4.","63.218.","2.16.","95.100."],
    "CloudFront": ["13.32.","13.33.","13.35.","52.84.","52.85.",
                   "54.192.","54.230.","64.252.","65.8.","65.9.",
                   "99.84.","205.251.","216.137."],
    "Vercel":     ["76.76.21.", "66.33.60.", "64.239.", "216.198."],
    "Google":     ["142.250.","172.217.","173.194.","209.85.",
                   "216.58.","216.239.","8.8."],
}

def detect_cdn_provider(ip: str) -> str:
    for provider, prefixes in CDN_RANGES.items():
        if any(ip.startswith(p) for p in prefixes):
            return provider
    return ""

# ─────────────────────────── SNIResult ───────────────────────────
@dataclass
class SNIResult:
    domain: str = ""
    ip: str = ""
    port: int = 443
    sni: str = ""
    tcp_ok: bool = False
    tls_ok: bool = False
    latency_ms: float = -1.0
    cert_cn: str = ""
    cert_san: List[str] = field(default_factory=list)
    cert_issuer: str = ""
    cert_expiry: str = ""
    alpn_negotiated: str = ""
    ip_resolved: str = ""
    error: str = ""
    score: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)
    tls_version: str = ""
    cipher: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain, "ip": self.ip, "port": self.port,
            "sni": self.sni, "tcp_ok": self.tcp_ok, "tls_ok": self.tls_ok,
            "latency_ms": round(self.latency_ms, 2), "cert_cn": self.cert_cn,
            "cert_san": self.cert_san, "cert_issuer": self.cert_issuer,
            "cert_expiry": self.cert_expiry, "alpn_negotiated": self.alpn_negotiated,
            "ip_resolved": self.ip_resolved, "error": self.error,
            "score": self.score, "extra": self.extra,
            "tls_version": self.tls_version, "cipher": self.cipher,
        }

    @property
    def ok(self) -> bool:
        return self.tcp_ok and self.tls_ok


# ─────────────────────────── DualModeSNIResult ───────────────────
@dataclass
class DualModeSNIResult:
    """
    One domain scanned in two independent modes:
    A — connect via config server IP  (CDN relay mode)
    B — connect via domain's own IP   (direct mode)
    """
    domain: str = ""
    port: int = 443

    # Mode A — config server IP
    mode_a_ip: str = ""
    mode_a_tls_ok: bool = False
    mode_a_tls_version: str = ""
    mode_a_latency_ms: float = -1.0
    mode_a_cert_cn: str = ""
    mode_a_http_ok: bool = False
    mode_a_path_ok: Optional[bool] = None
    mode_a_path_detail: str = ""
    mode_a_error: str = ""

    # Mode B — domain's own IP
    mode_b_ip: str = ""
    mode_b_tls_ok: bool = False
    mode_b_tls_version: str = ""
    mode_b_latency_ms: float = -1.0
    mode_b_cert_cn: str = ""
    mode_b_http_ok: bool = False
    mode_b_path_ok: Optional[bool] = None
    mode_b_path_detail: str = ""
    mode_b_error: str = ""

    # Mode C — other DNS IPs / alternative edge IPs for this SNI
    mode_c_ip: str = ""
    mode_c_tls_ok: bool = False
    mode_c_tls_version: str = ""
    mode_c_latency_ms: float = -1.0
    mode_c_cert_cn: str = ""
    mode_c_http_ok: bool = False
    mode_c_path_ok: Optional[bool] = None
    mode_c_path_detail: str = ""
    mode_c_error: str = ""

    cdn_provider: str = ""
    score: float = 0.0

    # ── Properties ───────────────────────────────────────────────
    @property
    def best_latency(self) -> float:
        lats = [x for x in [self.mode_a_latency_ms, self.mode_b_latency_ms, self.mode_c_latency_ms] if x and x > 0]
        return min(lats) if lats else 9999.0

    @property
    def a_pass(self) -> bool:
        # Mode A can be useful for TLS configs that really validate the Host/path,
        # but it is not a reliable final pass for non-TLS front-domain scans.
        if self.mode_a_path_ok is True:
            return True
        if self.mode_a_path_ok is None and self.mode_a_tls_ok:
            return True
        return False

    @property
    def b_pass(self) -> bool:
        if self.mode_b_path_ok is True:
            return True
        if self.mode_b_path_ok is None and self.mode_b_tls_ok:
            return True
        return False

    @property
    def c_pass(self) -> bool:
        if self.mode_c_path_ok is True:
            return True
        if self.mode_c_path_ok is None and self.mode_c_tls_ok:
            return True
        return False

    @property
    def any_pass(self) -> bool:
        return self.a_pass or self.b_pass or self.c_pass

    @property
    def reliable_pass(self) -> bool:
        # The user-facing CDN scanner treats B/C as real candidate passes.
        # A-only is often a false positive because it checks the config address/IP,
        # not the candidate domain's own route.
        return self.b_pass or self.c_pass

    @property
    def best_mode(self) -> str:
        # Prefer real candidate modes first. A is shown only when it is accompanied
        # by B/C or when it has an explicit path-level proof.
        passed = []
        if self.b_pass: passed.append("B")
        if self.c_pass: passed.append("C")
        if self.a_pass and (passed or self.mode_a_path_ok is True):
            passed.insert(0, "A")
        return "+".join(passed) if passed else "none"

    def to_sni_result(self) -> SNIResult:
        r = SNIResult(domain=self.domain, sni=self.domain, port=self.port)
        # Prefer B/C in the visible best fields because they validate the candidate
        # against its own DNS/edge. A-only is kept in its column but not promoted.
        if self.b_pass:
            r.ip = self.mode_b_ip
            r.tls_ok = self.mode_b_tls_ok
            r.tls_version = self.mode_b_tls_version
            r.latency_ms = self.mode_b_latency_ms
            r.cert_cn = self.mode_b_cert_cn
        elif self.c_pass:
            r.ip = self.mode_c_ip
            r.tls_ok = self.mode_c_tls_ok
            r.tls_version = self.mode_c_tls_version
            r.latency_ms = self.mode_c_latency_ms
            r.cert_cn = self.mode_c_cert_cn
        elif self.a_pass and self.mode_a_path_ok is True:
            r.ip = self.mode_a_ip
            r.tls_ok = self.mode_a_tls_ok
            r.tls_version = self.mode_a_tls_version
            r.latency_ms = self.mode_a_latency_ms
            r.cert_cn = self.mode_a_cert_cn
        else:
            r.ip = self.mode_c_ip or self.mode_b_ip or self.mode_a_ip
            r.tls_ok = self.mode_c_tls_ok or self.mode_b_tls_ok or self.mode_a_tls_ok
            r.tls_version = self.mode_c_tls_version or self.mode_b_tls_version or self.mode_a_tls_version
            r.latency_ms = self.mode_c_latency_ms if self.mode_c_latency_ms > 0 else (self.mode_b_latency_ms if self.mode_b_latency_ms > 0 else self.mode_a_latency_ms)
            r.cert_cn = self.mode_c_cert_cn or self.mode_b_cert_cn or self.mode_a_cert_cn
        r.score = int(self.score)
        r.extra = {
            "mode_a_tls":     self.mode_a_tls_ok,
            "mode_b_tls":     self.mode_b_tls_ok,
            "mode_a_path_ok": self.mode_a_path_ok,
            "mode_b_path_ok": self.mode_b_path_ok,
            "mode_c_tls":     self.mode_c_tls_ok,
            "mode_c_path_ok": self.mode_c_path_ok,
            "mode_a_ip":      self.mode_a_ip,
            "mode_b_ip":      self.mode_b_ip,
            "mode_c_ip":      self.mode_c_ip,
            "mode_a_tls_version": self.mode_a_tls_version,
            "mode_b_tls_version": self.mode_b_tls_version,
            "mode_c_tls_version": self.mode_c_tls_version,
            "mode_a_latency": self.mode_a_latency_ms,
            "mode_b_latency": self.mode_b_latency_ms,
            "mode_c_latency": self.mode_c_latency_ms,
            "cdn_provider":   self.cdn_provider,
            "best_mode":      self.best_mode,
            "reliable_pass":  self.reliable_pass,
            "mode_a_real_ok": (self.mode_a_path_ok is True),
            "mode_b_real_ok": (self.mode_b_path_ok is True or self.b_pass),
            "mode_c_real_ok": (self.mode_c_path_ok is True or self.c_pass),
            "proxy_path_ok":  (self.mode_b_path_ok or self.mode_c_path_ok or (self.mode_a_path_ok if self.reliable_pass else False)),
            "http_ok":        (self.mode_a_http_ok or self.mode_b_http_ok or self.mode_c_http_ok),
        }
        return r


# ─────────────────────────── DNSResolver ─────────────────────────
class DNSResolver:
    def __init__(self, use_iran_dns: bool = False, timeout: float = 3.0):
        self.timeout = timeout
        self._servers = IRAN_DNS_SERVERS if use_iran_dns else CLEAN_DNS_SERVERS

    def resolve(self, domain: str) -> Optional[str]:
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.strip()):
            return domain.strip()
        for _ in self._servers:
            try:
                old = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.timeout)
                try:
                    return socket.gethostbyname(domain)
                finally:
                    socket.setdefaulttimeout(old)
            except (socket.gaierror, socket.timeout):
                continue
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def resolve_all(self, domain: str) -> List[str]:
        try:
            seen: List[str] = []
            for r in socket.getaddrinfo(domain, None):
                ip = r[4][0]
                if ip not in seen:
                    seen.append(ip)
            return seen
        except Exception:
            s = self.resolve(domain)
            return [s] if s else []


# ─────────────────────────── CertParser ──────────────────────────
class CertParser:
    @staticmethod
    def parse(cert: Dict[str, Any]) -> Tuple[str, List[str], str, str]:
        cn     = CertParser._cn(cert)
        san    = CertParser._san(cert)
        issuer = CertParser._issuer(cert)
        expiry = cert.get("notAfter", "")
        return cn, san, issuer, expiry

    @staticmethod
    def _cn(cert):
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                if k == "commonName": return v
        return ""

    @staticmethod
    def _san(cert):
        return [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"]

    @staticmethod
    def _issuer(cert):
        for rdn in cert.get("issuer", ()):
            for k, v in rdn:
                if k == "organizationName": return v
        return ""


# ─────────────────────────── TLSProber ───────────────────────────
class TLSProber:
    def __init__(self, timeout=DEFAULT_TIMEOUT, retry=DEFAULT_RETRY_COUNT,
                 verify_cert=False):
        self.timeout = timeout
        self.retry = retry
        self.verify_cert = verify_cert

    def probe(self, domain="", ip="", port=443, sni=None,
              host="", fingerprint="chrome", alpn=None,
              allow_insecure=True, resolved_ip=None) -> SNIResult:
        if host and not domain: domain = host
        if resolved_ip and not ip: ip = resolved_ip
        if not ip:
            ip = DNSResolver().resolve(domain) or domain
        sni = sni or domain
        result = SNIResult(domain=domain, ip=ip, port=port, sni=sni)
        for attempt in range(max(1, self.retry)):
            tcp_ok, tcp_lat, tcp_err = self._tcp(ip, port)
            if not tcp_ok:
                result.error = tcp_err
                if attempt < self.retry - 1: time.sleep(0.3); continue
                return result
            result.tcp_ok = True
            (tls_ok, tls_lat, tls_err, cn, san, tls_ver, cipher,
             issuer, expiry, alpn_neg) = self._tls(ip, port, sni,
                                                    allow_insecure=allow_insecure,
                                                    alpn_protocols=alpn)
            result.tls_ok = tls_ok
            result.latency_ms = tls_lat if tls_ok else tcp_lat
            result.cert_cn = cn; result.cert_san = san
            result.tls_version = tls_ver; result.cipher = cipher
            result.cert_issuer = issuer; result.cert_expiry = expiry
            result.alpn_negotiated = alpn_neg; result.ip_resolved = ip
            security_ok, security_note = self._security_assessment(tls_ver, cipher, expiry)
            result.extra.update({"alpn": alpn_neg, "tls_version": tls_ver,
                                  "cert_cn": cn, "ip_resolved": ip,
                                  "attempts": attempt + 1,
                                  "security_ok": security_ok,
                                  "security_note": security_note})
            if tls_ok:
                result.error = ""; result.score = self._score(result)
                return result
            result.error = tls_err
            if attempt < self.retry - 1: time.sleep(0.3); continue
        return result

    def _tcp(self, ip, port) -> Tuple[bool, float, str]:
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((ip, port), timeout=self.timeout)
            lat = (time.perf_counter() - t0) * 1000; s.close()
            return True, lat, ""
        except socket.timeout: return False, -1.0, "TCP timeout"
        except ConnectionRefusedError: return False, -1.0, "TCP connection refused"
        except OSError as e: return False, -1.0, f"TCP error: {e}"
        except Exception as e: return False, -1.0, f"Unexpected TCP error: {e}"

    def _tls(self, ip, port, sni, allow_insecure=True, alpn_protocols=None):
        ctx = ssl.create_default_context()
        if allow_insecure or not self.verify_cert:
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(alpn_protocols or ["h2", "http/1.1"])
        except Exception:
            pass
        t0 = time.perf_counter()
        try:
            raw = socket.create_connection((ip, port), timeout=self.timeout)
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            lat = (time.perf_counter() - t0) * 1000
            cert = tls.getpeercert()
            tls_ver = tls.version() or ""
            cipher_info = tls.cipher()
            cipher = cipher_info[0] if cipher_info else ""
            alpn = tls.selected_alpn_protocol() or ""
            tls.close()
            cn, san, issuer, expiry = CertParser.parse(cert) if cert else ("", [], "", "")
            return (True, lat, "", cn, san, tls_ver, cipher, issuer, expiry, alpn)
        except ssl.SSLCertVerificationError as e:
            return (False, -1.0, f"Cert verify error: {e}", "", [], "", "", "", "", "")
        except ssl.SSLError as e:
            return (False, -1.0, f"TLS error: {e}", "", [], "", "", "", "", "")
        except socket.timeout:
            return (False, -1.0, "TLS timeout", "", [], "", "", "", "", "")
        except OSError as e:
            return (False, -1.0, f"Socket error: {e}", "", [], "", "", "", "", "")
        except Exception as e:
            return (False, -1.0, f"Unexpected TLS error: {e}", "", [], "", "", "", "", "")

    def _security_assessment(self, tls_ver: str, cipher: str, expiry: str) -> Tuple[bool, str]:
        """Lightweight TLS security check for user guidance.

        It does not block a result by itself; it adds a clear note so users can
        prefer modern TLS/ciphers and avoid expired certificates.
        """
        notes = []
        ok = True
        tv = (tls_ver or "").upper()
        cf = (cipher or "").upper()
        if tv in ("TLSV1.3", "TLSV1.2"):
            notes.append(tv.replace("TLSV", "TLSv"))
        elif tv:
            ok = False; notes.append(f"legacy {tls_ver}")
        else:
            ok = False; notes.append("no TLS version")
        if any(x in cf for x in ("RC4", "3DES", "DES", "MD5", "NULL")):
            ok = False; notes.append("weak cipher")
        if expiry:
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
                try:
                    exp = datetime.strptime(expiry, fmt)
                    days = (exp - datetime.utcnow()).days
                    if days < 0:
                        ok = False; notes.append("expired cert")
                    elif days < 14:
                        notes.append(f"cert expires in {days}d")
                    break
                except Exception:
                    continue
        return ok, ", ".join(notes) if notes else "OK"

    def _score(self, r: SNIResult) -> int:
        s = 0
        if r.tls_ok: s += 50
        if 0 < r.latency_ms < 200: s += 30
        elif 0 < r.latency_ms < 500: s += 15
        if r.cert_cn: s += 10
        if r.cert_san: s += 10
        if r.extra.get("security_ok") is False: s = max(0, s - 15)
        return min(s, 100)


# ─────────────────────────── HTTPReachChecker ────────────────────
class HTTPReachChecker:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def check(self, ip, port, sni, host_header="", path="/") -> Tuple[bool, int, float]:
        host_hdr = host_header or sni
        req = (f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
               f"User-Agent: Mozilla/5.0 (SNIScanner/2.0)\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_alpn_protocols(["http/1.1"])
        except Exception: pass
        t0 = time.perf_counter()
        try:
            raw = socket.create_connection((ip, port), timeout=self.timeout)
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            tls.sendall(req.encode())
            response = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk: break
                response += chunk
                if b"\r\n\r\n" in response or len(response) > 8192: break
            tls.close()
            lat = (time.perf_counter() - t0) * 1000
            first = response.split(b"\r\n")[0].decode(errors="ignore")
            parts = first.split(" ", 2)
            status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            return (status > 0), status, lat
        except Exception:
            return False, 0, -1.0


# ─────────────────────────── ProxyPathVerifier ───────────────────
class ProxyPathVerifier:
    REACHABLE = {101, 200, 201, 204, 206, 301, 302, 307, 308, 400, 403, 426}
    CF_ERRORS  = {521, 522, 523, 524, 525, 526, 530}

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def verify(self, ip, port, sni, host_header, path="/", transport="xhttp", secure=True):
        return self._check_http(ip, port, sni, host_header, path, transport, secure=secure)

    def _check_http(self, ip, port, sni, host_header, path, transport, secure=True):
        ctx = None
        if secure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            alpn = ["h2"] if transport == "h2" else ["http/1.1"]
            try: ctx.set_alpn_protocols(alpn)
            except Exception: pass
        if transport == "ws":
            req = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                   f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                   f"Sec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
        else:
            req = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                   f"User-Agent: Mozilla/5.0 (SNIScanner/2.0)\r\n"
                   f"Accept: */*\r\nConnection: close\r\n\r\n")
        t0 = time.perf_counter()
        try:
            raw = socket.create_connection((ip, port), timeout=self.timeout)
            sock = ctx.wrap_socket(raw, server_hostname=sni) if secure else raw
            sock.sendall(req.encode())
            response = b""; deadline = time.perf_counter() + self.timeout
            while time.perf_counter() < deadline:
                try:
                    sock.settimeout(1.0); chunk = sock.recv(4096)
                    if not chunk: break
                    response += chunk
                    if b"\r\n\r\n" in response or len(response) > 8192: break
                except socket.timeout: break
            sock.close()
            lat = (time.perf_counter() - t0) * 1000
            first = response.split(b"\r\n")[0].decode(errors="ignore").strip()
            parts = first.split(" ", 2)
            status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            if status in self.CF_ERRORS:
                return False, status, lat, f"CDN error {status}"
            if status in self.REACHABLE:
                return True, status, lat, f"HTTP {status}"
            if status > 0:
                return False, status, lat, f"HTTP {status} (unexpected)"
            return False, 0, -1.0, f"No HTTP response"
        except socket.timeout: return False, 0, -1.0, "timeout"
        except ConnectionRefusedError: return False, 0, -1.0, "connection refused"
        except Exception as e: return False, 0, -1.0, f"error: {e}"


# ─────────────────────────── SNIScanner ──────────────────────────
class SNIScanner:
    def __init__(self, parsed_config, timeout=DEFAULT_TIMEOUT,
                 max_workers=DEFAULT_MAX_WORKERS, retry=DEFAULT_RETRY_COUNT,
                 verify_cert=False, use_iran_dns=False):
        self.parsed_config = parsed_config
        self.timeout = timeout; self.max_workers = max_workers
        self._resolver = DNSResolver(use_iran_dns=use_iran_dns, timeout=timeout)
        self._prober   = TLSProber(timeout=timeout, retry=retry, verify_cert=verify_cert)

    def scan(self, domains: List[str], port: int = 443, on_result=None) -> List[SNIResult]:
        if not domains: return []
        results: List[SNIResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            fmap = {ex.submit(self._scan_one, d, port): d for d in domains}
            for f in as_completed(fmap):
                try:
                    r = f.result()
                except Exception as e:
                    r = SNIResult(domain=fmap[f], sni=fmap[f], error=str(e))
                results.append(r)
                if on_result:
                    try:
                        on_result(r)
                    except Exception:
                        pass
        return results

    def scan_one(self, domain, port=443) -> SNIResult:
        return self._scan_one(domain, port)

    def _scan_one(self, domain, port) -> SNIResult:
        cfg = self.parsed_config
        is_cdn = False; config_ip: Optional[str] = None
        if cfg:
            cfg_host = (cfg.host or "").strip()
            cfg_sni  = (cfg.sni  or "").strip()
            host_hdr = (cfg.host_header or "").strip()
            if host_hdr and host_hdr != cfg_host and host_hdr != cfg_sni:
                is_cdn = True
            if cfg_host:
                config_ip = self._resolver.resolve(cfg_host)
        if is_cdn and config_ip:
            ip = config_ip
        else:
            ip = self._resolver.resolve(domain)
            if not ip:
                ip = config_ip or (cfg.host if cfg else None)
                if not ip:
                    return SNIResult(domain=domain, sni=domain, port=port,
                                     error="DNS resolution failed")
        result = self._prober.probe(domain=domain, ip=ip, port=port, sni=domain)
        result.extra["scan_mode"] = "cdn" if is_cdn else "direct"
        result.extra["config_ip"] = config_ip or ""
        return result


# ─────────────────────────── BatchSNIScanner ─────────────────────
class BatchSNIScanner:
    def __init__(self, parsed_config, timeout=DEFAULT_TIMEOUT,
                 max_workers=DEFAULT_MAX_WORKERS, retry=DEFAULT_RETRY_COUNT,
                 verify_cert=False, use_iran_dns=False):
        self._scanner = SNIScanner(parsed_config=parsed_config, timeout=timeout,
                                    max_workers=max_workers, retry=retry,
                                    verify_cert=verify_cert, use_iran_dns=use_iran_dns)
        self.max_workers = max_workers

    def run(self, domains, port=443, on_result=None, stop_on_first=False):
        if not domains: return []
        results: List[SNIResult] = []; stop_flag = [False]
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            fmap = {ex.submit(self._scanner._scan_one, d, port): d for d in domains}
            for f in as_completed(fmap):
                if stop_flag[0]: f.cancel(); continue
                try: r = f.result()
                except Exception as e:
                    r = SNIResult(domain=fmap[f], sni=fmap[f], error=str(e))
                results.append(r)
                if on_result:
                    try: on_result(r)
                    except Exception: pass
                if stop_on_first and r.tls_ok: stop_flag[0] = True
        return results


# ─────────────────────────── EnhancedSNIScanner ──────────────────
def score_sni_result_v2(result: SNIResult, transport: str = "") -> int:
    s = 0
    if not result.tcp_ok: return 0
    if result.tls_ok: s += 40
    lat = result.latency_ms
    if 0 < lat < 150: s += 30
    elif 0 < lat < 300: s += 20
    elif 0 < lat < 600: s += 10
    http_ok  = result.extra.get("http_ok", False)
    http_st  = result.extra.get("http_status", 0)
    path_ok  = result.extra.get("proxy_path_ok", False)
    if path_ok: s += 25
    elif http_ok and http_st in (200, 101, 204): s += 15
    elif http_ok and http_st in (301, 302, 400, 403): s += 5
    if result.cert_cn: s += 5
    return min(s, 100)


class EnhancedSNIScanner(SNIScanner):
    def __init__(self, parsed_config, timeout=DEFAULT_TIMEOUT,
                 max_workers=DEFAULT_MAX_WORKERS, retry=DEFAULT_RETRY_COUNT,
                 verify_cert=False, use_iran_dns=False,
                 check_http=True, verify_proxy_path=True):
        super().__init__(parsed_config=parsed_config, timeout=timeout,
                         max_workers=max_workers, retry=retry,
                         verify_cert=verify_cert, use_iran_dns=use_iran_dns)
        self._http_checker    = HTTPReachChecker(timeout=max(2.0, timeout-1))
        self._path_verifier   = ProxyPathVerifier(timeout=max(2.0, timeout-1))
        self.check_http       = check_http
        self.verify_proxy_path = verify_proxy_path

    def _scan_one(self, domain, port) -> SNIResult:
        cfg = self.parsed_config
        is_cdn = False; config_ip = None
        if cfg:
            cfg_host = (cfg.host or "").strip()
            cfg_sni  = (cfg.sni  or "").strip()
            host_hdr = (cfg.host_header or "").strip()
            if host_hdr and host_hdr != cfg_host and host_hdr != cfg_sni:
                is_cdn = True
            if cfg_host: config_ip = self._resolver.resolve(cfg_host)
        if is_cdn and config_ip: ip = config_ip
        else:
            ip = self._resolver.resolve(domain)
            if not ip:
                ip = config_ip or (cfg.host if cfg else None)
                if not ip:
                    return SNIResult(domain=domain, sni=domain, port=port,
                                     error="DNS resolution failed")
        host_header = getattr(cfg, "host_header", "") or "" if cfg else ""
        path        = getattr(cfg, "path", "/") or "/" if cfg else "/"
        result = self._prober.probe(domain=domain, ip=ip, port=port, sni=domain)
        cdn = detect_cdn_provider(ip)
        result.extra["cdn_provider"] = cdn
        if self.check_http and result.tls_ok:
            http_ok, http_status, http_lat = self._http_checker.check(
                ip=ip, port=port, sni=domain,
                host_header=host_header, path=path)
            result.extra["http_ok"]         = http_ok
            result.extra["http_status"]     = http_status
            result.extra["http_latency_ms"] = round(http_lat, 2)
            if http_ok: result.score = min(result.score + 15, 100)
        else:
            result.extra.update({"http_ok": False, "http_status": 0, "http_latency_ms": -1.0})
        result.extra["scan_mode"] = "cdn" if is_cdn else "direct"
        result.extra["config_ip"] = config_ip or ""
        if self.verify_proxy_path and is_cdn and result.tls_ok and cfg:
            transport = (getattr(cfg, "network", "") or "").lower()
            path_hdr  = (getattr(cfg, "host_header", "") or "").strip()
            path_url  = (getattr(cfg, "path", "/") or "/")
            if path_hdr:
                path_ok, path_status, path_lat, path_detail = self._path_verifier.verify(
                    ip=ip, port=port, sni=domain, host_header=path_hdr,
                    path=path_url, transport=transport, secure=((getattr(cfg, "security", "") or "").lower() in ("tls", "reality", "xtls")))
                result.extra["proxy_path_ok"]     = path_ok
                result.extra["proxy_path_status"] = path_status
                result.extra["proxy_path_latency"]= round(path_lat, 2)
                result.extra["proxy_path_detail"] = path_detail
                result.score = score_sni_result_v2(result, transport)
                if not path_ok:
                    result.tls_ok = False
                    result.error  = f"TLS OK but proxy path failed ({path_detail})"
            else:
                result.extra["proxy_path_ok"] = None
        return result


# ─────────────────────────── DualModeSNIScanner ──────────────────
class DualModeSNIScanner:
    def __init__(self, parsed_config, timeout=DEFAULT_TIMEOUT,
                 max_workers=DEFAULT_MAX_WORKERS, verify_path=True, retry=DEFAULT_RETRY_COUNT,
                 use_iran_dns=False, use_cache=True, cache_ttl=900, stability_runs=1):
        self.cfg          = parsed_config
        self.timeout      = timeout
        self.max_workers  = max_workers
        self.verify_path  = verify_path
        self.retry        = max(1, int(retry or 1))
        # retry=1 is Fast/Normal, retry=2 Accurate, retry=3 Max.
        # Keep Fast usable by limiting extra edge attempts and retry sleep.
        self._alt_ip_limit = 1 if self.retry <= 1 else (3 if self.retry == 2 else 4)
        self._retry_delay = 0.0 if self.retry <= 1 else 0.25
        self._resolver    = DNSResolver(use_iran_dns=use_iran_dns, timeout=timeout)
        self._prober      = TLSProber(timeout=timeout, retry=self.retry, verify_cert=False)
        self._http        = HTTPReachChecker(timeout=max(2.0, timeout-1))
        self._path        = ProxyPathVerifier(timeout=max(2.0, timeout-1))
        self._cache       = ScanCache(enabled=use_cache, ttl_seconds=cache_ttl)
        self._stability_runs = max(1, min(5, int(stability_runs or 1)))

        cfg_host          = (getattr(parsed_config, "host", "") or "").strip()
        self._config_ip   = self._resolver.resolve(cfg_host) if cfg_host else ""
        self._host_header = (getattr(parsed_config, "host_header", "") or "").strip()
        self._path_url    = (getattr(parsed_config, "path", "/") or "/")
        self._transport   = (getattr(parsed_config, "network", "") or "").lower()
        self._port        = int(getattr(parsed_config, "port", 443) or 443)
        self._security    = (getattr(parsed_config, "security", "") or "").lower().strip()
        self._secure      = self._security in ("tls", "reality", "xtls")
        cfg_sni           = (getattr(parsed_config, "sni", "") or "").strip()
        self.is_cdn       = bool(
            self._host_header
            and self._host_header != cfg_host
            and self._host_header != cfg_sni
        )
        self._host_family = self._detect_host_family(self._host_header or cfg_host)

    def _detect_host_family(self, host: str) -> str:
        h = (host or "").lower().strip()
        if h.endswith("vercel.app") or h.endswith("vercel.com"):
            return "Vercel"
        if h.endswith("workers.dev") or h.endswith("pages.dev") or "cloudflare" in h:
            return "Cloudflare"
        if h.endswith("netlify.app"):
            return "Netlify"
        return ""

    def _candidate_compatible_with_config(self, domain: str, ip: str) -> bool:
        """
        For CDN/fronting-style configs the candidate is used as both ADDRESS and SNI,
        while the original config Host header is kept (for example: address/SNI=botid.vercel.com,
        Host=relay-xxxx.vercel.app). A candidate is useful only if it belongs to the same
        edge family as the Host header; otherwise random Cloudflare/hCaptcha domains can
        return TLS/HTTP responses and look green even though they cannot carry the config.
        """
        family = self._host_family
        d = (domain or "").lower().strip()
        if not family:
            return True
        if family == "Vercel":
            return (
                d.endswith("vercel.app") or d.endswith("vercel.com")
                or detect_cdn_provider(ip or "") == "Vercel"
            )
        if family == "Cloudflare":
            return detect_cdn_provider(ip or "") == "Cloudflare"
        return True

    def _probe_mode(self, domain, ip, port, do_path):
        """
        Probe one candidate.

        TLS configs: candidate is tested as SNI.
        NON-TLS configs (security=none, usually ws/http): there is no real SNI,
        so the candidate is tested as the ADDRESS/front domain while the original
        Host header/path are kept. This is the case for configs like:
        address=snapp.ir, Host=ms.example.ir, security=none, network=ws.
        """
        if not ip:
            return False, "", -1.0, "", False, None, "", "DNS failed"

        http_ok = False; path_ok = None; path_detail = ""
        compatible = self._candidate_compatible_with_config(domain, ip)

        if not self._secure:
            tcp_ok, tcp_lat, tcp_err = self._prober._tcp(ip, port)
            if not tcp_ok:
                return False, "plain", tcp_lat, "", False, False if do_path else None, "", tcp_err

            # IMPORTANT: security=none has no TLS/SNI at all.
            # For WS/HTTP CDN-front configs the candidate domain is the ADDRESS/front,
            # and the original Host/path must be validated. Do NOT mark every open
            # TCP/HTTP response as PASS; that caused almost all domains to become OK.
            if self._host_header and do_path:
                raw_path_ok, status, path_lat, path_detail = self._path.verify(
                    ip=ip, port=port, sni=domain,
                    host_header=self._host_header,
                    path=self._path_url, transport=self._transport, secure=False)
                http_ok = bool(status)
                latency = path_lat if path_lat and path_lat > 0 else tcp_lat

                if self._transport == "ws":
                    # A real plain WebSocket front must complete the WS upgrade.
                    # 400/403/404/426 only prove the web server is reachable, not that
                    # the VLESS WS Host/path can pass through this front domain.
                    path_ok = (status == 101)
                    if not path_ok:
                        path_detail = f"WS upgrade failed on front={domain}, Host={self._host_header}: {path_detail or ('HTTP '+str(status) if status else 'no HTTP response')}"
                elif self._transport in ("http", "httpupgrade", "xhttp"):
                    # For plain HTTP-like transports accept only successful/redirect
                    # responses, not client/server errors.
                    path_ok = (status in (101, 200, 201, 204, 206, 301, 302, 307, 308))
                    if not path_ok:
                        path_detail = f"HTTP front check failed on front={domain}, Host={self._host_header}: {path_detail or ('HTTP '+str(status) if status else 'no HTTP response')}"
                else:
                    path_ok = raw_path_ok and status not in (400, 403, 404, 405, 426)

                return path_ok is True, "plain", latency, "no-tls", http_ok, path_ok, path_detail, "" if path_ok else path_detail

            # Non-TLS direct TCP without Host/path can only prove TCP reachability.
            return True, "plain", tcp_lat, "no-tls", False, None, "Plain TCP OK", ""

        result = self._prober.probe(domain=domain, ip=ip, port=port, sni=domain)
        if result.tls_ok and self._host_header and do_path:
            raw_path_ok, status, _, path_detail = self._path.verify(
                ip=ip, port=port, sni=domain,
                host_header=self._host_header,
                path=self._path_url, transport=self._transport, secure=True)
            http_ok = bool(status)
            if not compatible:
                path_ok = False
                path_detail = f"Incompatible with config Host family ({self._host_family or 'unknown'}); {path_detail}"
            elif raw_path_ok:
                path_ok = True
            elif self._host_family == "Vercel":
                path_ok = True
                path_detail = f"TLS OK on Vercel-family edge; plain HTTP probe: {path_detail}"
            elif self._transport == "ws":
                path_ok = True
                path_detail = f"TLS OK; WS Host probe inconclusive: {path_detail}"
            else:
                path_ok = False
        elif result.tls_ok and self._host_header and not compatible:
            path_ok = False
            path_detail = f"Incompatible with config Host family ({self._host_family or 'unknown'})"
        return (result.tls_ok, result.tls_version, result.latency_ms,
                result.cert_cn, http_ok, path_ok, path_detail, result.error)

    def _probe_with_retry(self, domain, ip, port, do_path):
        """Run a mode probe with smart retry, cache and optional stability test."""
        cache_key = self._cache.key(
            "probe", domain, ip, port, do_path, self._security, self._transport,
            self._host_header, self._path_url, self._secure, self.verify_path,
            self.retry, self._stability_runs,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            try:
                probe = tuple(cached.get("probe", []))
                if len(probe) == 8:
                    # add cache hint into detail but preserve tuple shape
                    lst = list(probe)
                    lst[6] = (str(lst[6]) + " | cache") if lst[6] else "cache"
                    return tuple(lst)
            except Exception:
                pass

        best = None
        success_count = 0
        attempts_total = max(self.retry, self._stability_runs)
        for attempt in range(attempts_total):
            probe = self._probe_mode(domain, ip, port, do_path)
            ok, _, lat, _, _, path_ok, _, _ = probe
            if ok and path_ok is not False:
                success_count += 1
            if best is None:
                best = probe
            else:
                best_ok, _, best_lat, _, _, best_path_ok, _, _ = best
                better = False
                if ok and not best_ok:
                    better = True
                elif ok == best_ok:
                    if path_ok is True and best_path_ok is not True:
                        better = True
                    elif (lat and lat > 0) and (not best_lat or best_lat <= 0 or lat < best_lat):
                        better = True
                if better:
                    best = probe

            # Fast path: when stability is disabled, stop on a valid OK like before.
            if self._stability_runs <= 1 and ok and (path_ok is not False):
                break
            if attempt < attempts_total - 1 and self._retry_delay > 0:
                time.sleep(self._retry_delay)

        if best is None:
            best = (False, "", -1.0, "", False, False if do_path else None, "", "no probe")
        # If stability is enabled, require at least one success but attach the rate.
        if self._stability_runs > 1:
            rate = int((success_count / float(attempts_total)) * 100)
            lst = list(best)
            detail = str(lst[6] or "")
            lst[6] = (detail + f" | stability {success_count}/{attempts_total} ({rate}%)").strip(" |")
            best = tuple(lst)
        self._cache.set(cache_key, {"probe": list(best)})
        return best

    def _scan_one(self, domain: str, port: int) -> DualModeSNIResult:
        r = DualModeSNIResult(domain=domain, port=port)
        r.mode_a_ip = self._config_ip
        # In non-TLS WS/HTTP front-domain configs, Mode A would connect to the
        # original config address for every candidate, so it can make almost every
        # row look OK. Skip it there; B/C are the meaningful candidate tests.
        skip_a_for_plain_front = (not self._secure and bool(self._host_header))
        if self._config_ip and not skip_a_for_plain_front:
            (r.mode_a_tls_ok, r.mode_a_tls_version, r.mode_a_latency_ms,
             r.mode_a_cert_cn, r.mode_a_http_ok, r.mode_a_path_ok,
             r.mode_a_path_detail, r.mode_a_error) = self._probe_with_retry(
                domain=domain, ip=self._config_ip, port=port,
                do_path=self.verify_path and self.is_cdn)
        elif skip_a_for_plain_front:
            r.mode_a_error = "Mode A skipped for non-TLS WS/HTTP front-domain scan"
        own_ips = self._resolver.resolve_all(domain)
        own_ip = own_ips[0] if own_ips else ""
        r.mode_b_ip = own_ip or ""
        if own_ip and own_ip != self._config_ip:
            (r.mode_b_tls_ok, r.mode_b_tls_version, r.mode_b_latency_ms,
             r.mode_b_cert_cn, r.mode_b_http_ok, r.mode_b_path_ok,
             r.mode_b_path_detail, r.mode_b_error) = self._probe_with_retry(
                domain=domain, ip=own_ip, port=port,
                do_path=self.verify_path and self.is_cdn)
        elif own_ip == self._config_ip:
            r.mode_b_tls_ok = r.mode_a_tls_ok; r.mode_b_tls_version = r.mode_a_tls_version
            r.mode_b_latency_ms = r.mode_a_latency_ms; r.mode_b_cert_cn = r.mode_a_cert_cn
            r.mode_b_http_ok = r.mode_a_http_ok; r.mode_b_path_ok = r.mode_a_path_ok
            r.mode_b_path_detail = r.mode_a_path_detail; r.mode_b_ip = own_ip

        # Mode C: try alternative DNS edge IPs for the candidate SNI. This catches CDN
        # domains with multiple anycast/edge answers where the first DNS answer is not the best.
        alt_ips = [ip for ip in own_ips if ip and ip not in {own_ip, self._config_ip}]
        best_c = None
        for alt_ip in alt_ips[:self._alt_ip_limit]:
            probe = self._probe_with_retry(
                domain=domain, ip=alt_ip, port=port,
                do_path=self.verify_path and self.is_cdn)
            if best_c is None or (probe[0] and (not best_c[0] or (0 < probe[2] < best_c[2] if best_c[2] > 0 else True))):
                best_c = (alt_ip, probe)
            if probe[0] and probe[5] is not False:
                break
        if best_c:
            r.mode_c_ip = best_c[0]
            (r.mode_c_tls_ok, r.mode_c_tls_version, r.mode_c_latency_ms,
             r.mode_c_cert_cn, r.mode_c_http_ok, r.mode_c_path_ok,
             r.mode_c_path_detail, r.mode_c_error) = best_c[1]

        r.cdn_provider = detect_cdn_provider(self._config_ip or r.mode_b_ip or r.mode_c_ip)
        best_lat = min((x for x in [r.mode_a_latency_ms, r.mode_b_latency_ms, r.mode_c_latency_ms] if x > 0),
                       default=9999)
        score = 0
        if r.reliable_pass: score += 40
        if r.mode_b_path_ok is True or r.mode_c_path_ok is True or (r.mode_a_path_ok is True and r.reliable_pass): score += 30
        if best_lat < 200: score += 20
        elif best_lat < 400: score += 10
        elif best_lat < 700: score += 5
        r.score = min(float(score), 100.0)
        return r

    def run(self, domains, port=443, on_result=None) -> List[DualModeSNIResult]:
        results: List[DualModeSNIResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._scan_one, d, port): d for d in domains}
            for future in as_completed(futures):
                try: r = future.result()
                except Exception as e:
                    r = DualModeSNIResult(domain=futures[future],
                                          port=port, mode_a_error=str(e))
                results.append(r)
                if on_result: on_result(r)
        return results


# ─────────────────────────── SNIListLoader ───────────────────────
class SNIListLoader:
    @staticmethod
    def from_file(path: str) -> List[str]:
        p = path.strip()
        if not p: return []
        try:
            with open(p, "r", encoding="utf-8") as f: content = f.read()
        except (FileNotFoundError, OSError): return []
        ext = p.rsplit(".", 1)[-1].lower()
        if ext == "json":   return SNIListLoader._parse_json(content)
        elif ext == "csv":  return SNIListLoader._parse_csv(content)
        return SNIListLoader._parse_text(content)

    @staticmethod
    def from_string(raw: str) -> List[str]:
        return SNIListLoader._parse_text(raw.replace(",", "\n"))

    @staticmethod
    def _parse_text(content):
        return _dedup(l.strip() for l in content.splitlines()
                      if l.strip() and not l.strip().startswith("#"))

    @staticmethod
    def _parse_json(content):
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else data.get("domains", data.get("sni", []))
            return _dedup(str(i).strip() for i in items if i)
        except json.JSONDecodeError: return []

    @staticmethod
    def _parse_csv(content):
        domains = []
        try:
            for row in csv.reader(io.StringIO(content)):
                if row:
                    v = row[0].strip()
                    if v and not v.startswith("#"): domains.append(v)
        except Exception: pass
        return _dedup(domains)


# ─────────────────────────── SNIAutoCollector ────────────────────
class SNIAutoCollector:
    def collect(self, parsed_config) -> List[str]:
        if not parsed_config: return []
        sec = (getattr(parsed_config, "security", "") or "").lower()
        if sec not in ("tls", "reality", "xtls"): return []
        candidates: List[str] = []
        for attr in ("sni", "host_header", "server_name"):
            v = getattr(parsed_config, attr, None)
            if v and isinstance(v, str) and "." in v: candidates.append(v.strip())
        extra = getattr(parsed_config, "extra", {}) or {}
        for key in ("sni", "servername", "server_name", "cdn"):
            v = extra.get(key)
            if v and isinstance(v, str) and "." in v: candidates.append(v.strip())
        headers = getattr(parsed_config, "headers", {}) or {}
        hh = headers.get("Host") or headers.get("host")
        if hh and "." in hh: candidates.append(hh.strip())
        return _dedup(candidates)


# ─────────────────────────── Helpers ─────────────────────────────
def _dedup(items) -> List[str]:
    seen = set(); result: List[str] = []
    for item in items:
        item = item.strip().lower()
        if item and item not in seen:
            seen.add(item); result.append(item)
    return result

def sort_results(results: List[SNIResult], by: str = DEFAULT_SORT_BY) -> List[SNIResult]:
    if by == "score":
        return sorted(results, key=lambda r: (0 if r.tls_ok else 1, -r.score))
    elif by == "domain":
        return sorted(results, key=lambda r: r.domain.lower())
    return sorted(results, key=lambda r: (0 if r.tls_ok else 1,
                                          r.latency_ms if r.latency_ms > 0 else 9999))

def filter_results(results, ok_only=False, max_latency=DEFAULT_MAX_LATENCY, min_score=0):
    return [r for r in results
            if not (ok_only and not r.tls_ok)
            and not (r.tls_ok and r.latency_ms > max_latency)
            and r.score >= min_score]

def best_result(results: List[SNIResult]) -> Optional[SNIResult]:
    ok = [r for r in results if r.tls_ok]
    return min(ok, key=lambda r: r.latency_ms if r.latency_ms > 0 else 9999) if ok else None

def results_to_json(results: List[SNIResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False)


# ─────────────────────────── __all__ ─────────────────────────────
__all__ = [
    "DEFAULT_TIMEOUT", "DEFAULT_MAX_WORKERS", "DEFAULT_RETRY_COUNT",
    "DEFAULT_MAX_LATENCY", "DEFAULT_SORT_BY",
    "IRAN_DNS_SERVERS", "CLEAN_DNS_SERVERS",
    "CDN_RANGES", "detect_cdn_provider",
    "SNIResult", "DualModeSNIResult",
    "DNSResolver", "CertParser", "TLSProber",
    "HTTPReachChecker", "ProxyPathVerifier",
    "SNIScanner", "BatchSNIScanner", "EnhancedSNIScanner", "DualModeSNIScanner",
    "SNIListLoader", "SNIAutoCollector",
    "score_sni_result_v2",
    "sort_results", "filter_results", "best_result", "results_to_json",
]
