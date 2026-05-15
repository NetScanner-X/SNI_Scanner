# ============================================================
#  parser.py  —  Part 1 / 4
#  Imports · ParsedConfig · Helpers
# ============================================================

from __future__ import annotations

import re
import json
import base64
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote


# -----------------------------------------------------------------
# ParsedConfig — Core Data Model
# -----------------------------------------------------------------

@dataclass
class ParsedConfig:
    # Connection
    protocol:    str = ""        # vless, vmess, trojan, ss, ssr
    host:        str = ""        # server address (domain or IP)
    port:        int = 0         # server port
    uuid:        str = ""        # uuid / password / user

    # TLS
    security:    str = ""        # tls, reality, xtls, none
    sni:         str = ""        # TLS SNI
    fingerprint: str = "chrome"  # utls fingerprint
    alpn:        Optional[List[str]] = field(default=None)
    insecure:    bool = False

    # Reality
    public_key:  str = ""
    short_id:    str = ""
    spider_x:    str = ""

    # Transport
    network:     str = ""        # ws, h2, http, grpc, tcp, httpupgrade
    path:        str = "/"
    host_header: Optional[str] = None
    grpc_service_name: str = ""

    # Shadowsocks
    method:      str = ""        # encryption method for ss

    # Meta
    name:        str = ""        # config alias / remark
    raw:         str = ""        # original raw config string
    config_type: str = ""        # cdn_based / direct_server / plain_http
    extra:       Dict[str, Any] = field(default_factory=dict)  # manual flags / scanner metadata

    # -----------------------------------------------------------------

    def is_valid(self) -> bool:
        return bool(self.host and self.port and self.protocol)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol":    self.protocol,
            "host":        self.host,
            "port":        self.port,
            "uuid":        self.uuid,
            "security":    self.security,
            "sni":         self.sni,
            "fingerprint": self.fingerprint,
            "alpn":        self.alpn,
            "insecure":    self.insecure,
            "network":     self.network,
            "path":        self.path,
            "host_header": self.host_header,
            "method":      self.method,
            "name":        self.name,
            "config_type": self.config_type,
            "extra":       self.extra,
        }

    def get(self, key: str, default=None):
        """
        سازگاری با dict-style access برای SNIScanner و سایر ماژول‌ها.
        مثال: config.get("sni", "")
        """
        _key_map = {
            "address":      "host",
            "server":       "host",
            "use_iran_dns": None,   # وجود نداره → default برمیگرده
        }
        mapped = _key_map.get(key, key)
        if mapped is None:
            return default
        return getattr(self, mapped, default)

    def set(self, key: str, value) -> None:
        """
        سازگاری با dict-style set برای SNIScanner و سایر ماژول‌ها.
        مثال: config.set("sni", "example.com")
        """
        _key_map = {
            "address": "host",
            "server":  "host",
        }
        mapped = _key_map.get(key, key)
        if hasattr(self, mapped):
            setattr(self, mapped, value)


# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip(value: str) -> bool:
    return bool(_IP_PATTERN.match(value.strip()))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _decode_base64(data: str) -> str:
    data    = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _parse_alpn(raw: str) -> Optional[List[str]]:
    if not raw:
        return None
    items = [x.strip() for x in raw.split(",") if x.strip()]
    return items if items else None


def _extract_name(raw_url: str) -> str:
    if "#" in raw_url:
        fragment = raw_url.split("#", 1)[1]
        return unquote(fragment).strip()
    return ""


# ============================================================
#  parser.py  —  Part 2 / 4
#  VLESS · VMESS · TROJAN Parsers
# ============================================================

# -----------------------------------------------------------------
# VLESS Parser
# -----------------------------------------------------------------

def _parse_vless(raw: str) -> Optional[ParsedConfig]:
    """
    vless://uuid@host:port?security=tls&sni=...&fp=...&type=ws&path=...&host=...#name
    """
    try:
        url     = raw.strip()
        name    = _extract_name(url)
        url     = url.split("#")[0]

        body    = url[len("vless://"):]
        at_idx  = body.rfind("@")
        if at_idx == -1:
            return None

        uuid    = body[:at_idx]
        rest    = body[at_idx + 1:]

        # host:port?params
        if "?" in rest:
            addr_part, query = rest.split("?", 1)
        else:
            addr_part, query = rest, ""

        # IPv6 support: [::1]:443
        if addr_part.startswith("["):
            bracket_end = addr_part.find("]")
            host        = addr_part[1:bracket_end]
            port_str    = addr_part[bracket_end + 2:]  # skip ]:
        else:
            parts    = addr_part.rsplit(":", 1)
            host     = parts[0] if len(parts) == 2 else addr_part
            port_str = parts[1] if len(parts) == 2 else "443"

        port   = _safe_int(port_str, 443)
        params = parse_qs(query, keep_blank_values=True)

        def _get(key: str, default: str = "") -> str:
            return params.get(key, [default])[0]

        security    = _get("security", "none").lower()
        sni         = _get("sni") or _get("serverName") or host
        fingerprint = _get("fp", "chrome")
        alpn        = _parse_alpn(_get("alpn"))
        insecure    = _get("allowInsecure", "0") in ("1", "true")

        # Reality
        public_key  = _get("pbk")
        short_id    = _get("sid")
        spider_x    = _get("spx")

        # Transport
        network     = _get("type", "tcp").lower()
        path        = unquote(_get("path", "/"))
        host_header = _get("host") or None
        grpc_svc    = _get("serviceName")

        return ParsedConfig(
            protocol          = "vless",
            host              = host,
            port              = port,
            uuid              = uuid,
            security          = security,
            sni               = sni,
            fingerprint       = fingerprint,
            alpn              = alpn,
            insecure          = insecure,
            public_key        = public_key,
            short_id          = short_id,
            spider_x          = spider_x,
            network           = network,
            path              = path,
            host_header       = host_header,
            grpc_service_name = grpc_svc,
            name              = name,
            raw               = raw,
        )

    except Exception:
        return None


# -----------------------------------------------------------------
# VMESS Parser
# -----------------------------------------------------------------

def _parse_vmess(raw: str) -> Optional[ParsedConfig]:
    """
    vmess://base64(json)
    """
    try:
        b64  = raw.strip()[len("vmess://"):]
        b64  = b64.split("#")[0]
        data = _decode_base64(b64)
        if not data:
            return None

        obj  = json.loads(data)

        host        = str(obj.get("add", "") or obj.get("host", ""))
        port        = _safe_int(obj.get("port", 443))
        uuid        = str(obj.get("id", ""))
        network     = str(obj.get("net", "tcp")).lower()
        path        = str(obj.get("path", "/") or "/")
        host_header = str(obj.get("host", "") or "") or None
        sni         = str(obj.get("sni", "") or obj.get("serverName", "") or host)
        tls         = str(obj.get("tls", "")).lower()
        security    = "tls" if tls in ("tls", "1", "true") else "none"
        fingerprint = str(obj.get("fp", "chrome") or "chrome")
        alpn        = _parse_alpn(str(obj.get("alpn", "") or ""))
        name        = unquote(str(obj.get("ps", "") or "")).strip()
        grpc_svc    = str(obj.get("path", "") if network == "grpc" else "")

        return ParsedConfig(
            protocol          = "vmess",
            host              = host,
            port              = port,
            uuid              = uuid,
            security          = security,
            sni               = sni,
            fingerprint       = fingerprint,
            alpn              = alpn,
            network           = network,
            path              = path,
            host_header       = host_header if host_header else None,
            grpc_service_name = grpc_svc,
            name              = name,
            raw               = raw,
        )

    except Exception:
        return None


# -----------------------------------------------------------------
# TROJAN Parser
# -----------------------------------------------------------------

def _parse_trojan(raw: str) -> Optional[ParsedConfig]:
    """
    trojan://password@host:port?security=tls&sni=...&type=ws&path=...#name
    """
    try:
        url     = raw.strip()
        name    = _extract_name(url)
        url     = url.split("#")[0]

        body    = url[len("trojan://"):]
        at_idx  = body.rfind("@")
        if at_idx == -1:
            return None

        password  = body[:at_idx]
        rest      = body[at_idx + 1:]

        if "?" in rest:
            addr_part, query = rest.split("?", 1)
        else:
            addr_part, query = rest, ""

        if addr_part.startswith("["):
            bracket_end = addr_part.find("]")
            host        = addr_part[1:bracket_end]
            port_str    = addr_part[bracket_end + 2:]
        else:
            parts    = addr_part.rsplit(":", 1)
            host     = parts[0] if len(parts) == 2 else addr_part
            port_str = parts[1] if len(parts) == 2 else "443"

        port   = _safe_int(port_str, 443)
        params = parse_qs(query, keep_blank_values=True)

        def _get(key: str, default: str = "") -> str:
            return params.get(key, [default])[0]

        security    = _get("security", "tls").lower()
        sni         = _get("sni") or _get("serverName") or host
        fingerprint = _get("fp", "chrome")
        alpn        = _parse_alpn(_get("alpn"))
        insecure    = _get("allowInsecure", "0") in ("1", "true")
        network     = _get("type", "tcp").lower()
        path        = unquote(_get("path", "/"))
        host_header = _get("host") or None
        grpc_svc    = _get("serviceName")

        return ParsedConfig(
            protocol          = "trojan",
            host              = host,
            port              = port,
            uuid              = password,
            security          = security,
            sni               = sni,
            fingerprint       = fingerprint,
            alpn              = alpn,
            insecure          = insecure,
            network           = network,
            path              = path,
            host_header       = host_header,
            grpc_service_name = grpc_svc,
            name              = name,
            raw               = raw,
        )

    except Exception:
        return None


# ============================================================
#  parser.py  —  Part 3 / 4
#  SS · SSR Parsers · rebuild_config · detect_and_parse
# ============================================================

# -----------------------------------------------------------------
# Shadowsocks Parser
# -----------------------------------------------------------------

def _parse_ss(raw: str) -> Optional[ParsedConfig]:
    """
    ss://base64(method:password)@host:port#name
    ss://base64(method:password@host:port)#name
    """
    try:
        url  = raw.strip()
        name = _extract_name(url)
        url  = url.split("#")[0]

        body = url[len("ss://"):]

        # Format 1: ss://base64@host:port
        if "@" in body:
            b64_part, addr_part = body.rsplit("@", 1)
            decoded             = _decode_base64(b64_part)
            if ":" in decoded:
                method, password = decoded.split(":", 1)
            else:
                method, password = decoded, ""

            if addr_part.startswith("["):
                bracket_end = addr_part.find("]")
                host        = addr_part[1:bracket_end]
                port_str    = addr_part[bracket_end + 2:]
            else:
                parts    = addr_part.rsplit(":", 1)
                host     = parts[0] if len(parts) == 2 else addr_part
                port_str = parts[1] if len(parts) == 2 else "8388"

        # Format 2: ss://base64(method:password@host:port)
        else:
            decoded = _decode_base64(body)
            if "@" not in decoded:
                return None

            user_part, addr_part = decoded.rsplit("@", 1)
            if ":" in user_part:
                method, password = user_part.split(":", 1)
            else:
                method, password = user_part, ""

            if addr_part.startswith("["):
                bracket_end = addr_part.find("]")
                host        = addr_part[1:bracket_end]
                port_str    = addr_part[bracket_end + 2:]
            else:
                parts    = addr_part.rsplit(":", 1)
                host     = parts[0] if len(parts) == 2 else addr_part
                port_str = parts[1] if len(parts) == 2 else "8388"

        port     = _safe_int(port_str, 8388)
        security = "none"

        return ParsedConfig(
            protocol = "ss",
            host     = host,
            port     = port,
            uuid     = password,
            method   = method.strip().lower(),
            security = security,
            sni      = host,
            network  = "tcp",
            name     = name,
            raw      = raw,
        )

    except Exception:
        return None


# -----------------------------------------------------------------
# SSR Parser
# -----------------------------------------------------------------

def _parse_ssr(raw: str) -> Optional[ParsedConfig]:
    """
    ssr://base64(host:port:protocol:method:obfs:base64(password)/?params)
    """
    try:
        body    = raw.strip()[len("ssr://"):]
        decoded = _decode_base64(body)
        if not decoded:
            return None

        # split params
        if "/?" in decoded:
            main_part, param_part = decoded.split("/?", 1)
        else:
            main_part, param_part = decoded, ""

        parts = main_part.split(":")
        if len(parts) < 6:
            return None

        host     = parts[0]
        port     = _safe_int(parts[1], 1080)
        method   = parts[3]
        password = _decode_base64(parts[5])

        params   = parse_qs(param_part)

        def _get(key: str, default: str = "") -> str:
            return params.get(key, [default])[0]

        name_b64 = _get("remarks")
        name     = _decode_base64(name_b64) if name_b64 else ""

        return ParsedConfig(
            protocol = "ssr",
            host     = host,
            port     = port,
            uuid     = password,
            method   = method.strip().lower(),
            security = "none",
            sni      = host,
            network  = "tcp",
            name     = name,
            raw      = raw,
        )

    except Exception:
        return None


# -----------------------------------------------------------------
# rebuild_config_with_sni
# -----------------------------------------------------------------

def rebuild_config_with_sni(config: ParsedConfig, new_sni: str) -> str:
    """
    Rebuild the raw config string with a new SNI value.
    Supports: vless, vmess, trojan
    Returns the original raw string for ss/ssr (SNI not applicable).
    """
    if config.protocol == "vmess":
        return _rebuild_vmess(config, new_sni)

    if config.protocol in ("vless", "trojan"):
        return _rebuild_vless_trojan(config, new_sni)

    # ss / ssr — SNI not applicable
    return config.raw


def _rebuild_vmess(config: ParsedConfig, new_sni: str) -> str:
    try:
        b64  = config.raw.strip()[len("vmess://"):]
        b64  = b64.split("#")[0]
        data = _decode_base64(b64)
        obj  = json.loads(data)

        obj["sni"]        = new_sni
        obj["serverName"] = new_sni

        new_b64 = base64.b64encode(
            json.dumps(obj, ensure_ascii=False).encode()
        ).decode()

        suffix = f"#{config.name}" if config.name else ""
        return f"vmess://{new_b64}{suffix}"

    except Exception:
        return config.raw


def _rebuild_vless_trojan(config: ParsedConfig, new_sni: str) -> str:
    try:
        raw = config.raw.strip()

        # Remove fragment
        if "#" in raw:
            main_part, fragment = raw.split("#", 1)
            suffix = f"#{fragment}"
        else:
            main_part = raw
            suffix    = ""

        # Replace sni= param
        if "sni=" in main_part:
            main_part = re.sub(
                r"(sni=)[^&]*",
                lambda m: f"{m.group(1)}{new_sni}",
                main_part,
            )
        elif "?" in main_part:
            main_part += f"&sni={new_sni}"
        else:
            main_part += f"?sni={new_sni}"

        # Replace serverName= param
        if "serverName=" in main_part:
            main_part = re.sub(
                r"(serverName=)[^&]*",
                lambda m: f"{m.group(1)}{new_sni}",
                main_part,
            )

        return main_part + suffix

    except Exception:
        return config.raw


# -----------------------------------------------------------------
# detect_and_parse
# -----------------------------------------------------------------

def detect_and_parse(raw: str) -> Optional[ParsedConfig]:
    """
    Auto-detect protocol and parse the config string.
    Returns ParsedConfig or None if parsing fails.
    """
    raw = raw.strip()

    if not raw:
        return None

    if raw.startswith("vless://"):
        return _parse_vless(raw)

    if raw.startswith("vmess://"):
        return _parse_vmess(raw)

    if raw.startswith("trojan://"):
        return _parse_trojan(raw)

    if raw.startswith("ss://"):
        return _parse_ss(raw)

    if raw.startswith("ssr://"):
        return _parse_ssr(raw)

    return None


def parse_configs(raw_list: List[str]) -> List[ParsedConfig]:
    """
    Parse a list of raw config strings.
    Skips invalid or unparseable configs silently.
    """
    results = []
    for raw in raw_list:
        parsed = detect_and_parse(raw.strip())
        if parsed and parsed.is_valid():
            results.append(parsed)
    return results


def parse_from_text(text: str) -> List[ParsedConfig]:
    """
    Extract and parse all configs from a multiline text block.
    Each line is treated as one config.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return parse_configs(lines)


def parse_from_base64_text(b64_text: str) -> List[ParsedConfig]:
    """
    Decode a base64-encoded subscription text and parse all configs.
    """
    decoded = _decode_base64(b64_text.strip())
    if not decoded:
        return []
    return parse_from_text(decoded)


# ============================================================
#  parser.py  —  Part 4 / 4
#  ConfigValidator · rebuild_config · Summary · Exports
# ============================================================

# -----------------------------------------------------------------
# Config Validator
# -----------------------------------------------------------------

class ConfigValidator:
    """
    Validate a ParsedConfig for required fields and sane values.
    """

    VALID_PROTOCOLS  = {"vless", "vmess", "trojan", "ss", "ssr"}
    VALID_SECURITIES = {"tls", "reality", "xtls", "none", ""}
    VALID_NETWORKS   = {
        "tcp", "ws", "h2", "http",
        "grpc", "httpupgrade", "splithttp", "xhttp", ""
    }

    def validate(self, config: ParsedConfig) -> Dict[str, Any]:
        errors   = []
        warnings = []

        # Protocol
        if config.protocol not in self.VALID_PROTOCOLS:
            errors.append(f"Unknown protocol: {config.protocol}")

        # Host
        if not config.host:
            errors.append("Missing host")

        # Port
        if not (1 <= config.port <= 65535):
            errors.append(f"Invalid port: {config.port}")

        # UUID / password
        if config.protocol in ("vless", "vmess", "trojan"):
            if not config.uuid:
                errors.append("Missing uuid/password")

        # Security
        if config.security not in self.VALID_SECURITIES:
            warnings.append(f"Unknown security type: {config.security}")

        # Network
        if config.network not in self.VALID_NETWORKS:
            warnings.append(f"Unknown network type: {config.network}")

        # SNI check
        if config.security in ("tls", "reality", "xtls"):
            if not config.sni:
                warnings.append("TLS enabled but SNI is empty")

        # Port vs security mismatch
        if config.port == 80 and config.security in ("tls", "reality", "xtls"):
            warnings.append("Port 80 with TLS security — unusual combination")

        if config.port == 443 and config.security == "none":
            warnings.append("Port 443 without TLS — may not work correctly")

        return {
            "valid":    len(errors) == 0,
            "errors":   errors,
            "warnings": warnings,
        }

    def is_valid(self, config: ParsedConfig) -> bool:
        return self.validate(config)["valid"]


# -----------------------------------------------------------------
# rebuild_config
# -----------------------------------------------------------------

def rebuild_config(parsed: "ParsedConfig") -> str:
    """Rebuild a config URL from a ParsedConfig object."""
    from urllib.parse import urlencode, quote

    if not parsed or not parsed.protocol:
        return ""

    proto = parsed.protocol.lower()
    host  = parsed.host or ""
    port  = parsed.port or 443

    params = {}
    if parsed.security:    params["security"] = parsed.security
    if parsed.sni:         params["sni"]      = parsed.sni
    if parsed.network:     params["type"]     = parsed.network
    if parsed.path:        params["path"]     = parsed.path
    if parsed.host_header: params["host"]     = parsed.host_header
    if parsed.fingerprint: params["fp"]       = parsed.fingerprint
    if parsed.alpn:        params["alpn"]     = ",".join(parsed.alpn)

    query = urlencode(params) if params else ""
    name  = quote(parsed.name or "")
    uuid  = parsed.uuid or ""

    if proto in ("vless", "trojan"):
        base = f"{proto}://{uuid}@{host}:{port}"
    elif proto == "vmess":
        base = f"vmess://{uuid}@{host}:{port}"
    elif proto == "ss":
        base = f"ss://{uuid}@{host}:{port}"
    else:
        base = f"{proto}://{uuid}@{host}:{port}"

    url = base
    if query:
        url += f"?{query}"
    if name:
        url += f"#{name}"

    return url


# -----------------------------------------------------------------
# Config Summary Helper
# -----------------------------------------------------------------

def get_config_summary(config: ParsedConfig) -> str:
    """
    Return a short one-line human-readable summary of a ParsedConfig.
    Used in UI display and logging.
    """
    if not config:
        return "Invalid config"

    proto   = config.protocol.upper() if config.protocol else "?"
    host    = config.host             or "?"
    port    = config.port             or 0
    sni     = config.sni              or "—"
    network = config.network          or "tcp"
    sec     = config.security         or "none"
    name    = config.name             or ""

    summary = (
        f"{proto}  {host}:{port}"
        f"  net={network}"
        f"  sec={sec}"
        f"  sni={sni}"
    )

    if name:
        summary += f"  [{name}]"

    return summary


# -----------------------------------------------------------------
# Exports
# -----------------------------------------------------------------

__all__ = [
    # Core model
    "ParsedConfig",

    # Parsers
    "detect_and_parse",
    "parse_configs",
    "parse_from_text",
    "parse_from_base64_text",

    # Rebuilders
    "rebuild_config",
    "rebuild_config_with_sni",

    # Validator
    "ConfigValidator",

    # Summary
    "get_config_summary",

    # Helpers
    "_is_ip",
    "_decode_base64",
    "_parse_alpn",
]