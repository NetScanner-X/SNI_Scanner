#!/usr/bin/env python3
"""
file_manager.py — File & Data Management Layer
Handles logging, SNI list I/O, and result persistence.
"""

from __future__ import annotations

import os
import re
import json
import csv
import time
import shutil
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

from config import (
    config_manager,
    APP_NAME, VERSION,
    BASE_DIR, DATA_DIR, SNI_LIST_DIR, RESULTS_DIR, LOGS_DIR, BACKUP_DIR,
    DEFAULT_SNI_FILE, CUSTOM_SNI_FILE, IRAN_SNI_FILE,
    RESULTS_FILE, LAST_SCAN_FILE, LOG_FILE,
    ParsedConfig, SNIResult, ConfigTestResult,
)


# ── Logger ────────────────────────────────────────────────────────

class Logger:
    """
    Simple file-based logger with level filtering.

    Levels (ascending):
        DEBUG → INFO → WARNING → ERROR → CRITICAL

    Usage:
        logger = Logger()
        logger.info("Scan started")
        logger.error("Connection failed")
    """

    LEVELS = {
        "DEBUG":    0,
        "INFO":     1,
        "WARNING":  2,
        "ERROR":    3,
        "CRITICAL": 4,
    }

    def __init__(
        self,
        log_file: Path = LOG_FILE,
        level:    str  = "INFO",
    ):
        self.log_file = log_file
        self.level    = level.upper()
        self._ensure_file()

    # ── Setup ─────────────────────────────────────────────────────

    def _ensure_file(self) -> None:
        """Creates log file and parent dirs if missing."""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.touch()

    # ── Internal Write ────────────────────────────────────────────

    def _write(self, level: str, message: str) -> None:
        """Writes a log line if level passes the filter."""
        if self.LEVELS.get(level, 0) < self.LEVELS.get(self.level, 1):
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line      = f"[{timestamp}] [{level:<8}] {message}\n"

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

    # ── Public Log Methods ────────────────────────────────────────

    def debug(self,    msg: str) -> None: self._write("DEBUG",    msg)
    def info(self,     msg: str) -> None: self._write("INFO",     msg)
    def warning(self,  msg: str) -> None: self._write("WARNING",  msg)
    def error(self,    msg: str) -> None: self._write("ERROR",    msg)
    def critical(self, msg: str) -> None: self._write("CRITICAL", msg)

    # ── Utilities ─────────────────────────────────────────────────

    def set_level(self, level: str) -> None:
        """Changes the active log level at runtime."""
        level = level.upper()
        if level in self.LEVELS:
            self.level = level

    def clear(self) -> None:
        """Clears the log file, writes a header line."""
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write(
                    f"# Log cleared at "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
        except OSError:
            pass

    def read_last(self, lines: int = 50) -> List[str]:
        """Returns the last N lines from the log file."""
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
            return all_lines[-lines:]
        except OSError:
            return []

    def get_size_kb(self) -> float:
        """Returns log file size in KB."""
        try:
            return round(self.log_file.stat().st_size / 1024, 2)
        except OSError:
            return 0.0

    def rotate(self, max_kb: float = 512.0) -> bool:
        """
        Rotates log file if it exceeds max_kb.

        Returns:
            True  — file was rotated
            False — rotation not needed
        """
        if self.get_size_kb() < max_kb:
            return False

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive   = self.log_file.with_name(
                f"{self.log_file.stem}_{timestamp}.log"
            )
            shutil.move(str(self.log_file), str(archive))
            self._ensure_file()
            self.info(f"Log rotated → {archive.name}")
            return True
        except OSError:
            return False

    def __repr__(self) -> str:
        return (
            f"<Logger "
            f"file={self.log_file.name} "
            f"level={self.level} "
            f"size={self.get_size_kb()}KB>"
        )


# ── SNIListManager ────────────────────────────────────────────────

class SNIListManager:
    """
    Manages SNI domain lists on disk.

    Files:
        default.txt  — bundled default list
        iran.txt     — Iran-optimized list
        custom.txt   — user-defined list

    All load methods deduplicate and strip comments.
    """

    _DOMAIN_RE = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )

    def __init__(self):
        SNI_LIST_DIR.mkdir(parents=True, exist_ok=True)

    # ── Load ──────────────────────────────────────────────────────

    def load_from_file(self, file_path: Path) -> List[str]:
        """
        Loads SNI domains from a text file.

        Rules:
          - Lines starting with # are comments
          - Empty lines are skipped
          - Duplicates are removed (order preserved)

        Returns:
            List of unique domain strings.
        """
        sni_list: List[str] = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        sni_list.append(line.lower())
        except FileNotFoundError:
            pass
        except OSError:
            pass

        return list(dict.fromkeys(sni_list))

    def load_default(self) -> List[str]:
        """Loads the bundled default SNI list."""
        return self.load_from_file(DEFAULT_SNI_FILE)

    def load_custom(self) -> List[str]:
        """Loads the user-defined custom SNI list."""
        return self.load_from_file(CUSTOM_SNI_FILE)

    def load_iran(self) -> List[str]:
        """Loads the Iran-optimized SNI list."""
        return self.load_from_file(IRAN_SNI_FILE)

    def load_all(self) -> List[str]:
        """
        Loads and merges all three lists.

        Order: default → iran → custom
        Duplicates removed, order preserved.
        """
        combined = (
            self.load_default()
            + self.load_iran()
            + self.load_custom()
        )
        return list(dict.fromkeys(combined))

    def load_from_text(self, text: str) -> List[str]:
        """
        Parses SNI domains from a raw text string.

        Useful for pasting domains directly in UI.
        """
        sni_list: List[str] = []
        for line in text.splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                sni_list.append(line)
        return list(dict.fromkeys(sni_list))

    # ── Save ──────────────────────────────────────────────────────

    def save_custom(self, sni_list: List[str]) -> bool:
        """
        Overwrites custom SNI file with given list.

        Returns:
            True  — saved successfully
            False — write error
        """
        try:
            with open(CUSTOM_SNI_FILE, "w", encoding="utf-8") as f:
                f.write("# Custom SNI List\n")
                f.write(
                    f"# Updated: "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                )
                for sni in sni_list:
                    f.write(sni + "\n")
            return True
        except OSError:
            return False

    def append_custom(self, sni_list: List[str]) -> bool:
        """
        Appends new domains to custom SNI file.
        Deduplicates against existing entries.

        Returns:
            True  — saved successfully
            False — write error
        """
        existing = self.load_custom()
        combined = list(dict.fromkeys(existing + sni_list))
        return self.save_custom(combined)

    # ── Validation ────────────────────────────────────────────────

    def validate_sni(self, sni: str) -> bool:
        """
        Returns True if sni is a valid domain name.
        Rejects IPs, empty strings, and malformed domains.
        """
        if not sni or len(sni) > 253:
            return False
        return bool(self._DOMAIN_RE.match(sni.strip()))

    def filter_valid(self, sni_list: List[str]) -> List[str]:
        """Filters list to only valid domain names."""
        return [s for s in sni_list if self.validate_sni(s)]

    # ── Metadata ──────────────────────────────────────────────────

    def get_all_files(self) -> List[Dict[str, Any]]:
        """
        Returns metadata for all .txt files in SNI_LIST_DIR.

        Each entry:
            name     : filename
            path     : absolute path string
            count    : number of valid domains
            size_kb  : file size in KB
        """
        files: List[Dict[str, Any]] = []

        for f in sorted(SNI_LIST_DIR.glob("*.txt")):
            try:
                domains = self.load_from_file(f)
                files.append({
                    "name":    f.name,
                    "path":    str(f),
                    "count":   len(domains),
                    "size_kb": round(f.stat().st_size / 1024, 2),
                })
            except OSError:
                pass

        return files

    def get_stats(self) -> Dict[str, Any]:
        """Returns combined stats across all SNI lists."""
        return {
            "default_count": len(self.load_default()),
            "iran_count":    len(self.load_iran()),
            "custom_count":  len(self.load_custom()),
            "total_unique":  len(self.load_all()),
        }

    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<SNIListManager "
            f"total={stats['total_unique']} "
            f"custom={stats['custom_count']}>"
        )


# ── ResultsManager ────────────────────────────────────────────────

class ResultsManager:
    """
    Handles saving, loading, and exporting scan results.

    Supported formats:
        txt  — human-readable report
        json — machine-readable full data
        csv  — spreadsheet-friendly flat format

    File naming:
        sni_scan_YYYYMMDD_HHMMSS.{ext}
        config_test_YYYYMMDD_HHMMSS.{ext}
    """

    def __init__(self):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ═══════════════════════════════════════════════════════════════
    #  SNI Scan Results — Public Entry
    # ═══════════════════════════════════════════════════════════════

    def save_sni_results(
        self,
        results:       List[SNIResult],
        parsed_config: ParsedConfig,
        stats:         Dict[str, Any],
        fmt:           str = "txt",
    ) -> Path:
        """
        Saves SNI scan results to disk.

        Args:
            results       : list of SNIResult objects
            parsed_config : the config that was scanned against
            stats         : summary statistics dict
            fmt           : output format — txt / json / csv

        Returns:
            Path to the saved file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"sni_scan_{timestamp}.{fmt}"
        filepath  = RESULTS_DIR / filename

        if   fmt == "json": self._save_sni_json(results, parsed_config, stats, filepath)
        elif fmt == "csv":  self._save_sni_csv(results, filepath)
        else:               self._save_sni_txt(results,  parsed_config, stats, filepath)

        self._save_last_scan_meta(parsed_config, stats, str(filepath))
        return filepath

    # ── SNI TXT ───────────────────────────────────────────────────

    def _save_sni_txt(
        self,
        results:       List[SNIResult],
        parsed_config: ParsedConfig,
        stats:         Dict[str, Any],
        filepath:      Path,
    ) -> None:

        ok_results   = [r for r in results if r.handshake_ok]
        fail_results = [r for r in results if not r.handshake_ok]

        with open(filepath, "w", encoding="utf-8") as f:

            # ── Header ────────────────────────────────────────────
            f.write("=" * 64 + "\n")
            f.write(f"  {APP_NAME} v{VERSION} — SNI Scan Results\n")
            f.write("=" * 64 + "\n")
            f.write(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Protocol : {parsed_config.protocol or '?'}\n")
            f.write(f"  Host     : {parsed_config.host or '?'}:{parsed_config.port or 0}\n")
            f.write(f"  Network  : {(parsed_config.network  or '?').upper()}\n")
            f.write(f"  Security : {(parsed_config.security or '?').upper()}\n")
            f.write(f"  SNI      : {parsed_config.sni or '—'}\n")
            f.write("=" * 64 + "\n\n")

            # ── Statistics ────────────────────────────────────────
            f.write("── Statistics ──────────────────────────────────────────\n")
            for k, v in stats.items():
                f.write(f"  {k:<28}: {v}\n")
            f.write("\n")

            # ── Successful Results ────────────────────────────────
            f.write(f"── Successful SNIs ({len(ok_results)}) ──────────────────────────\n")
            for i, r in enumerate(ok_results, 1):
                f.write(
                    f"  [{i:>3}]  {(r.sni or '—'):<45}  "
                    f"Latency: {r.latency_ms:>8.1f}ms  "
                    f"TLS: {(r.tls_version or '?'):<10}  "
                    f"Score: {r.score:>5.1f}  "
                    f"Conf: {r.confidence:>3}%\n"
                )
            f.write("\n")

            # ── Failed Results (compact) ──────────────────────────
            if fail_results:
                f.write(f"── Failed SNIs ({len(fail_results)}) ─────────────────────────────\n")
                for r in fail_results:
                    f.write(
                        f"  ✗  {(r.sni or '—'):<45}  "
                        f"Stage: {r.error_stage or '?'}  "
                        f"{r.error or 'unreachable'}\n"
                    )
                f.write("\n")

            # ── Clean SNI List ────────────────────────────────────
            f.write("── Clean SNI List (copy-paste ready) ───────────────────\n")
            for r in ok_results:
                f.write(f"  {r.sni}\n")

    # ── SNI JSON ──────────────────────────────────────────────────

    def _save_sni_json(
        self,
        results:       List[SNIResult],
        parsed_config: ParsedConfig,
        stats:         Dict[str, Any],
        filepath:      Path,
    ) -> None:

        data = {
            "meta": {
                "app":       APP_NAME,
                "version":   VERSION,
                "timestamp": datetime.now().isoformat(),
                "config":    parsed_config.to_dict(),
            },
            "statistics": stats,
            "results":    [r.to_dict() for r in results],
            "successful": [
                r.sni for r in results
                if r.handshake_ok and r.sni
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ── SNI CSV ───────────────────────────────────────────────────

    def _save_sni_csv(
        self,
        results:  List[SNIResult],
        filepath: Path,
    ) -> None:

        fieldnames = [
            "sni",          "ip_resolved",
            "tcp_ok",       "tcp_latency_ms",
            "tls_ok",       "tls_version",      "alpn_negotiated",
            "cert_cn",      "cert_expiry",       "cert_valid",
            "handshake_ok", "latency_ms",
            "score",        "confidence",        "iran_friendly",
            "error",        "error_stage",
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()
            for r in results:
                writer.writerow(r.to_dict())

    # ═══════════════════════════════════════════════════════════════
    #  Config Test Results — Public Entry
    # ═══════════════════════════════════════════════════════════════

    def save_config_results(
        self,
        results:       List[ConfigTestResult],
        parsed_config: ParsedConfig,
        summary:       Dict[str, Any],
        fmt:           str = "txt",
    ) -> Path:
        """
        Saves config test results to disk.

        Args:
            results       : list of ConfigTestResult objects
            parsed_config : the config under test
            summary       : summary statistics dict
            fmt           : output format — txt / json / csv

        Returns:
            Path to the saved file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"config_test_{timestamp}.{fmt}"
        filepath  = RESULTS_DIR / filename

        if   fmt == "json": self._save_config_json(results, parsed_config, summary, filepath)
        elif fmt == "csv":  self._save_config_csv(results, filepath)
        else:               self._save_config_txt(results,  parsed_config, summary, filepath)

        return filepath

    # ── Config TXT ────────────────────────────────────────────────

    def _save_config_txt(
        self,
        results:       List[ConfigTestResult],
        parsed_config: ParsedConfig,
        summary:       Dict[str, Any],
        filepath:      Path,
    ) -> None:

        ok_results = [r for r in results if r.overall_ok]

        with open(filepath, "w", encoding="utf-8") as f:

            # ── Header ────────────────────────────────────────────
            f.write("=" * 64 + "\n")
            f.write(f"  {APP_NAME} v{VERSION} — Config Test Results\n")
            f.write("=" * 64 + "\n")
            f.write(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Protocol : {parsed_config.protocol or '?'}\n")
            f.write(f"  Host     : {parsed_config.host or '?'}:{parsed_config.port or 0}\n")
            f.write(f"  Tag      : {parsed_config.tag or '—'}\n")
            f.write("=" * 64 + "\n\n")

            # ── Summary ───────────────────────────────────────────
            f.write("── Summary ─────────────────────────────────────────────\n")
            for k, v in summary.items():
                f.write(f"  {k:<28}: {v}\n")
            f.write("\n")

            # ── Results Table ─────────────────────────────────────
            f.write("── Results ─────────────────────────────────────────────\n")
            header = (
                f"  {'#':<4}  {'SNI':<35}  "
                f"{'DNS':<4}  {'TCP':<4}  {'TLS':<4}  {'HTTP':<4}  "
                f"{'Score':>6}  {'Latency':>9}  Status\n"
            )
            f.write(header)
            f.write("  " + "─" * 88 + "\n")

            for i, r in enumerate(results, 1):

                def _s(stage: str) -> str:
                    v = r.test_stages.get(stage, "")
                    if v == "PASS": return "OK"
                    if v == "FAIL": return "XX"
                    return "--"

                status = "PASS" if r.overall_ok else "FAIL"
                lat    = f"{r.tcp_latency_ms:.1f}ms" if r.tcp_latency_ms > 0 else "—"

                f.write(
                    f"  [{i:>3}]  {(r.sni or '—'):<35}  "
                    f"{_s('dns'):<4}  {_s('tcp'):<4}  "
                    f"{_s('tls'):<4}  {_s('http'):<4}  "
                    f"{r.score:>6.1f}  {lat:>9}  {status}\n"
                )
            f.write("\n")

            # ── Rebuilt Configs ───────────────────────────────────
            rebuilt = [r.rebuilt_config for r in ok_results if r.rebuilt_config]
            if rebuilt:
                f.write("── Rebuilt Configs ─────────────────────────────────────\n")
                for link in rebuilt:
                    f.write(f"  {link}\n")
                f.write("\n")

            # ── Warnings ──────────────────────────────────────────
            all_warnings = [
                (r.sni or "?", w)
                for r in results
                for w in r.warnings
            ]
            if all_warnings:
                f.write("── Warnings ────────────────────────────────────────────\n")
                for sni, warn in all_warnings:
                    f.write(f"  [{sni}]  {warn}\n")

    # ── Config JSON ───────────────────────────────────────────────

    def _save_config_json(
        self,
        results:       List[ConfigTestResult],
        parsed_config: ParsedConfig,
        summary:       Dict[str, Any],
        filepath:      Path,
    ) -> None:

        data = {
            "meta": {
                "app":       APP_NAME,
                "version":   VERSION,
                "timestamp": datetime.now().isoformat(),
                "config":    parsed_config.to_dict(),
            },
            "summary": summary,
            "results": [r.to_dict() for r in results],
            "passed":  [r.to_dict() for r in results if r.overall_ok],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ── Config CSV ────────────────────────────────────────────────

    def _save_config_csv(
        self,
        results:  List[ConfigTestResult],
        filepath: Path,
    ) -> None:

        fieldnames = [
            "config_type",   "host",            "port",           "sni",
            "dns_ok",        "ip_resolved",      "dns_latency_ms",
            "tcp_ok",        "tcp_reachable",    "tcp_latency_ms",
            "tls_ok",        "tls_version",      "alpn_negotiated",
            "cert_cn",       "cert_valid",       "cert_expiry",    "tls_latency_ms",
            "http_ok",       "http_status",      "http_latency_ms",
            "is_cdn",        "cdn_provider",
            "score",         "score_label",      "overall_ok",
            "stage_summary", "test_duration_ms",
            "error",         "stage_failed",
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()
            for r in results:
                writer.writerow(r.to_dict())

    # ═══════════════════════════════════════════════════════════════
    #  Last Scan Meta
    # ═══════════════════════════════════════════════════════════════

    def _save_last_scan_meta(
        self,
        parsed_config: ParsedConfig,
        stats:         Dict[str, Any],
        filepath:      str,
    ) -> None:
        """Saves lightweight metadata for the most recent scan."""
        meta = {
            "timestamp":   datetime.now().isoformat(),
            "config":      parsed_config.to_dict(),
            "stats":       stats,
            "result_file": filepath,
        }
        try:
            with open(LAST_SCAN_FILE, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def load_last_scan_meta(self) -> Optional[Dict[str, Any]]:
        """
        Loads metadata from the most recent scan.

        Returns:
            dict if file exists and valid, else None.
        """
        try:
            with open(LAST_SCAN_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None


    # ═══════════════════════════════════════════════════════════════
    #  Result Browser
    # ═══════════════════════════════════════════════════════════════

    def list_result_files(self) -> List[Dict[str, Any]]:
        """
        Lists all result files in RESULTS_DIR.

        Returns list of dicts:
            name     : filename
            path     : absolute path string
            type     : sni_scan / config_test / unknown
            fmt      : txt / json / csv
            size_kb  : file size in KB
            created  : human-readable datetime string
        """
        files: List[Dict[str, Any]] = []

        for f in sorted(
            RESULTS_DIR.glob("*.*"),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        ):
            if f.suffix not in (".txt", ".json", ".csv"):
                continue

            try:
                name = f.name

                if   name.startswith("sni_scan"):    ftype = "sni_scan"
                elif name.startswith("config_test"): ftype = "config_test"
                else:                                ftype = "unknown"

                files.append({
                    "name":    name,
                    "path":    str(f),
                    "type":    ftype,
                    "fmt":     f.suffix.lstrip("."),
                    "size_kb": round(f.stat().st_size / 1024, 2),
                    "created": datetime.fromtimestamp(
                        f.stat().st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except OSError:
                pass

        return files

    def read_result_file(self, filename: str) -> Optional[str]:
        """
        Reads and returns raw content of a result file.

        Args:
            filename : name of file inside RESULTS_DIR

        Returns:
            File content as string, or None if not found.
        """
        filepath = RESULTS_DIR / filename
        try:
            return filepath.read_text(encoding="utf-8")
        except OSError:
            return None

    def load_result_json(self, filename: str) -> Optional[Dict[str, Any]]:
        """
        Loads a JSON result file and returns parsed dict.

        Args:
            filename : name of .json file inside RESULTS_DIR

        Returns:
            Parsed dict, or None on error.
        """
        filepath = RESULTS_DIR / filename
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def delete_result_file(self, filename: str) -> bool:
        """
        Deletes a single result file by name.

        Returns:
            True  — deleted successfully
            False — file not found or permission error
        """
        filepath = RESULTS_DIR / filename
        try:
            filepath.unlink()
            return True
        except OSError:
            return False

    def clear_all_results(self) -> int:
        """
        Deletes all result files in RESULTS_DIR.
        Skips protected metadata files:
            last_scan.json · results.json

        Returns:
            Number of files deleted.
        """
        protected = {LAST_SCAN_FILE.name, RESULTS_FILE.name}
        count     = 0

        for f in RESULTS_DIR.glob("*.*"):
            if f.name in protected:
                continue
            try:
                f.unlink()
                count += 1
            except OSError:
                pass

        return count

    def prune_old_results(self, keep: int = 50) -> int:
        """
        Keeps only the N most recent result files.
        Deletes the rest (oldest first).

        Args:
            keep : number of files to keep (default 50)

        Returns:
            Number of files deleted.
        """
        files = self.list_result_files()

        if len(files) <= keep:
            return 0

        to_delete = files[keep:]
        count     = 0

        for entry in to_delete:
            try:
                Path(entry["path"]).unlink()
                count += 1
            except OSError:
                pass

        return count

    def export_all_to_zip(
        self,
        output_path: Optional[Path] = None,
    ) -> Optional[Path]:
        """
        Zips all result files into a single archive.

        Args:
            output_path : destination path
                          default: RESULTS_DIR/export_TIMESTAMP.zip

        Returns:
            Path to created zip file, or None on error.
        """
        import zipfile

        if output_path is None:
            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = RESULTS_DIR / f"export_{timestamp}.zip"

        try:
            with zipfile.ZipFile(
                output_path, "w", zipfile.ZIP_DEFLATED
            ) as zf:
                for entry in self.list_result_files():
                    zf.write(entry["path"], arcname=entry["name"])
            return output_path
        except OSError:
            return None

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns storage statistics for RESULTS_DIR.

        Keys:
            total_files   : total result file count
            sni_scans     : SNI scan file count
            config_tests  : config test file count
            total_size_kb : total disk usage in KB
        """
        files    = self.list_result_files()
        total_kb = sum(f["size_kb"] for f in files)

        return {
            "total_files":   len(files),
            "sni_scans":     sum(1 for f in files if f["type"] == "sni_scan"),
            "config_tests":  sum(1 for f in files if f["type"] == "config_test"),
            "total_size_kb": round(total_kb, 2),
        }

    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<ResultsManager "
            f"files={stats['total_files']} "
            f"size={stats['total_size_kb']}KB>"
        )


# ── BackupManager ─────────────────────────────────────────────────

class BackupManager:
    """
    Handles full project data backup and restore.

    Backup includes:
        - config.json
        - All SNI list files  (sni_lists/)
        - All result files    (results/)
        - Log file            (logs/)
        - manifest.json       (auto-generated)

    Backup format:
        ZIP archive → BACKUP_DIR/backup_YYYYMMDD_HHMMSS[_label].zip
    """

    def __init__(self):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    # ═══════════════════════════════════════════════════════════════
    #  Create
    # ═══════════════════════════════════════════════════════════════

    def create(self, label: str = "") -> Optional[Path]:
        """
        Creates a full backup ZIP archive.

        Args:
            label : optional label appended to filename
                    e.g. "before_update" → backup_20260513_143000_before_update.zip

        Returns:
            Path to created backup file, or None on error.
        """
        import zipfile

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix    = f"_{label}" if label else ""
        filename  = f"backup_{timestamp}{suffix}.zip"
        filepath  = BACKUP_DIR / filename

        try:
            with zipfile.ZipFile(
                filepath, "w", zipfile.ZIP_DEFLATED
            ) as zf:

                # ── config.json ───────────────────────────────────
                cfg_file = DATA_DIR / "config.json"
                if cfg_file.exists():
                    zf.write(cfg_file, arcname="config.json")

                # ── SNI lists ─────────────────────────────────────
                for f in SNI_LIST_DIR.glob("*.txt"):
                    zf.write(f, arcname=f"sni_lists/{f.name}")

                # ── Results ───────────────────────────────────────
                for f in RESULTS_DIR.glob("*.*"):
                    if f.suffix in (".txt", ".json", ".csv"):
                        zf.write(f, arcname=f"results/{f.name}")

                # ── Log ───────────────────────────────────────────
                if LOG_FILE.exists():
                    zf.write(LOG_FILE, arcname=f"logs/{LOG_FILE.name}")

                # ── Manifest ──────────────────────────────────────
                manifest = {
                    "created":  datetime.now().isoformat(),
                    "app":      APP_NAME,
                    "version":  VERSION,
                    "label":    label,
                    "checksum": "",          # filled after zip closes
                }
                zf.writestr(
                    "manifest.json",
                    json.dumps(manifest, indent=2),
                )

            return filepath

        except OSError:
            return None

    # ═══════════════════════════════════════════════════════════════
    #  Restore
    # ═══════════════════════════════════════════════════════════════

    def restore(
        self,
        backup_path:     Path,
        restore_config:  bool = True,
        restore_sni:     bool = True,
        restore_results: bool = False,
        restore_logs:    bool = False,
    ) -> Dict[str, Any]:
        """
        Restores data from a backup ZIP archive.

        Args:
            backup_path     : path to .zip backup file
            restore_config  : restore config.json          (default True)
            restore_sni     : restore SNI list files       (default True)
            restore_results : restore result files         (default False)
            restore_logs    : restore log files            (default False)

        Returns:
            dict:
                ok       : bool   — overall success
                restored : list   — restored file names
                skipped  : list   — skipped file names
                errors   : list   — error messages
        """
        import zipfile

        result: Dict[str, Any] = {
            "ok":       False,
            "restored": [],
            "skipped":  [],
            "errors":   [],
        }

        if not backup_path.exists():
            result["errors"].append(
                f"Backup file not found: {backup_path}"
            )
            return result

        try:
            with zipfile.ZipFile(backup_path, "r") as zf:

                for name in zf.namelist():

                    # ── Skip manifest ─────────────────────────────
                    if name == "manifest.json":
                        continue

                    # ── config.json ───────────────────────────────
                    if name == "config.json":
                        if not restore_config:
                            result["skipped"].append(name)
                            continue
                        dest = DATA_DIR / "config.json"
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(zf.read(name))
                        result["restored"].append(name)

                    # ── SNI lists ─────────────────────────────────
                    elif name.startswith("sni_lists/"):
                        if not restore_sni:
                            result["skipped"].append(name)
                            continue
                        fname = Path(name).name
                        if not fname:
                            continue
                        dest = SNI_LIST_DIR / fname
                        dest.write_bytes(zf.read(name))
                        result["restored"].append(name)

                    # ── Results ───────────────────────────────────
                    elif name.startswith("results/"):
                        if not restore_results:
                            result["skipped"].append(name)
                            continue
                        fname = Path(name).name
                        if not fname:
                            continue
                        dest = RESULTS_DIR / fname
                        dest.write_bytes(zf.read(name))
                        result["restored"].append(name)

                    # ── Logs ──────────────────────────────────────
                    elif name.startswith("logs/"):
                        if not restore_logs:
                            result["skipped"].append(name)
                            continue
                        fname = Path(name).name
                        if not fname:
                            continue
                        dest = LOGS_DIR / fname
                        dest.write_bytes(zf.read(name))
                        result["restored"].append(name)

            result["ok"] = True

        except Exception as e:
            result["errors"].append(str(e))

        return result

    # ═══════════════════════════════════════════════════════════════
    #  List & Delete
    # ═══════════════════════════════════════════════════════════════

    def list_backups(self) -> List[Dict[str, Any]]:
        """
        Lists all backup ZIP files in BACKUP_DIR.

        Returns list of dicts:
            name     : filename
            path     : absolute path string
            size_kb  : file size in KB
            created  : human-readable datetime string
            label    : label extracted from filename
        """
        backups: List[Dict[str, Any]] = []

        for f in sorted(
            BACKUP_DIR.glob("backup_*.zip"),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        ):
            try:
                # filename: backup_YYYYMMDD_HHMMSS[_label].zip
                # stem:     backup_YYYYMMDD_HHMMSS[_label]
                parts = f.stem.split("_", 3)
                #          0       1         2       3
                #        backup  YYYYMMDD  HHMMSS  label?
                label = parts[3] if len(parts) > 3 else ""

                backups.append({
                    "name":    f.name,
                    "path":    str(f),
                    "size_kb": round(f.stat().st_size / 1024, 2),
                    "created": datetime.fromtimestamp(
                        f.stat().st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "label":   label,
                })
            except OSError:
                pass

        return backups

    def delete_backup(self, filename: str) -> bool:
        """
        Deletes a backup file by name.

        Returns:
            True  — deleted successfully
            False — not found or error
        """
        filepath = BACKUP_DIR / filename
        try:
            filepath.unlink()
            return True
        except OSError:
            return False

    def prune_old_backups(self, keep: int = 5) -> int:
        """
        Keeps only the N most recent backups.
        Deletes the rest (oldest first).

        Args:
            keep : number of backups to keep (default 5)

        Returns:
            Number of backups deleted.
        """
        backups = self.list_backups()

        if len(backups) <= keep:
            return 0

        count = 0
        for b in backups[keep:]:
            if self.delete_backup(b["name"]):
                count += 1

        return count

    # ═══════════════════════════════════════════════════════════════
    #  Verify & Checksum
    # ═══════════════════════════════════════════════════════════════

    def verify_backup(self, filename: str) -> Dict[str, Any]:
        """
        Verifies integrity of a backup ZIP file.

        Checks:
            - File exists
            - Valid ZIP format
            - No corrupted entries (testzip)
            - manifest.json present

        Returns:
            dict:
                ok       : bool   — passed all checks
                files    : list   — files inside archive
                manifest : dict   — parsed manifest (if present)
                error    : str    — error message (if any)
        """
        import zipfile

        result: Dict[str, Any] = {
            "ok":       False,
            "files":    [],
            "manifest": {},
            "error":    "",
        }

        filepath = BACKUP_DIR / filename
        if not filepath.exists():
            result["error"] = f"File not found: {filename}"
            return result

        try:
            with zipfile.ZipFile(filepath, "r") as zf:

                result["files"] = zf.namelist()

                # Parse manifest
                if "manifest.json" in result["files"]:
                    try:
                        result["manifest"] = json.loads(
                            zf.read("manifest.json").decode("utf-8")
                        )
                    except (json.JSONDecodeError, KeyError):
                        result["error"] = "manifest.json is corrupted"
                        return result
                else:
                    result["error"] = "manifest.json missing"
                    return result

                # Test archive integrity
                bad_file = zf.testzip()
                if bad_file:
                    result["error"] = (
                        f"Corrupted entry in archive: {bad_file}"
                    )
                    return result

            result["ok"] = True

        except Exception as e:
            result["error"] = str(e)

        return result

    def _checksum(self, filepath: Path) -> str:
        """
        Returns MD5 checksum of a file.
        Used for backup integrity verification.
        """
        md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
        except OSError:
            pass
        return md5.hexdigest()

    # ═══════════════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════════════

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns storage statistics for BACKUP_DIR.

        Keys:
            total_backups : number of backup files
            total_size_kb : total disk usage in KB
            oldest        : datetime of oldest backup
            newest        : datetime of newest backup
        """
        backups  = self.list_backups()
        total_kb = sum(b["size_kb"] for b in backups)

        return {
            "total_backups": len(backups),
            "total_size_kb": round(total_kb, 2),
            "oldest":        backups[-1]["created"] if backups else "—",
            "newest":        backups[0]["created"]  if backups else "—",
        }

    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<BackupManager "
            f"backups={stats['total_backups']} "
            f"size={stats['total_size_kb']}KB>"
        )


# ── Global Instances ──────────────────────────────────────────────

logger          = Logger(log_file=LOG_FILE, level=config_manager.get("log_level", "INFO"))
sni_list_manager = SNIListManager()
results_manager  = ResultsManager()
backup_manager   = BackupManager()


# ── Utility Functions ─────────────────────────────────────────────

def load_sni_list(
    source:   str  = "all",
    raw_text: str  = "",
) -> List[str]:
    """
    Unified SNI list loader.

    Args:
        source   : "all" | "default" | "iran" | "custom" | "text"
        raw_text : used only when source="text"

    Returns:
        List of unique domain strings.
    """
    if   source == "default": return sni_list_manager.load_default()
    elif source == "iran":    return sni_list_manager.load_iran()
    elif source == "custom":  return sni_list_manager.load_custom()
    elif source == "text":    return sni_list_manager.load_from_text(raw_text)
    else:                     return sni_list_manager.load_all()


def save_sni_results(
    results:       List[SNIResult],
    parsed_config: ParsedConfig,
    stats:         Dict[str, Any],
    fmt:           str = "txt",
) -> Optional[Path]:
    """
    Module-level shortcut for ResultsManager.save_sni_results().

    Returns:
        Path to saved file, or None on error.
    """
    try:
        path = results_manager.save_sni_results(
            results, parsed_config, stats, fmt
        )
        logger.info(
            f"SNI results saved → {path.name} "
            f"({len(results)} entries, fmt={fmt})"
        )
        return path
    except Exception as e:
        logger.error(f"save_sni_results failed: {e}")
        return None


def save_config_results(
    results:       List[ConfigTestResult],
    parsed_config: ParsedConfig,
    summary:       Dict[str, Any],
    fmt:           str = "txt",
) -> Optional[Path]:
    """
    Module-level shortcut for ResultsManager.save_config_results().

    Returns:
        Path to saved file, or None on error.
    """
    try:
        path = results_manager.save_config_results(
            results, parsed_config, summary, fmt
        )
        logger.info(
            f"Config results saved → {path.name} "
            f"({len(results)} entries, fmt={fmt})"
        )
        return path
    except Exception as e:
        logger.error(f"save_config_results failed: {e}")
        return None


def create_backup(label: str = "") -> Optional[Path]:
    """
    Module-level shortcut for BackupManager.create().

    Returns:
        Path to backup ZIP, or None on error.
    """
    path = backup_manager.create(label=label)
    if path:
        logger.info(f"Backup created → {path.name}")
    else:
        logger.error("Backup creation failed")
    return path


def restore_backup(
    filename:        str,
    restore_config:  bool = True,
    restore_sni:     bool = True,
    restore_results: bool = False,
    restore_logs:    bool = False,
) -> Dict[str, Any]:
    """
    Module-level shortcut for BackupManager.restore().

    Args:
        filename        : backup ZIP filename inside BACKUP_DIR
        restore_config  : restore config.json
        restore_sni     : restore SNI list files
        restore_results : restore result files
        restore_logs    : restore log files

    Returns:
        Result dict from BackupManager.restore()
    """
    backup_path = BACKUP_DIR / filename
    result = backup_manager.restore(
        backup_path     = backup_path,
        restore_config  = restore_config,
        restore_sni     = restore_sni,
        restore_results = restore_results,
        restore_logs    = restore_logs,
    )

    if result["ok"]:
        logger.info(
            f"Backup restored ← {filename} "
            f"({len(result['restored'])} files)"
        )
    else:
        logger.error(
            f"Backup restore failed ← {filename}: "
            f"{'; '.join(result['errors'])}"
        )

    return result


def get_file_manager_status() -> Dict[str, Any]:
    """
    Returns a combined health/status snapshot of all managers.

    Used by UI status bar or CLI --status flag.

    Keys:
        logger         : log file info
        sni_lists      : SNI list counts
        results        : result file stats
        backups        : backup stats
        dirs_ok        : bool — all required dirs exist
    """
    dirs_ok = all(
        d.exists()
        for d in (DATA_DIR, SNI_LIST_DIR, RESULTS_DIR, LOGS_DIR, BACKUP_DIR)
    )

    return {
        "logger": {
            "file":    str(LOG_FILE),
            "level":   logger.level,
            "size_kb": logger.get_size_kb(),
        },
        "sni_lists":  sni_list_manager.get_stats(),
        "results":    results_manager.get_stats(),
        "backups":    backup_manager.get_stats(),
        "dirs_ok":    dirs_ok,
    }


def rotate_log_if_needed(max_kb: float = 512.0) -> bool:
    """
    Rotates the log file if it exceeds max_kb.

    Returns:
        True  — log was rotated
        False — rotation not needed
    """
    rotated = logger.rotate(max_kb=max_kb)
    if rotated:
        logger.info("Log file rotated automatically")
    return rotated


def cleanup_old_data(
    keep_results: int = 50,
    keep_backups: int = 5,
) -> Dict[str, int]:
    """
    Runs a full cleanup pass:
        - Prunes old result files
        - Prunes old backup files
        - Rotates log if oversized

    Args:
        keep_results : number of result files to keep
        keep_backups : number of backup files to keep

    Returns:
        dict:
            results_deleted : number of result files deleted
            backups_deleted : number of backup files deleted
            log_rotated     : 1 if log was rotated, else 0
    """
    results_deleted = results_manager.prune_old_results(keep=keep_results)
    backups_deleted = backup_manager.prune_old_backups(keep=keep_backups)
    log_rotated     = int(rotate_log_if_needed())

    logger.info(
        f"Cleanup: results={results_deleted} deleted, "
        f"backups={backups_deleted} deleted, "
        f"log_rotated={bool(log_rotated)}"
    )

    return {
        "results_deleted": results_deleted,
        "backups_deleted": backups_deleted,
        "log_rotated":     log_rotated,
    }


# ── Public Exports ────────────────────────────────────────────────

__all__ = [
    # Classes
    "Logger",
    "SNIListManager",
    "ResultsManager",
    "BackupManager",

    # Global instances
    "logger",
    "sni_list_manager",
    "results_manager",
    "backup_manager",

    # Shortcuts
    "load_sni_list",
    "save_sni_results",
    "save_config_results",
    "create_backup",
    "restore_backup",

    # Utilities
    "get_file_manager_status",
    "rotate_log_if_needed",
    "cleanup_old_data",
]