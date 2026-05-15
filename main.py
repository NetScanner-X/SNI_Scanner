#!/usr/bin/env python3
"""
SNI Scanner — Main Entry Point
Handles all menu routing, user interaction, and orchestration.
"""

from __future__ import annotations

import os
import sys
import json
import csv
import zipfile
import shutil
import uuid as uuidlib
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict

from rich.prompt import Prompt, IntPrompt

from config import config_manager, APP_NAME, VERSION, BASE_DIR, RESULTS_DIR as CFG_RESULTS_DIR, SNI_LIST_DIR as CFG_SNI_LIST_DIR, BACKUP_DIR as CFG_BACKUP_DIR
from parser import detect_and_parse, ParsedConfig
from sni_scanner import SNIScanner, SNIResult, DualModeSNIScanner, DualModeSNIResult, EnhancedSNIScanner, sort_results, filter_results, best_result
from config_tester import (
    ConfigTester,
    QuickValidator,
    BatchTester,
    SNISwitcher,
    ConfigTestResult,
    format_result,
    format_summary,
)
from ui import (
    console,
    clear_screen,
    pause,
    print_banner,
    confirm_exit,
    print_main_menu,
    print_actions_menu,
    print_section,
    print_blank,
    print_separator,
    print_success,
    print_error,
    print_warning,
    print_info,
    print_step,
    Spinner,
    BatchProgress,
    print_config_input_panel,
    prompt_config_input,
    prompt_multi_config_input,
    print_parsed_config,
    print_config_oneliner,
    print_sni_input_panel,
    prompt_sni_list_manual,
    prompt_sni_source,
    prompt_sni_file_path,
    print_sni_results,
    print_test_result,
    print_batch_results,
    print_score_bar,
    print_sni_lists_panel,
    prompt_sni_list_name,
    prompt_sni_list_select,
    print_results_browser,
    prompt_results_page,
    print_export_panel,
    prompt_export_format,
    prompt_export_path,
    print_backup_panel,
    prompt_backup_path,
    prompt_restore_path,
    print_settings_panel,
    prompt_settings_edit,
    print_help_panel,
    toast_saved,
    toast_exported,
    toast_backup_done,
    toast_restore_done,
    toast_settings_saved,
    confirm_overwrite,
    confirm_delete,
    confirm_clear_results,
    confirm_reset_settings,
    print_error_screen,
    print_not_implemented,
)


# -----------------------------------------------------------------
# App State
# -----------------------------------------------------------------

class AppState:
    """
    Holds runtime state for the current session.
    All data lives here — no globals scattered around.
    """

    def __init__(self):
        self.current_config:    Optional[ParsedConfig]      = None
        self.sni_results:       List[SNIResult]             = []
        self.test_results:      List[ConfigTestResult]      = []
        self.sni_lists:         Dict[str, List[str]]        = {}
        self.saved_results:     List[ConfigTestResult]      = []
        self.results_page:      int                         = 1
        self.results_page_size: int                         = 10

    def has_config(self) -> bool:
        return self.current_config is not None

    def has_sni_results(self) -> bool:
        return len(self.sni_results) > 0

    def has_test_results(self) -> bool:
        return len(self.test_results) > 0

    def best_sni(self) -> Optional[str]:
        ok = [r for r in self.sni_results if r.tls_ok]
        if not ok:
            return None
        ok.sort(key=lambda r: r.latency_ms if r.latency_ms else 9999)
        return ok[0].sni

    def best_result(self) -> Optional[ConfigTestResult]:
        if not self.test_results:
            return None
        return max(self.test_results, key=lambda r: r.score)


# -----------------------------------------------------------------
# Paths & Persistence
# -----------------------------------------------------------------

RESULTS_DIR        = CFG_RESULTS_DIR
SNI_LIST_DIR       = CFG_SNI_LIST_DIR
BACKUP_DIR         = CFG_BACKUP_DIR
SNI_LISTS_FILE     = SNI_LIST_DIR / "sni_lists.json"
SAVED_RESULTS_FILE = RESULTS_DIR / "saved_results.json"


def _move_files_if_any(src: Path, dst: Path) -> None:
    """Move files from a legacy folder into the canonical data folder, safely."""
    if not src.exists() or not src.is_dir():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_file():
            if not target.exists():
                shutil.move(str(item), str(target))
            else:
                # Keep both without overwriting user data.
                stamped = dst / f"{item.stem}_legacy_{datetime.now().strftime('%Y%m%d_%H%M%S')}{item.suffix}"
                shutil.move(str(item), str(stamped))
    try:
        if not any(src.iterdir()):
            src.rmdir()
    except OSError:
        pass


def _cleanup_legacy_root_dirs() -> None:
    """Unify old root-level output folders into data/.

    Canonical layout:
      data/results/
      data/sni_lists/
      data/logs/
      data/backups/

    Old root folders from previous builds are migrated if they exist, then
    removed only when empty. This preserves all previous fixes and user data.
    """
    legacy_map = {
        BASE_DIR / "results": RESULTS_DIR,
        BASE_DIR / "sni_list": SNI_LIST_DIR,
        BASE_DIR / "sni_lists": SNI_LIST_DIR,
        BASE_DIR / "logs": CFG_BACKUP_DIR.parent / "logs",
        BASE_DIR / "backup": BACKUP_DIR,
        BASE_DIR / "backups": BACKUP_DIR,
        BASE_DIR / "configs": RESULTS_DIR / "legacy_configs",
    }
    for src, dst in legacy_map.items():
        _move_files_if_any(src, dst)


def _ensure_dirs():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    SNI_LIST_DIR.mkdir(parents=True, exist_ok=True)
    _cleanup_legacy_root_dirs()


def load_sni_lists() -> Dict[str, List[str]]:
    if SNI_LISTS_FILE.exists():
        try:
            with open(SNI_LISTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_sni_lists(sni_lists: Dict[str, List[str]]):
    _ensure_dirs()
    with open(SNI_LISTS_FILE, "w", encoding="utf-8") as f:
        json.dump(sni_lists, f, indent=2, ensure_ascii=False)


def load_saved_results() -> List[Dict]:
    if SAVED_RESULTS_FILE.exists():
        try:
            with open(SAVED_RESULTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_results_to_disk(results: List[ConfigTestResult]):
    _ensure_dirs()
    data = [r.to_dict() for r in results]
    with open(SAVED_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)




def _is_cdn_config(cfg: ParsedConfig) -> bool:
    host = (getattr(cfg, "host", "") or "").strip()
    sni = (getattr(cfg, "sni", "") or "").strip()
    host_header = (getattr(cfg, "host_header", "") or "").strip()
    network = (getattr(cfg, "network", "") or "").lower()
    return bool(host_header and host_header not in (host, sni)) or network in ("ws", "h2", "http", "httpupgrade", "xhttp")

def _suggest_scanner_for_config(cfg: ParsedConfig) -> str:
    sec = (getattr(cfg, "security", "") or "").lower()
    net = (getattr(cfg, "network", "") or "").lower()
    if _is_cdn_config(cfg):
        if sec in ("tls", "reality", "xtls"):
            return "Option 1 (CDN Scanner): use Mode A/B/C for CDN/SNI edge testing."
        if net in ("ws", "http", "httpupgrade"):
            return "Option 1 (CDN Scanner): non-TLS WS/HTTP address scan (Address + Host header)."
    if sec in ("tls", "reality", "xtls"):
        return "Option 2 (SNI Scanner): use Direct/Reality SNI scan."
    return "Option 3 (Test Config): this config does not look SNI/CDN-based."

def _print_config_scan_suggestion(cfg: ParsedConfig):
    print_blank()
    print_info("Suggested scanner: " + _suggest_scanner_for_config(cfg))
    sec = (getattr(cfg, "security", "") or "").lower()
    if sec in ("tls", "reality", "xtls"):
        print_info("Mode A = candidate SNI on config IP | Mode B = candidate SNI on its own DNS IP | Mode C = candidate SNI on alternative DNS edge IPs")
    else:
        print_info("Non-TLS mode: candidate is tested as ADDRESS/front domain; original Host header/path are kept.")



def _dual_mode_pass(r: SNIResult, mode: str) -> bool:
    """Return True exactly when the requested A/B/C column is a usable OK.

    This function is used by Save/Apply, so it must match the table counters:
    B saves only rows where Mode-B passed; C saves only rows where Mode-C passed.
    A is still conservative and accepted only when the real/path check is true,
    because A-only can be a false positive in front-domain scans.
    """
    ex = r.extra or {}
    mode = (mode or "").upper()
    # Match the user-visible table/footer exactly: the footer counts modes from
    # best_mode, so Save/Apply must use the same source of truth. This prevents
    # cases like "Mode-B 21/307" but only 11 rows saved.
    best_mode = str(ex.get("best_mode", "none")).upper()
    if mode in ("A", "B", "C"):
        return mode in best_mode.split("+") or mode in best_mode
    return False


def _dual_mode_latency(r: SNIResult, mode: str) -> float:
    ex = r.extra or {}
    val = ex.get(f"mode_{mode.lower()}_latency", -1)
    try:
        val = float(val)
    except Exception:
        val = -1
    return val if val > 0 else 999999.0


def _dual_mode_ip(r: SNIResult, mode: str) -> str:
    return (r.extra or {}).get(f"mode_{mode.lower()}_ip", "") or ""


def _prompt_save_modes() -> List[str]:
    """Ask which CDN scanner modes should be saved/applied.

    A is kept available for advanced/manual use, but B/C are the reliable defaults
    for the user's CDN/front-domain workflows.
    """
    actions = {
        "b": "Mode B only — Own DNS IP (recommended)",
        "c": "Mode C only — Alternative CDN/IP",
        "bc": "Mode B + C only — recommended real passes",
        "a": "Mode A only — only if real/path check passed",
        "all": "All real modes A+B+C",
        "q": "Cancel",
    }
    choice = print_actions_menu(actions)
    if choice == "q":
        return []
    if choice == "bc":
        return ["B", "C"]
    if choice == "all":
        return ["A", "B", "C"]
    return [choice.upper()]


def _filter_dual_results_by_modes(results: List[SNIResult], modes: List[str]) -> List[SNIResult]:
    filtered = []
    wanted = [m.upper() for m in modes]
    for r in results:
        if any(_dual_mode_pass(r, m) for m in wanted):
            filtered.append(r)
    filtered.sort(key=lambda r: min((_dual_mode_latency(r, m) for m in wanted if _dual_mode_pass(r, m)), default=999999.0))
    return filtered


def _best_dual_sni_by_modes(results: List[SNIResult], modes: List[str]) -> Optional[str]:
    candidates = _filter_dual_results_by_modes(results, modes)
    return candidates[0].sni if candidates else None

def _save_selected_mode_results_to_results_dir(name: str, results: List[SNIResult], modes: List[str]) -> Path:
    """Save selected real mode results into data/results, not data/sni_lists.

    This keeps user scan outputs separate from input SNI list files. It also
    preserves which mode passed for each domain, so saved counts match the
    B/C/A summary shown on screen.
    """
    import json
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in (name or "scan_results")).strip("_") or "scan_results"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(config_manager.get("results_dir", str(RESULTS_DIR)))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe}_{'_'.join(modes)}_{stamp}.json"

    rows = []
    # Do NOT de-duplicate here: the on-screen Mode-B/Mode-C counters are row-based.
    # The same domain may pass on different resolved/edge IPs, and users expect
    # the saved count to match the table summary exactly.
    for idx, r in enumerate(results, 1):
        ex = r.extra or {}
        passed = [m for m in modes if _dual_mode_pass(r, m)]
        if not passed:
            continue
        rows.append({
            "row": idx,
            "domain": r.sni or r.domain,
            "modes": passed,
            "best_mode": ex.get("best_mode", "none"),
            "best_ip": r.ip,
            "latency_ms": r.latency_ms,
            "mode_b_ip": ex.get("mode_b_ip", ""),
            "mode_b_latency": ex.get("mode_b_latency", -1),
            "mode_c_ip": ex.get("mode_c_ip", ""),
            "mode_c_latency": ex.get("mode_c_latency", -1),
            "mode_a_ip": ex.get("mode_a_ip", ""),
            "mode_a_latency": ex.get("mode_a_latency", -1),
        })

    out_path.write_text(json.dumps({
        "name": name,
        "saved_at": stamp,
        "selected_modes": modes,
        "count": len(rows),
        "results": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    # A simple TXT companion is useful for copy/paste.
    txt_path = out_path.with_suffix(".txt")
    txt_path.write_text("\n".join(row["domain"] for row in rows if row.get("domain")), encoding="utf-8")
    return out_path


def _smart_filter_sni_results(results: List[SNIResult], max_latency_ms: float = 1500.0) -> List[SNIResult]:
    """Return user-useful results only, without changing raw scan data.

    Dual-mode: keeps reliable B/C or explicit real/path A passes; A-only fake
    results stay visible in the raw table but are filtered out here.
    Standard TLS: keeps TLS OK and path OK when path info exists.
    """
    good: List[SNIResult] = []
    for r in results:
        ex = r.extra or {}
        is_dual = "mode_a_tls" in ex
        lat = r.latency_ms if r.latency_ms and r.latency_ms > 0 else 999999.0
        if lat > max_latency_ms:
            continue
        if is_dual:
            if ex.get("reliable_pass") or ex.get("mode_b_real_ok") or ex.get("mode_c_real_ok"):
                good.append(r)
        else:
            path = ex.get("proxy_path_ok")
            if r.tls_ok and (path is True or path is None):
                good.append(r)
    good.sort(key=lambda r: r.latency_ms if r.latency_ms and r.latency_ms > 0 else 999999.0)
    return good

def _print_smart_filter_summary(results: List[SNIResult]) -> None:
    smart = _smart_filter_sni_results(results)
    removed = len(results) - len(smart)
    print_info(f"Smart Filter: {len(smart)}/{len(results)} result(s) look reliable; {removed} noisy/A-only/slow result(s) filtered from smart view.")

# -----------------------------------------------------------------
# SNI List Loader
# -----------------------------------------------------------------

def _load_sni_from_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [
                line.strip()
                for line in f
                if line.strip() and "." in line.strip()
            ]
        return lines
    except Exception as e:
        print_error(f"Could not read file: {e}")
        return []


def _collect_sni_list(state: AppState) -> List[str]:
    source = prompt_sni_source()

    if source == "manual":
        return prompt_sni_list_manual()

    if source == "file":
        path = prompt_sni_file_path()
        snis = _load_sni_from_file(path)
        print_info(f"Loaded {len(snis)} SNI(s) from file.")
        return snis

    if source == "saved":
        if not state.sni_lists:
            print_warning("No saved SNI lists found.")
            return []
        name = prompt_sni_list_select(state.sni_lists)
        if name:
            return state.sni_lists.get(name, [])
        return []

    if source == "auto":
        if not state.has_config():
            print_warning("No active config. Please enter a config first.")
            return []

        cfg = state.current_config

        sec = (getattr(cfg, "security", "") or "").lower()

        snis = []
        if sec in ("tls", "reality", "xtls"):
            # TLS configs: collect real SNI/address candidates.
            if cfg.sni:        snis.append(cfg.sni)
            if cfg.host:       snis.append(cfg.host)
            if getattr(cfg, "cdn_domain", ""): snis.append(cfg.cdn_domain)
        else:
            # Non-TLS WS/HTTP configs do not have TLS SNI. Here the candidate list
            # means ADDRESS/front domain candidates, while Host header remains unchanged.
            if cfg.host:       snis.append(cfg.host)
            if cfg.sni:        snis.append(cfg.sni)

        snis = list(dict.fromkeys([x for x in snis if x]))

        if not snis:
            print_warning("No SNI candidates found in config.")
            return []

        print_info(f"Auto-collected {len(snis)} SNI candidate(s) from config.")
        return snis

    return []

# -----------------------------------------------------------------
# Menu Handler — 1: Scan SNI List  ✅ اصلاح شد
# -----------------------------------------------------------------

def handle_scan_sni(state: AppState):
    print_section("SCAN SNI LIST")

    if not state.has_config():
        print_warning("No active config. Please enter a config first (option 4).")
        pause()
        return

    print_config_oneliner(state.current_config)
    print_blank()

    sni_list = _collect_sni_list(state)
    if not sni_list:
        print_warning("No SNI domains provided. Operation cancelled.")
        pause()
        return

    # ✅ port از config گرفته میشه
    port = int(state.current_config.port) if state.current_config.port else 443

    print_info(f"Starting SNI scan for {len(sni_list)} domain(s)...")
    print_blank()

    # Option 1 is intentionally NOT the same as option 3.
    # It performs a simple A-only SNI scan: candidate domain is used as SNI,
    # and for CDN-like configs it is tested against the config address/IP only.
    # Use option 3 when you need the dedicated CDN A/B/C scanner.
    if _is_cdn_config(state.current_config):
        print_info("CDN-like config detected. Option 1 will run A-only simple SNI scan.")
        print_info("For full A/B/C CDN logic, use option 3.")

    scan_actions = {
        "1": "Fast scan — A-only TLS",
        "2": "Deep scan — A-only TLS + HTTP/path checks",
    }
    scan_choice = print_actions_menu(scan_actions)
    scanner_cls = EnhancedSNIScanner if scan_choice == "2" else SNIScanner
    _print_retry_status()
    scanner = scanner_cls(
        parsed_config=state.current_config,
        timeout=_effective_timeout(),
        max_workers=_effective_max_workers(),
        retry=_effective_retry(),
        use_iran_dns=bool(config_manager.get("use_iran_dns", False)),
        use_cache=_effective_cache_enabled(),
        cache_ttl=_effective_cache_ttl(),
        stability_runs=_effective_stability_runs(),
    )

    with BatchProgress(total=len(sni_list), title="Scanning SNIs") as progress:
        results = scanner.scan(
            sni_list,
            port=port,
            on_result=lambda r: progress.update(host=r.sni or r.domain, ok=r.tls_ok),
        )

    state.sni_results = results

    state.sni_results.sort(
        key=lambda r: (
            0 if r.tls_ok else 1,
            r.latency_ms if r.latency_ms and r.latency_ms > 0 else 9999,
        )
    )

    print_sni_results(state.sni_results)
    _print_smart_filter_summary(state.sni_results)

    actions = {
        "f": "View Smart Filtered results only",
        "s": "Save results as SNI list",
        "a": "Apply best SNI to current config",
        "b": "Both — save and apply",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    if choice == "f":
        print_sni_results(_smart_filter_sni_results(state.sni_results))
        pause()
        return

    if choice in ("s", "b"):
        name = prompt_sni_list_name()
        ok_snis = [r.sni for r in state.sni_results if r.tls_ok and r.sni]
        if ok_snis:
            state.sni_lists[name] = ok_snis
            save_sni_lists(state.sni_lists)
            toast_saved(str(SNI_LISTS_FILE))
        else:
            print_warning("No working SNIs found to save.")

    if choice in ("a", "b"):
        best = state.best_sni()
        if best:
            state.current_config.sni = best
            print_success(f"Applied best SNI: {best}")
        else:
            print_warning("No working SNI found to apply.")

    pause()


# -----------------------------------------------------------------
# Menu Handler — 2: Test Config
# -----------------------------------------------------------------

def handle_test_config(state: AppState):
    print_section("TEST CONFIG")

    if not state.has_config():
        print_warning("No active config. Please enter a config first (option 4).")
        pause()
        return

    print_config_oneliner(state.current_config)
    print_blank()

    actions = {
        "1": "Fast config test — DNS + TCP + TLS only",
        "2": "Deep config test — DNS + TCP + TLS + HTTP/path",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)
    if choice == "q":
        return

    timeout = int(config_manager.get("timeout", 6))
    if choice == "1":
        print_info("Running fast config test: DNS + TCP + TLS only")
        runner = QuickValidator(timeout=timeout)
        with Spinner("Fast testing config..."):
            result = runner.validate(state.current_config)
    else:
        print_info("Running deep config test: DNS → TCP → TLS → HTTP/path")
        runner = ConfigTester(timeout=timeout)
        with Spinner("Deep testing config..."):
            result = runner.test(state.current_config)

    state.test_results = [result]

    print_test_result(result)
    print_score_bar(result.score)
    print_blank()

    if config_manager.get("save_results", True):
        state.saved_results.append(result)
        save_results_to_disk(state.saved_results)
        toast_saved(str(SAVED_RESULTS_FILE))

    actions = {
        "r": "Re-test with different SNI",
        "s": "Save rebuilt config to file",
        "v": "View full details",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    if choice == "r":
        sni_list = _collect_sni_list(state)
        if sni_list:
            switcher = SNISwitcher(tester=ConfigTester(timeout=timeout), max_workers=_effective_max_workers())
            print_info(f"Testing {len(sni_list)} SNI(s)...")
            print_blank()

            all_results: List[ConfigTestResult] = []

            with BatchProgress(
                total=len(sni_list),
                title="Testing SNIs",
            ) as progress:
                def _on_result(r: ConfigTestResult):
                    all_results.append(r)
                    progress.update(
                        host=r.sni or (r.config.host if r.config else "?"),
                        ok=r.overall_ok,
                    )

                switcher.run(
                    parsed_config=state.current_config,
                    sni_list=sni_list,
                    on_result=_on_result,
                )

            state.test_results = all_results
            print_batch_results(all_results)

            best = state.best_result()
            if best and best.sni:
                state.current_config.sni = best.sni
                print_success(f"Applied best SNI: {best.sni}")

            if config_manager.get("save_results", True):
                state.saved_results.extend(all_results)
                save_results_to_disk(state.saved_results)

    elif choice == "s":
        path = prompt_export_path(
            default=str(RESULTS_DIR / f"config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        )
        _export_links([result], path)

    elif choice == "v":
        console.print()
        console.print(format_result(result))
        pause()

    pause()




# -----------------------------------------------------------------
# Menu Handler — 3: CDN Scanner (Mode A/B/C)
# -----------------------------------------------------------------


def _effective_retry() -> int:
    """Global Smart Retry setting for every scanner section.
    0=Off/Fast, 1=Normal, 2=Accurate, 3=Max.
    Internal probe loops need at least one attempt, so 0 and 1 both run one attempt.
    """
    try:
        level = int(config_manager.get("smart_retry", config_manager.get("sni_retry", 1)))
    except Exception:
        level = 1
    return max(1, min(3, level if level > 0 else 1))

def _effective_timeout() -> int:
    """Timeout used by scanner sections.

    Smart Retry = 0 means Fast/Off, so it also caps per-probe timeout.
    Otherwise the user's timeout setting is used unchanged.
    """
    try:
        timeout = int(config_manager.get("timeout", 6))
    except Exception:
        timeout = 6
    try:
        level = int(config_manager.get("smart_retry", config_manager.get("sni_retry", 1)))
    except Exception:
        level = 1
    if level == 0:
        return min(timeout, 1)
    if level == 1:
        return min(timeout, 4)
    return timeout

def _effective_max_workers() -> int:
    """Worker count used globally by scanner sections.

    Fast/Off mode increases concurrency so scans do not feel stuck when many
    candidates timeout. User max_workers is still respected as the baseline.
    """
    try:
        base = int(config_manager.get("max_workers", 10))
    except Exception:
        base = 10
    try:
        level = int(config_manager.get("smart_retry", config_manager.get("sni_retry", 1)))
    except Exception:
        level = 1
    if level == 0:
        return max(base, 40)
    return max(1, base)

def _effective_stability_runs() -> int:
    try:
        return max(1, min(5, int(config_manager.get("stability_runs", 1))))
    except Exception:
        return 1

def _effective_cache_enabled() -> bool:
    try:
        return bool(config_manager.get("use_cache", True))
    except Exception:
        return True

def _effective_cache_ttl() -> int:
    try:
        return max(30, min(86400, int(config_manager.get("cache_ttl", 900))))
    except Exception:
        return 900

def _print_retry_status():
    level = int(config_manager.get("smart_retry", config_manager.get("sni_retry", 1)))
    label = {0: "Off/Fast", 1: "Normal", 2: "Accurate", 3: "Max"}.get(level, "Normal")
    cache_state = "On" if _effective_cache_enabled() else "Off"
    print_info(f"Retry: {level} ({label}) | Timeout: {_effective_timeout()}s | Workers: {_effective_max_workers()} | Cache: {cache_state} | Stability: {_effective_stability_runs()}x")

def handle_cdn_scanner(state: AppState):
    print_section("CDN SCANNER — MODE A/B/C")

    if not state.has_config():
        print_warning("No active config. Please enter a config first (option 4).")
        pause()
        return

    print_config_oneliner(state.current_config)
    _print_config_scan_suggestion(state.current_config)
    print_blank()

    sni_list = _collect_sni_list(state)
    if not sni_list:
        print_warning("No SNI domains provided. Operation cancelled.")
        pause()
        return

    port = int(state.current_config.port) if state.current_config.port else 443
    sec = (getattr(state.current_config, "security", "") or "").lower()
    print_info("Running CDN 3-mode scan:")
    if sec in ("tls", "reality", "xtls"):
        print_info("A: SNI on config IP | B: SNI on own DNS IP | C: SNI on alternative DNS/CDN edge IPs")
    else:
        print_info("Non-TLS WS/HTTP: B/C test ADDRESS/front domains with the original Host header/path; A is skipped to avoid fake OKs")
    print_blank()
    _print_retry_status()

    scanner = DualModeSNIScanner(
        parsed_config=state.current_config,
        timeout=_effective_timeout(),
        max_workers=_effective_max_workers(),
        verify_path=True,
        retry=_effective_retry(),
        use_iran_dns=bool(config_manager.get("use_iran_dns", False)),
        use_cache=_effective_cache_enabled(),
        cache_ttl=_effective_cache_ttl(),
        stability_runs=_effective_stability_runs(),
    )
    with BatchProgress(total=len(sni_list), title="Scanning SNIs") as progress:
        dual_results = scanner.run(
            sni_list,
            port=port,
            on_result=lambda r: progress.update(host=r.domain, ok=r.reliable_pass),
        )
    results = [r.to_sni_result() for r in dual_results]
    results.sort(key=lambda r: (0 if (r.extra or {}).get("best_mode") != "none" else 1, r.latency_ms if r.latency_ms and r.latency_ms > 0 else 9999))
    state.sni_results = results
    print_sni_results(results)
    _print_smart_filter_summary(results)

    actions = {
        "s": "Save by selected mode",
        "a": "Apply best by selected mode",
        "b": "Both — save and apply by selected mode",
        "f": "View Smart Filtered results only",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    selected_modes: List[str] = []
    if choice in ("s", "a", "b"):
        print_info("Choose which mode(s) should be considered valid. For normal use, choose B or B+C. A can be a false-positive.")
        selected_modes = _prompt_save_modes()
        if not selected_modes:
            print_warning("No mode selected. Operation cancelled.")
            pause()
            return

    if choice == "f":
        smart = _smart_filter_sni_results(results)
        print_sni_results(smart)
        _print_smart_filter_summary(smart)
        pause()
        return

    if choice in ("s", "b"):
        name = prompt_sni_list_name()
        filtered = _filter_dual_results_by_modes(results, selected_modes)
        ok_snis = list(dict.fromkeys([r.sni for r in filtered if r.sni]))
        if ok_snis:
            out_path = _save_selected_mode_results_to_results_dir(name, results, selected_modes)
            toast_saved(str(out_path))
            print_success(f"Saved {len(ok_snis)} real result(s) from mode(s): {', '.join(selected_modes)}")
            print_info(f"Output folder: {Path(config_manager.get('results_dir', str(RESULTS_DIR)))}")
        else:
            print_warning(f"No passing SNIs found for selected mode(s): {', '.join(selected_modes)}")

    if choice in ("a", "b"):
        best = _best_dual_sni_by_modes(results, selected_modes)
        if best:
            state.current_config.sni = best
            print_success(f"Applied best SNI from mode(s) {', '.join(selected_modes)}: {best}")
        else:
            print_warning(f"No passing SNI found for selected mode(s): {', '.join(selected_modes)}")
    pause()

# -----------------------------------------------------------------
# Legacy quick validate
# -----------------------------------------------------------------

def handle_quick_validate(state: AppState):
    print_section("QUICK VALIDATE")

    if not state.has_config():
        print_warning("No active config. Please enter a config first (option 4).")
        pause()
        return

    print_config_oneliner(state.current_config)
    print_blank()

    timeout   = int(config_manager.get("timeout", 6))
    validator = QuickValidator(timeout=timeout)

    print_info("Running quick check: DNS + TCP + TLS only (no HTTP)...")
    print_blank()

    with Spinner("Validating..."):
        result = validator.validate(state.current_config)

    print_test_result(result)
    print_score_bar(result.score)
    print_blank()

    if result.overall_ok:
        print_success("Config passed quick validation.")
    else:
        print_warning("Config failed quick validation.")

    pause()




def _prompt_manual_config() -> Optional[ParsedConfig]:
    """Build a ParsedConfig from step-by-step user input.

    This keeps all previous parsing behavior untouched, but lets users who do not
    have a full link enter the important fields manually.
    """
    console.print()
    print_info("Manual mode: enter the config/spec fields one by one.")
    print_info("Leave optional fields blank if they do not exist.")
    print_blank()

    protocol = Prompt.ask("  Protocol", choices=["vless", "vmess", "trojan", "ss", "socks", "http"], default="vless")
    host = Prompt.ask("  Address / server domain or IP", default="").strip()
    if not host:
        print_warning("Address is required.")
        return None

    port = IntPrompt.ask("  Port", default=443)
    security = Prompt.ask("  Security", choices=["none", "tls", "reality", "xtls"], default="tls").strip().lower()
    network = Prompt.ask("  Network", choices=["tcp", "ws", "http", "h2", "grpc", "xhttp", "httpupgrade"], default="tcp").strip().lower()

    user_id = ""
    if protocol in ("vless", "vmess"):
        user_id = Prompt.ask("  UUID / ID (blank = auto-generate)", default="").strip()
        if not user_id:
            user_id = str(uuidlib.uuid4())
    elif protocol in ("trojan", "ss", "socks", "http"):
        user_id = Prompt.ask("  Password / user-pass (optional)", default="").strip()

    sni = ""
    if security in ("tls", "reality", "xtls"):
        sni = Prompt.ask("  SNI / serverName", default=host).strip()
    else:
        # Non-TLS has no real TLS SNI. Keep the address as the front domain so
        # manual input behaves like parsed links, but mark it as ignored in extra.
        sni = host

    host_header = ""
    path = "/"
    grpc_service_name = ""
    if network in ("ws", "http", "httpupgrade", "xhttp", "h2"):
        host_header = Prompt.ask("  Host header", default="").strip() or None
        path = Prompt.ask("  Path", default="/").strip() or "/"
    elif network == "grpc":
        grpc_service_name = Prompt.ask("  gRPC service name", default="").strip()

    fingerprint = "chrome"
    public_key = short_id = spider_x = ""
    if security == "reality":
        fingerprint = Prompt.ask("  Fingerprint", default="chrome").strip() or "chrome"
        public_key = Prompt.ask("  Reality public key", default="").strip()
        short_id = Prompt.ask("  Reality short id", default="").strip()
        spider_x = Prompt.ask("  Reality spiderX", default="/").strip() or "/"

    name = Prompt.ask("  Name/remark", default="manual-config").strip()

    cfg = ParsedConfig(
        protocol=protocol,
        host=host,
        port=int(port),
        uuid=user_id,
        security=security,
        sni=sni,
        fingerprint=fingerprint,
        network=network,
        path=path,
        host_header=host_header,
        grpc_service_name=grpc_service_name,
        public_key=public_key,
        short_id=short_id,
        spider_x=spider_x,
        name=name,
        raw="manual-input",
        extra={"manual_input": True, "non_tls_sni_ignored": security == "none"},
    )

    if security == "none" and network in ("ws", "http", "httpupgrade", "xhttp"):
        cfg.config_type = "plain_http"
    elif host_header and host_header not in (host, sni):
        cfg.config_type = "cdn_based"
    elif security in ("tls", "reality", "xtls"):
        cfg.config_type = "direct_server"
    else:
        cfg.config_type = "manual"

    return cfg

# -----------------------------------------------------------------
# Menu Handler — 4: Enter Config
# -----------------------------------------------------------------

def handle_enter_config(state: AppState):
    print_section("ENTER CONFIG ⭐")
    print_config_input_panel()
    print_info("Start here first: paste a full config or enter specs manually, then the app suggests the right scanner.")

    actions = {
        "1": "Paste single config link",
        "2": "Enter specs manually step-by-step",
        "3": "Enter multiple configs (batch)",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    if choice == "q":
        return

    if choice == "1":
        raw = prompt_config_input()
        if not raw:
            print_warning("No input provided.")
            pause()
            return

        with Spinner("Parsing config..."):
            parsed = detect_and_parse(raw)

        if not parsed:
            print_error("Could not parse config. Check format and try again.")
            pause()
            return

        state.current_config = parsed
        print_blank()
        print_parsed_config(parsed)
        print_success("Config loaded successfully.")
        _print_config_scan_suggestion(parsed)

    elif choice == "2":
        parsed = _prompt_manual_config()
        if not parsed:
            pause()
            return
        state.current_config = parsed
        print_blank()
        print_parsed_config(parsed)
        print_success("Manual specs loaded successfully.")
        _print_config_scan_suggestion(parsed)

    elif choice == "3":
        raws = prompt_multi_config_input()
        if not raws:
            print_warning("No configs provided.")
            pause()
            return

        parsed_list: List[ParsedConfig] = []
        failed = 0

        with Spinner(f"Parsing {len(raws)} config(s)..."):
            for raw in raws:
                p = detect_and_parse(raw)
                if p:
                    parsed_list.append(p)
                else:
                    failed += 1

        print_info(
            f"Parsed: [bold green]{len(parsed_list)}[/bold green]  "
            f"Failed: [bold red]{failed}[/bold red]"
        )

        if not parsed_list:
            print_error("No valid configs found.")
            pause()
            return

        state.current_config = parsed_list[0]
        print_blank()
        print_config_oneliner(state.current_config)
        print_success(
            f"Loaded {len(parsed_list)} config(s). "
            f"First config set as active."
        )
        _print_config_scan_suggestion(state.current_config)

        if len(parsed_list) > 1:
            from rich.prompt import Confirm
            if Confirm.ask(
                f"  Run batch test on all {len(parsed_list)} configs?",
                default=True,
            ):
                _run_batch_test(state, parsed_list)
                return

    pause()


# -----------------------------------------------------------------
# Internal — Batch Test Runner
# -----------------------------------------------------------------

def _run_batch_test(
    state:   AppState,
    configs: List[ParsedConfig],
):
    timeout = int(config_manager.get("timeout", 6))
    workers = int(config_manager.get("max_workers", 10))
    tester  = ConfigTester(timeout=timeout)
    batcher = BatchTester(tester=tester, max_workers=workers)

    print_info(f"Batch testing {len(configs)} config(s)...")
    print_blank()

    all_results: List[ConfigTestResult] = []

    with BatchProgress(
        total=len(configs),
        title="Batch Testing",
    ) as progress:
        def _on_result(r: ConfigTestResult):
            all_results.append(r)
            host = r.config.host if r.config else "?"
            progress.update(host=host, ok=r.overall_ok)

        batcher.run(configs=configs, on_result=_on_result)

    state.test_results = all_results
    print_batch_results(all_results)

    if config_manager.get("save_results", True):
        state.saved_results.extend(all_results)
        save_results_to_disk(state.saved_results)
        toast_saved(str(SAVED_RESULTS_FILE))

    pause()


# -----------------------------------------------------------------
# Menu Handler — 5: Manage SNI Lists
# -----------------------------------------------------------------

def handle_manage_sni_lists(state: AppState):
    print_section("MANAGE SNI LISTS")
    print_sni_lists_panel(state.sni_lists)

    actions = {
        "1": "Create new list manually",
        "2": "Import list from file",
        "3": "View list contents",
        "4": "Rename list",
        "5": "Delete list",
        "6": "Merge two lists",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    # ── Create new list ───────────────────────────────────────
    if choice == "1":
        name = prompt_sni_list_name()
        if not name:
            print_warning("Name cannot be empty.")
            pause()
            return

        if name in state.sni_lists:
            print_warning(f"List '{name}' already exists. Choose a different name.")
            pause()
            return

        domains = prompt_sni_list_manual()
        if not domains:
            print_warning("No domains entered. List not created.")
            pause()
            return

        state.sni_lists[name] = domains
        save_sni_lists(state.sni_lists)
        print_success(f"Created list '{name}' with {len(domains)} domain(s).")

    # ── Import from file ──────────────────────────────────────
    elif choice == "2":
        path = prompt_sni_file_path()
        if not path:
            pause()
            return

        domains = _load_sni_from_file(path)
        if not domains:
            print_warning("No valid domains found in file.")
            pause()
            return

        name = prompt_sni_list_name(
            existing=Path(path).stem
        )
        if name in state.sni_lists:
            if not confirm_overwrite(name):
                pause()
                return

        state.sni_lists[name] = domains
        save_sni_lists(state.sni_lists)
        print_success(
            f"Imported {len(domains)} domain(s) into list '{name}'."
        )

    # ── View list contents ────────────────────────────────────
    elif choice == "3":
        if not state.sni_lists:
            print_warning("No SNI lists available.")
            pause()
            return

        name = prompt_sni_list_select(state.sni_lists)
        if not name:
            pause()
            return

        domains = state.sni_lists.get(name, [])
        print_blank()
        print_section(f"LIST: {name}  ({len(domains)} domains)")

        for i, d in enumerate(domains, 1):
            console.print(f"  [dim]{i:>3}.[/dim]  [cyan]{d}[/cyan]")

        print_blank()

    # ── Rename list ───────────────────────────────────────────
    elif choice == "4":
        if not state.sni_lists:
            print_warning("No SNI lists available.")
            pause()
            return

        old_name = prompt_sni_list_select(state.sni_lists)
        if not old_name:
            pause()
            return

        new_name = prompt_sni_list_name(existing=old_name)
        if not new_name or new_name == old_name:
            print_warning("No change made.")
            pause()
            return

        if new_name in state.sni_lists:
            print_warning(f"List '{new_name}' already exists.")
            pause()
            return

        state.sni_lists[new_name] = state.sni_lists.pop(old_name)
        save_sni_lists(state.sni_lists)
        print_success(f"Renamed '{old_name}' → '{new_name}'.")

    # ── Delete list ───────────────────────────────────────────
    elif choice == "5":
        if not state.sni_lists:
            print_warning("No SNI lists available.")
            pause()
            return

        name = prompt_sni_list_select(state.sni_lists)
        if not name:
            pause()
            return

        if confirm_delete(name):
            del state.sni_lists[name]
            save_sni_lists(state.sni_lists)
            print_success(f"Deleted list '{name}'.")
        else:
            print_info("Delete cancelled.")

    # ── Merge two lists ───────────────────────────────────────
    elif choice == "6":
        if len(state.sni_lists) < 2:
            print_warning("Need at least 2 lists to merge.")
            pause()
            return

        print_info("Select first list:")
        name_a = prompt_sni_list_select(state.sni_lists)
        if not name_a:
            pause()
            return

        print_info("Select second list:")
        name_b = prompt_sni_list_select(state.sni_lists)
        if not name_b or name_b == name_a:
            print_warning("Please select two different lists.")
            pause()
            return

        merged = list(dict.fromkeys(
            state.sni_lists[name_a] + state.sni_lists[name_b]
        ))
        new_name = prompt_sni_list_name(
            existing=f"{name_a}_{name_b}"
        )
        state.sni_lists[new_name] = merged
        save_sni_lists(state.sni_lists)
        print_success(
            f"Merged '{name_a}' + '{name_b}' → '{new_name}' "
            f"({len(merged)} unique domains)."
        )

    pause()


# -----------------------------------------------------------------
# Menu Handler — 6: View Results
# -----------------------------------------------------------------

def handle_view_results(state: AppState):
    print_section("VIEW RESULTS")

    all_results = state.saved_results
    if not all_results:
        print_info("No saved results yet. Run a test first.")
        pause()
        return

    print_results_browser(
        results   = all_results,
        page      = state.results_page,
        page_size = state.results_page_size,
    )

    total_pages = max(
        1,
        (len(all_results) + state.results_page_size - 1)
        // state.results_page_size,
    )

    actions = {
        "n": "Next page",
        "p": "Previous page",
        "g": "Go to page",
        "e": "Export results",
        "d": "View result details",
        "c": "Clear all results",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    if choice == "n":
        if state.results_page < total_pages:
            state.results_page += 1
        else:
            print_info("Already on last page.")
        handle_view_results(state)
        return

    elif choice == "p":
        if state.results_page > 1:
            state.results_page -= 1
        else:
            print_info("Already on first page.")
        handle_view_results(state)
        return

    elif choice == "g":
        page = prompt_results_page(
            current     = state.results_page,
            total_pages = total_pages,
        )
        state.results_page = max(1, min(page, total_pages))
        handle_view_results(state)
        return

    elif choice == "e":
        handle_export_results(state)
        return

    elif choice == "d":
        from rich.prompt import IntPrompt
        idx = IntPrompt.ask(
            "  [bold cyan]Result number to view[/bold cyan]",
            default=1,
        )
        idx = max(1, min(idx, len(all_results)))
        result = all_results[idx - 1]
        print_blank()
        console.print(format_result(result))
        pause()
        return

    elif choice == "c":
        if confirm_clear_results():
            state.saved_results  = []
            state.test_results   = []
            state.results_page   = 1
            save_results_to_disk([])
            print_success("All results cleared.")

    pause()


# -----------------------------------------------------------------
# Menu Handler — Export Results
# -----------------------------------------------------------------

def handle_export_results(state: AppState):
    print_section("EXPORT RESULTS")
    print_export_panel()

    results = state.saved_results
    if not results:
        print_warning("No results to export.")
        pause()
        return

    fmt          = prompt_export_format()
    ts           = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_path = str(RESULTS_DIR / f"export_{ts}.{fmt}")
    path         = prompt_export_path(default=default_path)

    if Path(path).exists():
        if not confirm_overwrite(path):
            print_info("Export cancelled.")
            pause()
            return

    _ensure_dirs()

    if fmt == "json":
        _export_json(results, path)
    elif fmt == "csv":
        _export_csv(results, path)
    elif fmt == "txt":
        _export_txt(results, path)
    elif fmt == "links":
        _export_links(results, path)

    toast_exported(path, fmt)
    pause()


# -----------------------------------------------------------------
# Export Helpers
# -----------------------------------------------------------------

def _export_json(results: List[ConfigTestResult], path: str):
    data = [r.to_dict() for r in results]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _export_csv(results: List[ConfigTestResult], path: str):
    if not results:
        return

    fieldnames = list(results[0].to_dict().keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = r.to_dict()
            for k, v in row.items():
                if isinstance(v, (list, dict)):
                    row[k] = json.dumps(v, ensure_ascii=False)
            writer.writerow(row)


def _export_txt(results: List[ConfigTestResult], path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(format_summary(results))


def _export_links(results: List[ConfigTestResult], path: str):
    lines = []
    for r in results:
        if r.rebuilt_config:
            lines.append(r.rebuilt_config)
        elif r.config and r.config.raw:
            lines.append(r.config.raw)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print_info(f"Exported {len(lines)} config link(s).")


# -----------------------------------------------------------------
# Menu Handler — 7: Settings
# -----------------------------------------------------------------

def handle_settings(state: AppState):
    print_section("SETTINGS")
    print_settings_panel()

    actions = {
        "e": "Edit a setting",
        "r": "Reset all to defaults",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    if choice == "e":
        changes = prompt_settings_edit()
        if changes:
            for key, value in changes.items():
                if key == "smart_retry":
                    try:
                        level = max(0, min(3, int(value)))
                    except ValueError:
                        print_warning("smart_retry must be 0, 1, 2, or 3. Keeping previous value.")
                        continue
                    # Keep retry behavior consistent across every scanner section.
                    # Internal loops need at least 1 attempt, so Off/Fast stores 1 for low-level retry values.
                    attempts = max(1, level)
                    config_manager.set("smart_retry", level)
                    config_manager.set("sni_retry", attempts)
                    config_manager.set("retry_count", attempts)
                    continue

                existing = config_manager.get(key)
                if isinstance(existing, bool):
                    value = value.lower() in ("true", "1", "yes", "on")
                elif isinstance(existing, int):
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                ok = config_manager.set(key, value)
                if not ok:
                    print_warning(f"Invalid value for {key}. No change was applied.")
            toast_settings_saved()
            print_blank()
            # Reload from disk so the screen always reflects the saved global settings.
            config_manager.reload()
            print_settings_panel()

    elif choice == "r":
        if confirm_reset_settings():
            config_manager.reset_defaults()
            toast_settings_saved()
            print_blank()
            print_settings_panel()

    pause()


# -----------------------------------------------------------------
# Menu Handler — 8: Backup & Restore
# -----------------------------------------------------------------

def handle_backup_restore(state: AppState):
    print_section("BACKUP & RESTORE")
    print_backup_panel()

    actions = {
        "1": "Create backup",
        "2": "Restore from backup",
        "q": "Back to main menu",
    }
    choice = print_actions_menu(actions)

    # ── Create backup ─────────────────────────────────────────
    if choice == "1":
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = str(BACKUP_DIR / f"backup_{ts}.zip")
        path    = prompt_backup_path(default=default)

        if Path(path).exists():
            if not confirm_overwrite(path):
                print_info("Backup cancelled.")
                pause()
                return

        _ensure_dirs()

        try:
            with Spinner("Creating backup..."):
                with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                    if SNI_LISTS_FILE.exists():
                        zf.write(SNI_LISTS_FILE, "sni_lists.json")

                    if SAVED_RESULTS_FILE.exists():
                        zf.write(SAVED_RESULTS_FILE, "saved_results.json")

                    cfg_path = Path("config.json")
                    if cfg_path.exists():
                        zf.write(cfg_path, "config.json")

                    for txt_file in RESULTS_DIR.glob("*.txt"):
                        zf.write(txt_file, f"results/{txt_file.name}")

            toast_backup_done(path)

        except Exception as e:
            print_error_screen("Backup Failed", str(e))

    # ── Restore from backup ───────────────────────────────────
    elif choice == "2":
        path = prompt_restore_path()
        if not path or not Path(path).exists():
            print_error("File not found. Check the path and try again.")
            pause()
            return

        try:
            with Spinner("Restoring backup..."):
                with zipfile.ZipFile(path, "r") as zf:
                    names = zf.namelist()

                    if "sni_lists.json" in names:
                        _ensure_dirs()
                        zf.extract("sni_lists.json", str(RESULTS_DIR))
                        state.sni_lists = load_sni_lists()

                    if "saved_results.json" in names:
                        _ensure_dirs()
                        zf.extract("saved_results.json", str(RESULTS_DIR))
                        raw = load_saved_results()
                        print_info(f"Restored {len(raw)} result record(s).")

                    if "config.json" in names:
                        zf.extract("config.json", ".")
                        config_manager.reload()

                    for name in names:
                        if name.startswith("results/") and name.endswith(".txt"):
                            zf.extract(name, ".")

            toast_restore_done()

        except zipfile.BadZipFile:
            print_error_screen(
                "Restore Failed",
                "The file is not a valid zip archive."
            )
        except Exception as e:
            print_error_screen("Restore Failed", str(e))

    pause()


# -----------------------------------------------------------------
# Menu Handler — 9: Help
# -----------------------------------------------------------------

def handle_help(state: AppState):
    print_section("HELP & GUIDE")
    print_help_panel()
    pause()


# -----------------------------------------------------------------
# Menu Handler — 10: About
# -----------------------------------------------------------------

def handle_about(state: AppState):
    print_section("ABOUT")
    print_blank()

    from rich.panel import Panel
    from rich.align import Align
    from rich.text  import Text

    lines = Text(justify="center")
    lines.append(f"{APP_NAME}\n",          style="bold cyan")
    lines.append(f"Version {VERSION}\n\n", style="bold white")
    lines.append(
        "A fast, modular proxy config tester\n"
        "with SNI scanning, TLS fingerprinting,\n"
        "and CDN-aware detection.\n\n",
        style="dim",
    )
    lines.append("Built with Python + Rich\n", style="dim cyan")
    lines.append(
        "TCP  ·  TLS  ·  HTTP  ·  SNI  ·  CDN",
        style="bold magenta",
    )

    console.print(
        Align.center(
            Panel(
                Align.center(lines),
                border_style = "cyan",
                padding      = (2, 6),
                width        = 52,
            )
        )
    )
    print_blank()
    pause()


# -----------------------------------------------------------------
# Main Menu Router
# -----------------------------------------------------------------

MENU_HANDLERS = {
    "1":  handle_cdn_scanner,
    "2":  handle_scan_sni,
    "3":  handle_test_config,
    "4":  handle_enter_config,
    "5":  handle_manage_sni_lists,
    "6":  handle_view_results,
    "7":  handle_settings,
    "8":  handle_backup_restore,
    "9":  handle_help,
    "10": handle_about,
}


def run_menu(state: AppState):
    """
    Main event loop.
    Renders menu, reads choice, dispatches to handler.
    """
    while True:
        clear_screen()
        print_banner()

        choice = print_main_menu()

        if choice == "0":
            if confirm_exit():
                clear_screen()
                console.print(
                    "\n  [bold cyan]Goodbye![/bold cyan]\n"
                )
                sys.exit(0)
            continue

        handler = MENU_HANDLERS.get(choice)
        if handler:
            clear_screen()
            try:
                handler(state)
            except KeyboardInterrupt:
                print_blank()
                print_warning("Operation cancelled by user.")
                pause()
            except Exception as e:
                print_error_screen(
                    "Unexpected Error",
                    f"{type(e).__name__}: {e}",
                )
                pause()
        else:
            print_warning("Invalid choice. Please try again.")
            pause()


# -----------------------------------------------------------------
# Startup Checks
# -----------------------------------------------------------------

def _startup_checks() -> bool:
    issues = []

    if sys.version_info < (3, 9):
        issues.append(
            f"Python 3.9+ required. "
            f"Current: {sys.version_info.major}.{sys.version_info.minor}"
        )

    try:
        _ensure_dirs()
        test_file = RESULTS_DIR / ".write_test"
        test_file.touch()
        test_file.unlink()
    except Exception:
        issues.append(
            f"Results directory not writable: {RESULTS_DIR}"
        )

    if issues:
        for issue in issues:
            print_error(f"Startup check failed: {issue}")
        return False

    return True


def _print_startup_summary(state: AppState):
    sni_count    = sum(len(v) for v in state.sni_lists.values())
    result_count = len(state.saved_results)

    print_info(
        f"Loaded  "
        f"[bold cyan]{len(state.sni_lists)}[/bold cyan] SNI list(s)  ·  "
        f"[bold cyan]{sni_count}[/bold cyan] domain(s)  ·  "
        f"[bold cyan]{result_count}[/bold cyan] saved result(s)"
    )


# -----------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------

def main():
    _ensure_dirs()
    state = AppState()

    state.sni_lists     = load_sni_lists()
    state.saved_results = []

    clear_screen()
    print_banner()

    if not _startup_checks():
        print_error("Critical startup error. Exiting.")
        sys.exit(1)

    _print_startup_summary(state)
    pause()

    run_menu(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [bold cyan]Interrupted. Goodbye![/bold cyan]\n")
        sys.exit(0)