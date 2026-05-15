# ============================================================
#  ui.py  —  Part 1 / 5
#  Imports · Console · Helpers · Status Messages · Banner
# ============================================================

import os
import sys
import time
import threading
from datetime import datetime
from typing import List, Dict, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich.rule import Rule
from rich import box

from config import (
    config_manager, VERSION, APP_NAME, APP_SUBTITLE,
    SUPPORTED_PROTOCOLS, THEME, TLS_FINGERPRINTS,
    SNI_LIST_DIR,
)
from parser import ParsedConfig, detect_and_parse, get_config_summary
from sni_scanner import SNIResult
from config_tester import ConfigTestResult

def _get_latency(r):
    """Safe latency getter for both SNIResult and DualModeSNIResult."""
    if hasattr(r, "best_latency"):
        v = r.best_latency
        return v if v and v > 0 else 9999.0
    if hasattr(r, "latency_ms"):
        v = r.latency_ms
        return v if v and v > 0 else 9999.0
    return 9999.0



# -----------------------------------------------------------------
# Console Instance
# -----------------------------------------------------------------

console = Console()


# -----------------------------------------------------------------
# Legacy Terminal Detection
# -----------------------------------------------------------------

def _is_legacy_terminal() -> bool:
    if os.name == "nt":
        if os.environ.get("WT_SESSION"):   return False
        if os.environ.get("ConEmuPID"):    return False
        if os.environ.get("TERM_PROGRAM"): return False
        return True
    return False

LEGACY = _is_legacy_terminal()


def ic(emoji: str, fallback: str = "") -> str:
    """Return emoji or fallback text for legacy terminals."""
    return fallback if LEGACY else emoji


# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "Press Enter to continue..."):
    console.print()
    console.input(f"  [dim]{msg}[/dim]")


def print_rule(title: str = "", style: str = "cyan"):
    console.print(Rule(title, style=style))


# -----------------------------------------------------------------
# Status Messages
# -----------------------------------------------------------------

def print_success(msg: str):
    console.print(f"  [bold green][ OK ][/bold green]  {msg}")

def print_error(msg: str):
    console.print(f"  [bold red][FAIL][/bold red]  {msg}")

def print_warning(msg: str):
    console.print(f"  [bold yellow][WARN][/bold yellow]  {msg}")

def print_info(msg: str):
    console.print(f"  [bold cyan][INFO][/bold cyan]  {msg}")

def print_step(step: int, total: int, msg: str):
    console.print(f"  [bold blue][{step}/{total}][/bold blue]  {msg}")


# -----------------------------------------------------------------
# Banner
# -----------------------------------------------------------------

def print_banner():
    clear_screen()

    if LEGACY:
        border_tl = border_tr = border_bl = border_br = "+"
        border_h  = "="
        border_v  = "|"
    else:
        border_tl = "╔"
        border_tr = "╗"
        border_bl = "╚"
        border_br = "╝"
        border_h  = "═"
        border_v  = "║"

    art_lines = [
        "  ███████╗███╗   ██╗██╗                                    ",
        "  ██╔════╝████╗  ██║██║                                    ",
        "  ███████╗██╔██╗ ██║██║                                    ",
        "  ╚════██║██║╚██╗██║██║                                    ",
        "  ███████║██║ ╚████║██║                                    ",
        "  ╚══════╝╚═╝  ╚═══╝╚═╝                                    ",
        "                                                           ",
        "  ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗",
        "  ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗",
        "  ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝",
        "  ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗",
        "  ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║",
        "  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝",
    ]

    content_width = max(
        max(len(line) for line in art_lines),
        len(APP_SUBTITLE) + 2,
        len(f"Version {VERSION}") + 2,
    )
    h_line = border_h * content_width

    def boxed(text: str) -> str:
        return f"{border_v}{text:<{content_width}}{border_v}"

    console.print(f"{border_tl}{h_line}{border_tr}", style="bold magenta")
    for line in art_lines:
        if "█" in line:
            console.print(boxed(line), style="bold red")
        else:
            console.print(boxed(line), style="bold magenta")

    console.print(boxed(""), style="bold magenta")
    console.print(boxed(f"  {APP_SUBTITLE}"), style="bold magenta")
    console.print(boxed(f"  Version {VERSION}"), style="bold magenta")
    console.print(f"{border_bl}{h_line}{border_br}", style="bold magenta")

    console.print(
        Align.center(
            Text(
                f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
                f"{sys.platform.upper()}  |  "
                f"Python {sys.version.split()[0]}  ",
                style="dim magenta",
            )
        )
    )
    console.print()


# -----------------------------------------------------------------
# Confirm Exit
# -----------------------------------------------------------------

def confirm_exit() -> bool:
    console.print()
    return Confirm.ask(
        "  [bold red]Are you sure you want to exit?[/bold red]",
        default=False,
    )


# ============================================================
#  ui.py  —  Part 2 / 5
#  Spinner · BatchProgress · Main Menu · Actions Menu
#  Config Input Panel · Parsed Config Display
# ============================================================

# -----------------------------------------------------------------
# Spinner Context Manager
# -----------------------------------------------------------------

class Spinner:
    def __init__(self, message: str = "Please wait..."):
        self.message   = message
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn(f"[bold cyan]{self.message}"),
            console=console,
            transient=True,
        )
        self._task = None

    def __enter__(self):
        self._progress.start()
        self._task = self._progress.add_task(self.message, total=None)
        return self

    def __exit__(self, *args):
        self._progress.stop()


# -----------------------------------------------------------------
# Batch Progress
# -----------------------------------------------------------------

class BatchProgress:
    def __init__(self, total: int, title: str = "Testing configs"):
        self.total     = total
        self.title     = title
        self._done     = 0
        self._lock     = threading.Lock()
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn(f"[bold cyan]{self.title}[/bold cyan]"),
            BarColumn(bar_width=36, style="cyan", complete_style="green"),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[status]}[/dim]"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        self._task = None

    def start(self):
        self._progress.start()
        self._task = self._progress.add_task(
            self.title,
            total=self.total,
            status="starting...",
        )

    def update(self, host: str, ok: bool):
        with self._lock:
            self._done += 1
            status = (
                f"[green]OK[/green]   {host}"
                if ok else
                f"[red]FAIL[/red] {host}"
            )
            self._progress.update(
                self._task,
                advance=1,
                status=status,
            )

    def stop(self):
        self._progress.stop()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# -----------------------------------------------------------------
# Main Menu
# -----------------------------------------------------------------

def print_main_menu() -> str:
    console.print()
    print_rule("  MAIN MENU  ")
    console.print()

    menu_items = [
        ("1", "CDN Scanner",      "Main A/B/C scanner for CDN, WS, XHTTP and front domains"),
        ("2", "SNI Scanner",      "Direct A-only SNI scan, fast/deep modes"),
        ("3", "Test Config",      "Full test + Quick check (DNS/TCP/TLS/HTTP)"),
        ("4", "⭐ Enter Config",   "START HERE: paste config or enter specs manually"),
        ("5", "Manage SNI Lists", "Add, remove, view SNI lists"),
        ("6", "View Results",     "Browse and export saved results"),
        ("7", "Settings",         "Adjust scanner settings"),
        ("8", "Backup & Restore", "Backup or restore your data"),
        ("9", "Help",             "Usage guide and tips"),
        ("0", "Exit",             "Quit the application"),
    ]

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("Key",   style="bold yellow", width=4)
    table.add_column("Title", style="bold white",  width=22)
    table.add_column("Desc",  style="dim white",   width=44)

    for key, title, desc in menu_items:
        table.add_row(f"[{key}]", title, desc)

    console.print(Align.center(table))
    console.print()

    return Prompt.ask(
        "  [bold cyan]Select option[/bold cyan]",
        choices=["0","1","2","3","4","5","6","7","8","9"],
        default="4",
    )


# -----------------------------------------------------------------
# Actions Menu
# -----------------------------------------------------------------

def print_actions_menu(choices_map: Dict[str, str]) -> str:
    """Show action choices as numbers while preserving old return keys.

    The rest of the program still receives the original action keys (s/a/b/q,
    etc.), so previous fixes and handlers stay unchanged. Users only see and
    type simple numbers.
    """
    console.print()
    print_rule("  ACTIONS  ")
    console.print()

    keys = list(choices_map.keys())
    index_to_key = {str(i): key for i, key in enumerate(keys, 1)}

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("#",      style="bold yellow", width=4, justify="right")
    table.add_column("Action", style="bold white",  width=42)

    for i, key in enumerate(keys, 1):
        label = choices_map[key]
        safe_label = "".join(c for c in label if ord(c) < 128)
        table.add_row(f"[{i}]", safe_label)

    console.print(Align.center(table))
    console.print()

    numeric_choices = list(index_to_key.keys())
    selected = Prompt.ask(
        f"  [bold cyan]Select action number[/bold cyan] [dim][{'/'.join(numeric_choices)}][/dim]",
        choices=numeric_choices,
        default=numeric_choices[-1],
    )
    return index_to_key[selected]


# -----------------------------------------------------------------
# Config Input Panel
# -----------------------------------------------------------------

def print_config_input_panel():
    console.print()
    print_rule("  ENTER CONFIG  ")
    console.print()
    console.print(
        Panel(
            "[dim]Paste your proxy config link below.\n"
            "Supported protocols: "
            + ", ".join(SUPPORTED_PROTOCOLS)
            + "\n\nExample:\n"
            "  vless://uuid@host:port?security=tls&sni=example.com#tag\n"
            "  vmess://base64...\n"
            "  trojan://password@host:port?sni=example.com\n"
            "  ss://base64@host:port#tag[/dim]",
            title="[bold cyan]Config Input[/bold cyan]",
            border_style="cyan",
            padding=(1, 3),
        )
    )
    console.print()


def prompt_config_input() -> str:
    return Prompt.ask("  [bold cyan]Config link[/bold cyan]").strip()


def prompt_multi_config_input() -> List[str]:
    console.print(
        "  [dim]Paste configs one per line. "
        "Enter blank line when done.[/dim]"
    )
    console.print()

    lines = []
    index = 1
    while True:
        line = console.input(f"  [dim cyan][{index}][/dim cyan] ").strip()
        if not line:
            break
        lines.append(line)
        index += 1

    return lines


# -----------------------------------------------------------------
# Parsed Config Display
# -----------------------------------------------------------------

def print_parsed_config(parsed: ParsedConfig):
    console.print()
    print_rule("  PARSED CONFIG  ")
    console.print()

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("Field", style="bold cyan",  width=18)
    table.add_column("Value", style="bold white", width=50)

    security_value = parsed.security or "—"
    sni_value = parsed.sni or "—"
    if (parsed.security or "").lower() == "none":
        if parsed.sni:
            sni_value = f"{parsed.sni} (front/address; TLS SNI ignored)"
        else:
            sni_value = "— (non-TLS)"

    uuid_value = parsed.uuid or "—"
    if getattr(parsed, "extra", None) and parsed.extra.get("manual_input") and parsed.uuid:
        uuid_value = f"{parsed.uuid} (auto/generated if left blank)"

    fields = [
        ("Protocol",    parsed.protocol     or "—"),
        ("Host",        parsed.host         or "—"),
        ("Port",        str(parsed.port)    if parsed.port else "—"),
        ("UUID / Pass", uuid_value),
        ("Security",    security_value),
        ("SNI",         sni_value),
        ("Host Header", parsed.host_header  or "—"),
        ("Network",     parsed.network      or "—"),
        ("Path",        parsed.path         or "—"),
        ("Fingerprint", parsed.fingerprint  or "—"),
        ("ALPN",        ", ".join(parsed.alpn) if parsed.alpn else "—"),
        ("Tag / Name",  parsed.name         or "—"),
    ]

    for field, value in fields:
        table.add_row(field, value)

    console.print(Align.center(table))
    console.print()


# -----------------------------------------------------------------
# SNI Input Panel
# -----------------------------------------------------------------

def print_sni_input_panel():
    console.print()
    print_rule("  SNI SCANNER  ")
    console.print()
    console.print(
        Panel(
            "[dim]Enter SNI domains to test against your config.\n"
            "You can enter them manually or load from a saved list.\n\n"
            "Tips:\n"
            "  - Use real CDN domains (e.g. cloudflare.com)\n"
            "  - Mix different TLDs for better coverage\n"
            "  - Avoid IP addresses as SNI values[/dim]",
            title="[bold cyan]SNI Scanner[/bold cyan]",
            border_style="cyan",
            padding=(1, 3),
        )
    )
    console.print()


def prompt_sni_list_manual() -> List[str]:
    console.print(
        "  [dim]Enter SNI domains one per line. "
        "Enter blank line when done.[/dim]"
    )
    console.print()

    sni_list = []
    index    = 1
    while True:
        line = console.input(
            f"  [dim cyan][{index}][/dim cyan] "
        ).strip()
        if not line:
            break
        if "." in line:
            sni_list.append(line)
            index += 1
        else:
            print_warning(f"Invalid domain skipped: {line}")

    return sni_list


def prompt_sni_source() -> str:
    console.print()
    return Prompt.ask(
        "  [bold cyan]SNI source[/bold cyan]",
        choices=["manual", "file", "saved", "auto"],
        default="manual",
    )


def prompt_sni_file_path() -> str:
    """Select an SNI list file from data/sni_lists or enter a custom path."""
    console.print()
    files = []
    try:
        SNI_LIST_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted([p for p in SNI_LIST_DIR.glob("*.txt") if p.is_file()], key=lambda x: x.name.lower())
    except Exception:
        files = []

    if files:
        console.print("  [bold cyan]Available SNI list files[/bold cyan]")
        for i, f in enumerate(files, 1):
            try:
                count = sum(1 for line in f.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.strip().startswith("#"))
            except Exception:
                count = 0
            console.print(f"  [dim cyan][{i}][/dim cyan] {f.name} [dim]({count} entries)[/dim]")
        console.print("  [dim cyan][0][/dim cyan] Back / Cancel")
        console.print("  [dim cyan][c][/dim cyan] Custom path")
        console.print()

        # Keep numeric UX consistent with the rest of the app.
        choices = ["0"] + [str(i) for i in range(1, len(files) + 1)] + ["c"]
        choice = Prompt.ask(
            "  [bold cyan]Select SNI file[/bold cyan]",
            choices=choices,
            default="1",
        ).strip().lower()

        if choice == "0":
            return ""
        if choice != "c":
            selected = files[int(choice) - 1]
            console.print(f"  [green]Using:[/green] {selected}")
            return str(selected)

    return Prompt.ask(
        "  [bold cyan]SNI file path[/bold cyan]"
    ).strip()


# ============================================================
#  ui.py  —  Part 3 / 5
#  print_test_result · print_batch_results
# ============================================================

# -----------------------------------------------------------------
# Test Result Table — single config
# -----------------------------------------------------------------

def print_test_result(result: ConfigTestResult):
    console.print()
    print_rule("  TEST RESULT  ")
    console.print()

    cfg   = result.config
    host  = cfg.host if cfg else "unknown"
    port  = cfg.port if cfg else 0
    proto = (cfg.protocol.upper() if cfg and cfg.protocol else "UNKNOWN")

    score_color = (
        "green"  if result.score >= 70 else
        "yellow" if result.score >= 40 else
        "red"
    )
    overall_tag = (
        "[bold green]PASS[/bold green]"
        if result.overall_ok else
        "[bold red]FAIL[/bold red]"
    )

    console.print(
        Panel(
            f"[bold white]{proto}[/bold white]  "
            f"[cyan]{host}:{port}[/cyan]\n"
            f"SNI: [yellow]{result.sni or '—'}[/yellow]   "
            f"Type: [magenta]{result.config_type}[/magenta]\n"
            f"Score: [bold {score_color}]{result.score:.1f}/100[/bold {score_color}]   "
            f"Overall: {overall_tag}   "
            f"Duration: [dim]{result.test_duration_ms:.0f}ms[/dim]",
            title="[bold cyan]Config Under Test[/bold cyan]",
            border_style="cyan",
            padding=(1, 3),
        )
    )
    console.print()

    # Stages table
    stages_table = Table(
        title="Test Stages",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
        expand=False,
        padding=(0, 2),
    )
    stages_table.add_column("Stage",   style="bold white", width=10)
    stages_table.add_column("Status",  width=8)
    stages_table.add_column("Latency", width=12)
    stages_table.add_column("Details", width=40)

    stage_rows = [
        (
            "DNS",
            result.test_stages.get("dns", "—"),
            "—",
            result.ip_resolved or "—",
        ),
        (
            "TCP",
            result.test_stages.get("tcp", "—"),
            f"{result.tcp_latency_ms:.1f}ms" if result.tcp_latency_ms > 0 else "—",
            "Connection established" if result.tcp_reachable else "Connection refused",
        ),
        (
            "TLS",
            result.test_stages.get("tls", "—"),
            f"{result.tls_latency_ms:.1f}ms" if result.tls_latency_ms > 0 else "—",
            (
                f"{result.tls_version}  "
                f"ALPN={result.alpn_negotiated or '—'}  "
                f"CN={result.cert_cn or '—'}"
            ),
        ),
        (
            "HTTP",
            result.test_stages.get("http", "—"),
            f"{result.http_latency_ms:.1f}ms" if result.http_latency_ms > 0 else "—",
            f"HTTP {result.http_status}" if result.http_status > 0 else "—",
        ),
    ]

    for stage, status, latency, details in stage_rows:
        if status == "PASS":
            status_text = "[bold green]PASS[/bold green]"
        elif status == "FAIL":
            status_text = "[bold red]FAIL[/bold red]"
        else:
            status_text = "[dim]SKIP[/dim]"

        stages_table.add_row(stage, status_text, latency, details)

    console.print(Align.center(stages_table))
    console.print()

    # Warnings
    if result.warnings:
        for w in result.warnings:
            print_warning(w)
        console.print()

    # Error
    if result.error:
        print_error(result.error)
        console.print()


# -----------------------------------------------------------------
# Batch Results Table
# -----------------------------------------------------------------

def print_batch_results(results: List[ConfigTestResult]):
    if not results:
        print_warning("No results to display.")
        return

    console.print()
    print_rule("  BATCH RESULTS  ")
    console.print()

    table = Table(
        title=f"Results — {len(results)} config(s)",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column("#",       style="dim",        width=4,  justify="right")
    table.add_column("Host",    style="bold white", width=28)
    table.add_column("Port",    style="cyan",       width=6,  justify="right")
    table.add_column("SNI",     style="yellow",     width=24)
    table.add_column("TCP",     width=6,  justify="center")
    table.add_column("TLS",     width=6,  justify="center")
    table.add_column("HTTP",    width=6,  justify="center")
    table.add_column("Score",   width=8,  justify="right")
    table.add_column("Latency", width=10, justify="right")
    table.add_column("Overall", width=8,  justify="center")

    for i, r in enumerate(results, 1):
        cfg  = r.config
        host = cfg.host if cfg else "—"
        port = str(cfg.port) if cfg and cfg.port else "—"

        def _stage(key: str) -> str:
            s = r.test_stages.get(key, "—")
            if s == "PASS": return "[green]OK[/green]"
            if s == "FAIL": return "[red]--[/red]"
            return "[dim]--[/dim]"

        score_color = (
            "green"  if r.score >= 70 else
            "yellow" if r.score >= 40 else
            "red"
        )
        overall_text = (
            "[bold green]PASS[/bold green]"
            if r.overall_ok else
            "[bold red]FAIL[/bold red]"
        )
        latency_text = (
            f"{r.tcp_latency_ms:.0f}ms"
            if r.tcp_latency_ms > 0 else "—"
        )

        table.add_row(
            str(i),
            host,
            port,
            r.sni or "—",
            _stage("tcp"),
            _stage("tls"),
            _stage("http"),
            f"[{score_color}]{r.score:.1f}[/{score_color}]",
            latency_text,
            overall_text,
        )

    console.print(table)
    console.print()

    # Stats footer
    total     = len(results)
    ok_count  = sum(1 for r in results if r.overall_ok)
    avg_score = sum(r.score for r in results) / total
    avg_lat   = [r.tcp_latency_ms for r in results if r.tcp_latency_ms > 0]
    avg_lat   = sum(avg_lat) / len(avg_lat) if avg_lat else 0

    console.print(
        f"  [bold green]Pass:[/bold green] {ok_count}/{total}   "
        f"[bold cyan]Avg Score:[/bold cyan] {avg_score:.1f}   "
        f"[bold yellow]Avg Latency:[/bold yellow] {avg_lat:.0f}ms"
    )
    console.print()


# ============================================================
#  ui.py  —  Part 4 / 5
#  print_sni_results · print_results_browser
#  Settings Panel · SNI Lists Panel
# ============================================================

# -----------------------------------------------------------------
# SNI Scan Results Table  ✅ Fixed: ip_resolved→ip, alpn_negotiated→extra
# -----------------------------------------------------------------

def print_sni_results(results: List[SNIResult]):
    if not results:
        print_warning("No SNI results to display.")
        return

    console.print()
    print_rule("  SNI SCAN RESULTS  ")
    console.print()

    # Detect if this is a dual-mode scan by checking extra fields
    is_dual = any(
        r.extra and "mode_a_tls" in r.extra
        for r in results
    )

    table = Table(
        title=f"SNI Results — {len(results)} domain(s)"
              + (" [dim](A=Config IP / B=Own IP / C=Alt IP)[/dim]" if is_dual else ""),
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
        expand=False,
        padding=(0, 1),
    )

    table.add_column("#", style="dim", width=3, justify="right", no_wrap=True)

    if is_dual:
        # Compact table: avoids right-side overflow in normal CMD/terminal widths.
        # Full IP/latency details are still saved to CSV/JSON by the save action.
        table.add_column("SNI Domain", style="bold white", width=32, overflow="ellipsis")
        table.add_column("A", width=9, justify="center", no_wrap=True)
        table.add_column("B", width=9, justify="center", no_wrap=True)
        table.add_column("C", width=9, justify="center", no_wrap=True)
        table.add_column("Best", width=8, justify="center", no_wrap=True)
        table.add_column("Best IP", style="cyan", width=15, no_wrap=True)
        table.add_column("Lat", width=8, justify="right", no_wrap=True)
    else:
        # Compact standard/SNI-scanner table for normal Windows CMD width.
        # Full cert/ALPN details remain in saved result data/logs; this keeps
        # option 2 readable without overflowing to the right.
        table.add_column("SNI Domain", style="bold white", width=28, overflow="ellipsis")
        table.add_column("IP",      style="cyan", width=15, overflow="ellipsis")
        table.add_column("TLS",     width=5,  justify="center", no_wrap=True)
        table.add_column("Ver",     width=7,  justify="center", no_wrap=True)
        table.add_column("Lat",     width=7,  justify="right", no_wrap=True)
        table.add_column("HTTP",    width=6,  justify="center", no_wrap=True)
        table.add_column("Path",    width=6,  justify="center", no_wrap=True)
        table.add_column("Sec",     width=6,  justify="center", no_wrap=True)
        table.add_column("Status",  width=8,  justify="center", no_wrap=True)

    for i, r in enumerate(results, 1):
        ex = r.extra or {}

        if is_dual:
            # ── Dual-mode row ─────────────────────────────────
            a_tls = ex.get("mode_a_tls", False)
            b_tls = ex.get("mode_b_tls", False)
            a_ip  = ex.get("mode_a_ip", "–") or "–"
            b_ip  = ex.get("mode_b_ip", "–") or "–"
            c_ip  = ex.get("mode_c_ip", "–") or "–"
            a_lat = ex.get("mode_a_latency", -1) or -1
            b_lat = ex.get("mode_b_latency", -1) or -1
            c_lat = ex.get("mode_c_latency", -1) or -1
            a_path = ex.get("mode_a_path_ok", None)
            b_path = ex.get("mode_b_path_ok", None)
            c_path = ex.get("mode_c_path_ok", None)
            c_tls = ex.get("mode_c_tls", False)
            best   = ex.get("best_mode", "none")

            def _tls_mark(ok):
                return "[bold green]OK[/bold green]" if ok else "[bold red]--[/bold red]"

            def _lat_str(ms):
                return f"{ms:.0f}ms" if ms and ms > 0 else "–"

            def _path_mark(p):
                if p is True:  return "[bold green]OK[/bold green]"
                if p is False: return "[red]FAIL[/red]"
                return "[dim]–[/dim]"

            # Combined path (either mode)
            if a_path is True or b_path is True or c_path is True:
                path_cell  = "[bold green]OK[/bold green]"
            elif a_path is False and b_path is False and c_path is False:
                path_cell  = "[red]FAIL[/red]"
            else:
                path_cell  = "[dim]–[/dim]"

            # Status
            if best != "none":
                status_cell = f"[bold green]PASS-{best}[/bold green]"
            else:
                status_cell = "[bold red]FAIL[/bold red]"

            def _mode_cell(ok, lat):
                return f"[bold green]OK[/bold green] {_lat_str(lat)}" if ok else "[red]--[/red]"

            # Pick the fastest passing mode as the visible best candidate.
            candidates = []
            if "A" in str(best): candidates.append((a_lat if a_lat and a_lat > 0 else 999999, "A", a_ip))
            if "B" in str(best): candidates.append((b_lat if b_lat and b_lat > 0 else 999999, "B", b_ip))
            if "C" in str(best): candidates.append((c_lat if c_lat and c_lat > 0 else 999999, "C", c_ip))
            if candidates:
                best_lat, best_short, best_ip = sorted(candidates, key=lambda x: x[0])[0]
                best_cell = f"[bold green]{best_short}[/bold green]"
                best_lat_cell = _lat_str(best_lat)
            else:
                best_ip, best_cell, best_lat_cell = "–", "[bold red]FAIL[/bold red]", "–"

            table.add_row(
                str(i),
                r.sni or r.domain or "–",
                _mode_cell(a_tls, a_lat),
                _mode_cell(b_tls, b_lat),
                _mode_cell(c_tls, c_lat),
                best_cell,
                best_ip,
                best_lat_cell,
            )

        else:
            # ── Standard row ──────────────────────────────────
            tls_text = (
                "[bold green]OK[/bold green]" if r.tls_ok else
                "[bold red]--[/bold red]"
            )
            ver_color = (
                "green"  if r.tls_version == "TLSv1.3" else
                "yellow" if r.tls_version == "TLSv1.2" else
                "dim"
            )
            latency_text = f"{r.latency_ms:.0f}ms" if r.latency_ms and r.latency_ms > 0 else "–"
            alpn = r.extra.get("alpn", "–") if r.extra else "–"

            http_ok = ex.get("http_ok",       None)
            path_ok = ex.get("proxy_path_ok", None)
            http_mark = (
                "[bold green]OK[/bold green]" if http_ok is True else
                "[red]FAIL[/red]"              if http_ok is False else
                "[dim]–[/dim]"
            )
            path_mark = (
                "[bold green]OK[/bold green]" if path_ok is True else
                "[red]FAIL[/red]"              if path_ok is False else
                "[dim]–[/dim]"
            )
            sec_ok = ex.get("security_ok")
            sec_note = ex.get("security_note", "")
            if sec_ok is True:
                sec_mark = "[green]OK[/green]"
            elif sec_ok is False:
                sec_mark = "[yellow]WARN[/yellow]"
            else:
                sec_mark = "[dim]–[/dim]"
            if r.tls_ok and (path_ok is True or path_ok is None):
                status_text = "[bold green]PASS[/bold green]"
            elif r.tls_ok and path_ok is False:
                status_text = "[bold yellow]TLS-ONLY[/bold yellow]"
            else:
                status_text = "[bold red]FAIL[/bold red]"

            table.add_row(
                str(i),
                r.sni or r.domain or "–",
                r.ip or "–",
                tls_text,
                f"[{ver_color}]{r.tls_version or '–'}[/{ver_color}]",
                latency_text,
                http_mark,
                path_mark,
                sec_mark,
                status_text,
            )

    console.print(table)
    console.print()

    # ── Stats footer ──────────────────────────────────────────
    total = len(results)
    if is_dual:
        a_pass = sum(1 for r in results if "A" in str((r.extra or {}).get("best_mode", "")))
        b_pass = sum(1 for r in results if "B" in str((r.extra or {}).get("best_mode", "")))
        c_pass = sum(1 for r in results if "C" in str((r.extra or {}).get("best_mode", "")))
        any_pass = sum(1 for r in results if (r.extra or {}).get("best_mode", "none") != "none")
        console.print(
            f"  [bold green]Any Pass:[/bold green] {any_pass}/{total}   "
            f"[bold cyan]Mode-A Config-IP:[/bold cyan] {a_pass}/{total}   "
            f"[bold magenta]Mode-B Own-IP:[/bold magenta] {b_pass}/{total}   "
            f"[bold green]Mode-C Alt-IP:[/bold green] {c_pass}/{total}"
        )
    else:
        path_ok_count = sum(1 for r in results if (r.extra or {}).get("proxy_path_ok") is True)
        tls_ok_count  = sum(1 for r in results if r.tls_ok)
        lats = [r.latency_ms for r in results if r.latency_ms and r.latency_ms > 0]
        avg_lat = sum(lats) / len(lats) if lats else 0
        any_path = any((r.extra or {}).get("proxy_path_ok") is not None for r in results)
        if any_path:
            console.print(
                f"  [bold green]Path OK:[/bold green] {path_ok_count}/{total}   "
                f"[bold cyan]TLS OK:[/bold cyan] {tls_ok_count}/{total}   "
                f"[bold yellow]Avg Latency:[/bold yellow] {avg_lat:.0f}ms"
            )
        else:
            console.print(
                f"  [bold green]TLS OK:[/bold green] {tls_ok_count}/{total}   "
                f"[bold yellow]Avg Latency:[/bold yellow] {avg_lat:.0f}ms"
            )
    console.print()


def print_results_browser(
    results:   List[ConfigTestResult],
    page:      int = 1,
    page_size: int = 10,
):
    if not results:
        print_info("No saved results found.")
        return

    total_pages = max(1, (len(results) + page_size - 1) // page_size)
    page        = max(1, min(page, total_pages))
    start       = (page - 1) * page_size
    end         = start + page_size
    page_items  = results[start:end]

    console.print()
    print_rule(f"  RESULTS  —  Page {page}/{total_pages}  ")
    console.print()

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column("#",       style="dim",        width=4,  justify="right")
    table.add_column("Host",    style="bold white", width=26)
    table.add_column("SNI",     style="yellow",     width=22)
    table.add_column("Type",    style="magenta",    width=14)
    table.add_column("Score",   width=8,  justify="right")
    table.add_column("Latency", width=10, justify="right")
    table.add_column("TLS",     width=10, justify="center")
    table.add_column("Overall", width=8,  justify="center")

    for i, r in enumerate(page_items, start + 1):
        cfg  = r.config
        host = cfg.host if cfg else "—"

        score_color = (
            "green"  if r.score >= 70 else
            "yellow" if r.score >= 40 else
            "red"
        )
        overall_text = (
            "[bold green]PASS[/bold green]"
            if r.overall_ok else
            "[bold red]FAIL[/bold red]"
        )
        latency_text = (
            f"{r.tcp_latency_ms:.0f}ms"
            if r.tcp_latency_ms > 0 else "—"
        )

        # ✅ Fix 3: safe access — tls_version may not exist on ConfigTestResult
        tls_text = getattr(r, "tls_version", None) or ("OK" if r.tls_ok else "—")

        table.add_row(
            str(i),
            host,
            r.sni         or "—",
            r.config_type or "—",
            f"[{score_color}]{r.score:.1f}[/{score_color}]",
            latency_text,
            tls_text,
            overall_text,
        )

    console.print(table)
    console.print()
    console.print(
        f"  [dim]Page {page}/{total_pages}  —  "
        f"{len(results)} total result(s)[/dim]"
    )
    console.print()


def prompt_results_page(current: int, total_pages: int) -> int:
    console.print(
        f"  [dim]Current page: {current}/{total_pages}[/dim]"
    )
    return IntPrompt.ask(
        "  [bold cyan]Go to page[/bold cyan]",
        default=current,
    )


# -----------------------------------------------------------------
# Settings Panel
# -----------------------------------------------------------------

def print_settings_panel():
    console.print()
    print_rule("  SETTINGS  ")
    console.print()

    cfg = config_manager

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("Key",   style="bold cyan",  width=28)
    table.add_column("Value", style="bold white", width=30)
    table.add_column("Desc",  style="dim",        width=36)

    smart_retry = int(cfg.get("smart_retry", cfg.get("sni_retry", 1)))
    retry_label = {0: "Off/Fast", 1: "Normal", 2: "Accurate", 3: "Max"}.get(smart_retry, "Normal")

    rows = [
        ("timeout",         str(cfg.get("timeout", 6)),           "Connection timeout (seconds)"),
        ("smart_retry",     f"{smart_retry} ({retry_label})",       "Global retry: 0 Off, 1 Normal, 2 Accurate, 3 Max"),
        ("use_cache",       str(cfg.get("use_cache", True)),        "Reuse recent probe results"),
        ("cache_ttl",       str(cfg.get("cache_ttl", 900)),         "Cache lifetime (seconds)"),
        ("stability_runs",  str(cfg.get("stability_runs", 1)),      "1 off, 2-5 repeat probes"),
        ("max_workers",     str(cfg.get("max_workers", 10)),       "Parallel threads for batch test"),
        ("tls_fingerprint", cfg.get("tls_fingerprint", "chrome"),  "TLS client fingerprint"),
        ("use_iran_dns",    str(cfg.get("use_iran_dns", False)),   "Use Iran-based DNS resolvers"),
        ("save_results",    str(cfg.get("save_results", True)),    "Auto-save test results"),
        ("results_dir",     cfg.get("results_dir", "./results"),   "Directory for saved results"),
        ("log_level",       cfg.get("log_level", "INFO"),          "Logging verbosity level"),
        ("auto_rebuild",    str(cfg.get("auto_rebuild", True)),    "Auto-rebuild config with best SNI"),
        ("show_cert_info",  str(cfg.get("show_cert_info", True)),  "Display certificate details"),
        ("theme",           cfg.get("theme", "default"),           "UI color theme"),
    ]

    for key, value, desc in rows:
        table.add_row(key, value, desc)

    console.print(Align.center(table))
    console.print()


def prompt_settings_edit() -> Dict[str, str]:
    """User-friendly settings editor.

    Older builds asked for a raw "setting key". That was confusing and also allowed
    users to type values such as "3" as a fake key. This menu maps a number to the
    real config key, validates common choices, and returns only known keys.
    """
    editable = [
        ("smart_retry", "Smart Retry", "0 Off/Fast, 1 Normal, 2 Accurate, 3 Max"),
        ("use_cache", "Use Cache", "true/false, speeds repeated scans"),
        ("cache_ttl", "Cache TTL", "seconds, 30-86400"),
        ("stability_runs", "Stability Runs", "1 off/fast, 2-5 repeat probes"),
        ("timeout", "Timeout", "seconds, 1-60"),
        ("max_workers", "Max Workers", "parallel threads, 1-200"),
        ("tls_fingerprint", "TLS Fingerprint", "chrome/firefox/safari/edge"),
        ("use_iran_dns", "Use Iran DNS", "true/false"),
        ("save_results", "Save Results", "true/false"),
        ("show_cert_info", "Show Cert Info", "true/false"),
        ("auto_rebuild", "Auto Rebuild", "true/false"),
        ("log_level", "Log Level", "DEBUG/INFO/WARNING/ERROR"),
        ("theme", "Theme", "default"),
    ]

    console.print("  [dim]Choose a setting number, or press Enter to cancel.[/dim]")
    console.print("  [dim]Smart Retry is global and applies to all scanner sections.[/dim]")
    console.print()

    menu = Table(show_header=True, box=box.SIMPLE, padding=(0, 2), expand=False)
    menu.add_column("#", style="bold cyan", justify="right", width=3)
    menu.add_column("Setting", style="bold white", width=20)
    menu.add_column("Key", style="cyan", width=18)
    menu.add_column("Hint", style="dim", width=42)
    for i, (key, label, hint) in enumerate(editable, 1):
        menu.add_row(str(i), label, key, hint)
    console.print(Align.center(menu))
    console.print()

    choice = Prompt.ask("  [bold cyan]Setting number[/bold cyan]", default="").strip()
    if not choice:
        return {}

    # Accept either a menu number or the real key for advanced users.
    selected_key = None
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(editable):
            selected_key = editable[idx - 1][0]
    else:
        valid_keys = {k for k, _, _ in editable}
        if choice in valid_keys:
            selected_key = choice

    if not selected_key:
        print_warning("Invalid setting selection. No changes were made.")
        return {}

    current = config_manager.get(selected_key)
    if selected_key == "smart_retry":
        console.print("  [dim]0=Off/Fast, 1=Normal, 2=Accurate, 3=Max[/dim]")
    elif selected_key == "stability_runs":
        console.print("  [dim]1 disables stability repeat. 2-5 repeats probes for more reliable results but takes longer.[/dim]")
    elif selected_key == "cache_ttl":
        console.print("  [dim]Cache lifetime in seconds. Use a smaller value if your network changes often.[/dim]")
    elif isinstance(current, bool):
        console.print("  [dim]Use true/false, yes/no, or 1/0[/dim]")

    value = Prompt.ask(
        f"  [bold cyan]New value for[/bold cyan] [yellow]{selected_key}[/yellow] "
        f"[dim](current: {current})[/dim]"
    ).strip()
    if value == "":
        return {}

    return {selected_key: value}


# -----------------------------------------------------------------
# Manage SNI Lists Panel
# -----------------------------------------------------------------

def print_sni_lists_panel(sni_lists: Dict[str, List[str]]):
    console.print()
    print_rule("  SNI LISTS  ")
    console.print()

    if not sni_lists:
        print_info("No SNI lists saved yet.")
        console.print()
        return

    table = Table(
        title="Saved SNI Lists",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
        expand=False,
        padding=(0, 2),
    )
    table.add_column("#",       style="dim",        width=4,  justify="right")
    table.add_column("Name",    style="bold white", width=24)
    table.add_column("Count",   style="cyan",       width=8,  justify="right")
    table.add_column("Preview", style="dim",        width=44)

    for i, (name, domains) in enumerate(sni_lists.items(), 1):
        preview = ", ".join(domains[:3])
        if len(domains) > 3:
            preview += f", ... (+{len(domains) - 3} more)"
        table.add_row(str(i), name, str(len(domains)), preview)

    console.print(Align.center(table))
    console.print()


def prompt_sni_list_name(existing: Optional[str] = None) -> str:
    default = existing or "my_sni_list"
    return Prompt.ask(
        "  [bold cyan]List name[/bold cyan]",
        default=default,
    ).strip()


def prompt_sni_list_select(sni_lists: Dict[str, List[str]]) -> Optional[str]:
    if not sni_lists:
        print_warning("No SNI lists available.")
        return None

    names = list(sni_lists.keys())
    console.print(
        "  [dim]Available lists: "
        + ", ".join(f"[yellow]{n}[/yellow]" for n in names)
        + "[/dim]"
    )
    console.print()

    choice = Prompt.ask(
        "  [bold cyan]Select list name[/bold cyan]",
        choices=names,
        default=names[0],
    )
    return choice


# ============================================================
#  ui.py  —  Part 5 / 5
#  Export · Backup & Restore · Help · Toasts
#  Inline Helpers · Confirm Prompts · Error Screens · __all__
# ============================================================

# -----------------------------------------------------------------
# Export Panel
# -----------------------------------------------------------------

def print_export_panel():
    console.print()
    print_rule("  EXPORT RESULTS  ")
    console.print()
    console.print(
        Panel(
            "[dim]Export your test results to a file.\n\n"
            "Supported formats:\n"
            "  json  — Full structured data\n"
            "  csv   — Spreadsheet-compatible\n"
            "  txt   — Human-readable plain text\n"
            "  links — Config links only (working configs)[/dim]",
            title="[bold cyan]Export[/bold cyan]",
            border_style="cyan",
            padding=(1, 3),
        )
    )
    console.print()


def prompt_export_format() -> str:
    return Prompt.ask(
        "  [bold cyan]Export format[/bold cyan]",
        choices=["json", "csv", "txt", "links"],
        default="json",
    )


def prompt_export_path(default: str = "./results/export") -> str:
    return Prompt.ask(
        "  [bold cyan]Output file path[/bold cyan]",
        default=default,
    ).strip()


# -----------------------------------------------------------------
# Backup & Restore Panel
# -----------------------------------------------------------------

def print_backup_panel():
    console.print()
    print_rule("  BACKUP & RESTORE  ")
    console.print()
    console.print(
        Panel(
            "[dim]Backup or restore your SNI lists, configs, "
            "and settings.\n\n"
            "Backup saves everything to a single .zip file.\n"
            "Restore loads from a previously saved backup.[/dim]",
            title="[bold cyan]Backup & Restore[/bold cyan]",
            border_style="cyan",
            padding=(1, 3),
        )
    )
    console.print()


def prompt_backup_path(default: str = "./backup") -> str:
    return Prompt.ask(
        "  [bold cyan]Backup directory[/bold cyan]",
        default=default,
    ).strip()


def prompt_restore_path() -> str:
    return Prompt.ask(
        "  [bold cyan]Restore file path (.zip)[/bold cyan]"
    ).strip()


# -----------------------------------------------------------------
# Help Panel
# -----------------------------------------------------------------

def print_help_panel():
    console.print()
    print_rule("  HELP & GUIDE  ")
    console.print()

    sections = [
        (
            "Getting Started",
            [
                "Start from option 4 (*) to paste a config or enter specs manually",
                "The app detects config type and suggests the best scanner",
                "Use option 1 for CDN / WS / HTTP address + host checks",
                "Use option 2 for simple TLS/SNI checks only",
                "Use option 3 for multiple configs / batch workflow",
            ],
        ),
        (
            "Config Formats",
            [
                "vless://uuid@host:port?security=tls&sni=x.com#tag",
                "vmess://base64encodedJSON",
                "trojan://password@host:port?sni=x.com#tag",
                "ss://base64@host:port#tag",
                "Manual specs are also supported when no full link exists",
            ],
        ),
        (
            "Scanner Modes",
            [
                "Mode A: test candidate on the config/front address",
                "Mode B: test candidate on its own DNS IP",
                "Mode C: test candidate on alternative CDN/edge IPs",
                "A-only results are treated as weak/fake and are not saved by default",
                "Save results by selected mode: B, C, or B+C",
            ],
        ),
        (
            "Smart Detection",
            [
                "Non-TLS WS/HTTP configs use address + Host header logic",
                "SNI is ignored for security=none because there is no TLS SNI",
                "Manual input auto-generates UUID/ID when left empty",
                "Wrong scanner choices are corrected when possible",
            ],
        ),
        (
            "Real Connection Test",
            [
                "WS/HTTP configs are checked with real Host + Path requests",
                "TLS configs are checked with real TLS handshake",
                "Smart retry runs unstable checks again and keeps the best attempt",
                "Change smart_retry in Settings: 0 Off, 1 Normal, 2 Accurate, 3 Max",
                "TCP + non-TLS can only confirm basic reachability",
                "Live scan progress is shown while each domain is tested",
            ],
        ),
        (
            "Smart Filter & Security",
            [
                "Smart Filter hides noisy A-only, slow, or non-real results",
                "TLS security check marks legacy TLS, weak ciphers, or expired certs",
                "Raw results are still visible; filtering does not delete data",
                "Use Smart Filter before saving/sharing final results",
            ],
        ),
        (
            "SNI Tips",
            [
                "For CDN configs: SNI/domain and Host header may be different",
                "For direct TLS configs: SNI usually equals the server hostname",
                "For non-TLS configs: focus on Address, Host Header, Port and Path",
                "Prefer B or C results for real usable candidates",
            ],
        ),
        (
            "Score Guide",
            [
                "100 = Fully working / best candidate",
                "70+ = Good and likely usable",
                "40+ = Partial or unstable",
                "0 = Dead / connection failed",
            ],
        ),
        (
            "Keyboard Shortcuts",
            [
                "Enter    — Confirm / select default option",
                "Ctrl+C   — Cancel current operation",
                "0 / q    — Exit or go back from menus",
            ],
        ),
    ]

    for title, items in sections:
        console.print(
            Panel(
                "\n".join(f"  {ic('•', '-')} {item}" for item in items),
                title=f"[bold cyan]{title}[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
                expand=False,
            )
        )
        console.print()


# -----------------------------------------------------------------
# Notification Toasts
# -----------------------------------------------------------------

def toast_saved(path: str):
    console.print()
    print_success(f"Results saved to: [bold white]{path}[/bold white]")
    console.print()


def toast_exported(path: str, fmt: str):
    console.print()
    print_success(
        f"Exported as [bold yellow]{fmt.upper()}[/bold yellow] "
        f"to: [bold white]{path}[/bold white]"
    )
    console.print()


def toast_backup_done(path: str):
    console.print()
    print_success(f"Backup saved to: [bold white]{path}[/bold white]")
    console.print()


def toast_restore_done():
    console.print()
    print_success("Restore completed successfully.")
    console.print()


def toast_config_copied():
    console.print()
    print_success("Config link copied to clipboard.")
    console.print()


def toast_settings_saved():
    console.print()
    print_success("Settings saved successfully.")
    console.print()


# -----------------------------------------------------------------
# Inline Config Summary (one-liner)
# -----------------------------------------------------------------

def print_config_oneliner(parsed: ParsedConfig):
    proto = (parsed.protocol.upper() if parsed.protocol else "?")
    host  = parsed.host  or "?"
    port  = parsed.port  or 0
    sni   = parsed.sni   or "—"
    sec   = parsed.security or "—"

    console.print(
        f"  [bold cyan]{proto}[/bold cyan]  "
        f"[white]{host}[/white]:[yellow]{port}[/yellow]  "
        f"SNI=[green]{sni}[/green]  "
        f"Security=[magenta]{sec}[/magenta]"
    )


# -----------------------------------------------------------------
# Score Bar (inline visual)
# -----------------------------------------------------------------

def print_score_bar(score: float, width: int = 30):
    filled = int((score / 100.0) * width)
    empty  = width - filled

    color = (
        "green"  if score >= 70 else
        "yellow" if score >= 40 else
        "red"
    )

    bar = (
        f"[{color}]"
        + ("█" * filled if not LEGACY else "#" * filled)
        + "[/]"
        + "[dim]"
        + ("░" * empty if not LEGACY else "." * empty)
        + "[/dim]"
    )

    console.print(
        f"  Score  [{bar}]  "
        f"[bold {color}]{score:.1f}/100[/bold {color}]"
    )


# -----------------------------------------------------------------
# Divider Helpers
# -----------------------------------------------------------------

def print_section(title: str):
    console.print()
    print_rule(f"  {title}  ", style="bold cyan")
    console.print()


def print_blank():
    console.print()


def print_separator():
    console.print("[dim]" + "─" * 55 + "[/dim]")


# -----------------------------------------------------------------
# Confirm Prompts
# -----------------------------------------------------------------

def confirm_overwrite(path: str) -> bool:
    return Confirm.ask(
        f"  [bold yellow]File already exists:[/bold yellow] "
        f"[white]{path}[/white]\n"
        f"  Overwrite?",
        default=False,
    )


def confirm_delete(name: str) -> bool:
    return Confirm.ask(
        f"  [bold red]Delete[/bold red] [white]{name}[/white]?",
        default=False,
    )


def confirm_clear_results() -> bool:
    return Confirm.ask(
        "  [bold red]Clear ALL saved results?[/bold red] "
        "This cannot be undone.",
        default=False,
    )


def confirm_reset_settings() -> bool:
    return Confirm.ask(
        "  [bold red]Reset ALL settings to defaults?[/bold red]",
        default=False,
    )


# -----------------------------------------------------------------
# Error Screens
# -----------------------------------------------------------------

def print_error_screen(title: str, detail: str):
    console.print()
    console.print(
        Panel(
            f"[bold red]{title}[/bold red]\n\n"
            f"[dim]{detail}[/dim]",
            title="[bold red]Error[/bold red]",
            border_style="red",
            padding=(1, 3),
        )
    )
    console.print()


def print_not_implemented():
    console.print()
    console.print(
        Panel(
            "[bold yellow]This feature is not implemented yet.[/bold yellow]\n"
            "[dim]Check back in a future version.[/dim]",
            title="[bold yellow]Coming Soon[/bold yellow]",
            border_style="yellow",
            padding=(1, 3),
        )
    )
    console.print()


# -----------------------------------------------------------------
# __all__ — public API
# -----------------------------------------------------------------

__all__ = [
    # Console
    "console",
    "clear_screen",
    "pause",
    "print_rule",
    "print_blank",
    "print_separator",
    "print_section",

    # Status
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_step",

    # Banner & Menus
    "print_banner",
    "confirm_exit",
    "print_main_menu",
    "print_actions_menu",

    # Spinner & Progress
    "Spinner",
    "BatchProgress",

    # Config
    "print_config_input_panel",
    "prompt_config_input",
    "prompt_multi_config_input",
    "print_parsed_config",
    "print_config_oneliner",

    # SNI
    "print_sni_input_panel",
    "prompt_sni_list_manual",
    "prompt_sni_source",
    "prompt_sni_file_path",
    "print_sni_results",

    # Test Results
    "print_test_result",
    "print_batch_results",
    "print_score_bar",

    # SNI Lists
    "print_sni_lists_panel",
    "prompt_sni_list_name",
    "prompt_sni_list_select",

    # Results Browser
    "print_results_browser",
    "prompt_results_page",

    # Export
    "print_export_panel",
    "prompt_export_format",
    "prompt_export_path",

    # Backup
    "print_backup_panel",
    "prompt_backup_path",
    "prompt_restore_path",

    # Settings
    "print_settings_panel",
    "prompt_settings_edit",

    # Help
    "print_help_panel",

    # Toasts
    "toast_saved",
    "toast_exported",
    "toast_backup_done",
    "toast_restore_done",
    "toast_config_copied",
    "toast_settings_saved",

    # Confirms
    "confirm_overwrite",
    "confirm_delete",
    "confirm_clear_results",
    "confirm_reset_settings",

    # Errors
    "print_error_screen",
    "print_not_implemented",
]