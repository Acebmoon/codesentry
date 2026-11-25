# menu_ui.py
# Interactive terminal menu (banner + numbered options). Opens when codesentry runs with no arguments.

import os
import shutil
import sys
from typing import Callable, List, Optional, Sequence

from . import __version__
from .scan_engine import scan, SkippedFile, Finding
from .rules_db import SEVERITY_ORDER
from .history_scan import scan_history, is_git_repo, HistoryError
from .deps_check import check_deps, find_manifests, DepsError
from .report_output import as_json
from .repo_fetch import (is_repo_url, scan_repo, RepoError, parse_repo_url, download_path,
                         downloads_dir, list_downloads, delete_download, delete_all_downloads)

RED, YELLOW, CYAN, GREEN, DIM, RESET = "\033[91m", "\033[93m", "\033[96m", "\033[92m", "\033[2m", "\033[0m"
SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}

_FONT = {
    "C": [" ████", "█    ", "█    ", "█    ", " ████"],
    "O": [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    "D": ["████ ", "█   █", "█   █", "█   █", "████ "],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "S": [" ████", "█    ", " ███ ", "    █", "████ "],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "T": ["█████", "  █  ", "  █  ", "  █  ", "  █  "],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "Y": ["█   █", " █ █ ", "  █  ", "  █  ", "  █  "],
}


MAIN = "\033[38;5;203m"    # coral red, letter body
SHADOW = "\033[38;5;88m"   # dark red, outline/shadow


def _word_rows(word: str, scale: int = 2):
    """Big block letters: each pixel is `scale` columns wide, plus a shadow offset one cell down-right."""
    base = [" ".join(_FONT[ch][i] for ch in word) for i in range(5)]
    h, w = len(base) + 1, len(base[0]) * scale + 2
    grid = [[(" ", "") for _ in range(w)] for _ in range(h)]
    for y, row in enumerate(base):
        for x, c in enumerate(row):
            if c != " ":
                for k in range(scale):
                    grid[y + 1][x * scale + k + 1] = ("▒", SHADOW)
    for y, row in enumerate(base):
        for x, c in enumerate(row):
            if c != " ":
                for k in range(scale):
                    grid[y][x * scale + k] = ("█", MAIN)
    return ["".join(f"{col}{ch}{RESET}" if col else ch for ch, col in line).rstrip() for line in grid]


def banner() -> str:
    """CODE / SENTRY in big outlined pixel letters (fits an 80-column terminal)."""
    lines = _word_rows("CODE") + _word_rows("SENTRY")
    return "\n".join(lines)


def _setup_console() -> None:
    """Make colors and block characters work in cmd.exe / PowerShell."""
    if os.name == "nt":
        os.system("")  # codesentry:ignore[CS-INJ-002] constant empty command, enables ANSI colors
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _clean_path(raw: str) -> str:
    """Drag-and-drop adds quotes around paths; strip them."""
    return raw.strip().strip('"').strip("'")


def _clear_screen() -> None:
    sys.stdout.write("\033[2J\033[3J\033[H")
    sys.stdout.flush()


def _per_page() -> int:
    rows = shutil.get_terminal_size((80, 24)).lines
    return max(1, (rows - 11) // 5)        # each finding takes 5 lines, the frame about 11


_FILTERS = {"h": "HIGH", "m": "MEDIUM", "l": "LOW"}


def results_screen(findings: List[Finding], skipped: List[SkippedFile], input_fn, out,
                   clear: Callable[[], None] = lambda: None, notes: Sequence[str] = ()) -> None:
    """Results in their own screen: pages, a severity filter, save and Back."""
    only: Optional[str] = None
    page = 0
    size = _per_page()
    while True:
        shown = [f for f in findings if only is None or f.severity == only]
        pages = max(1, -(-len(shown) // size))
        page = min(page, pages - 1)
        clear()
        out(f"{RED}CODESENTRY{RESET} {DIM}>{RESET} RESULTS")
        out(f"{DIM}{'-' * 60}{RESET}")
        counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEV_COLOR}
        out(f"Total: {len(findings)} | {RED}HIGH: {counts['HIGH']}{RESET} | "
            f"{YELLOW}MEDIUM: {counts['MEDIUM']}{RESET} | {CYAN}LOW: {counts['LOW']}{RESET}"
            + (f"   {DIM}(showing {only}){RESET}" if only else ""))
        if not findings:
            out(f"\n{GREEN}No issues found.{RESET}")
        elif not shown:
            out(f"\n{YELLOW}No {only} findings.{RESET}")
        for i, f in enumerate(shown[page * size:(page + 1) * size], page * size + 1):
            color = SEV_COLOR.get(f.severity, "")
            out(f"\n{DIM}{i:>3}{RESET} {color}[{f.severity}]{RESET} {f.rule_id}  {f.file}:{f.line}")
            out(f"    {f.name} ({f.cwe})")
            out(f"    {DIM}> {f.snippet}{RESET}")
            out(f"    fix: {f.fix}")
        if page == pages - 1:
            for sk in skipped:
                out(f"{DIM}skipped {sk.file}: {sk.reason}{RESET}")
            for note in notes:
                out(f"{DIM}{note}{RESET}")
        out(f"\n{DIM}{'-' * 60}{RESET}")
        out(f"Page {page + 1}/{pages}   [N]ext  [P]rev  [H]igh  [M]edium  [L]ow  [A]ll  [S]ave JSON  [B]ack")
        try:
            cmd = input_fn("[+] Command: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if cmd in ("b", "back", "q"):
            return
        if cmd in ("", "n", "next"):
            page = min(page + 1, pages - 1)
        elif cmd in ("p", "prev"):
            page = max(page - 1, 0)
        elif cmd in _FILTERS:
            only, page = _FILTERS[cmd], 0
        elif cmd in ("a", "all"):
            only, page = None, 0
        elif cmd in ("s", "save"):
            target = _clean_path(input_fn("[+] Save as (default: codesentry-report.json): ")) \
                or "codesentry-report.json"
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(as_json(findings) + "\n")
            out(f"\n{GREEN}Saved to {os.path.abspath(target)}{RESET}")
            input_fn("[Enter to continue] ")


def _size(n: int) -> str:
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} MB"


def _manage_downloads(input_fn, out) -> None:
    while True:
        items = list_downloads()
        out("")
        if not items:
            out("No downloaded repos.")
            return
        out(f"Downloaded repos in {downloads_dir()}:")
        for i, (name, size) in enumerate(items, 1):
            out(f"  [{i}] {name.replace('__', '/', 1)}  ({_size(size)})")
        out("  [a] Delete all")
        out("  [Enter] Back\n")
        try:
            pick = input_fn("[+] Delete which? ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if not pick:
            return
        if pick == "a":
            out(f"\n{GREEN}Deleted {delete_all_downloads()} download(s).{RESET}")
        elif pick.isdigit() and 1 <= int(pick) <= len(items):
            delete_download(items[int(pick) - 1][0])
            out(f"\n{GREEN}Deleted.{RESET}")
        else:
            out(f"\n{YELLOW}Invalid option.{RESET}")


def _ask_deps(input_fn) -> bool:
    return input_fn("[+] Also check dependencies online (OSV.dev)? [Y/n]: ").strip().lower() != "n"


def run_menu(input_fn: Callable[[str], str] = input,
             out: Callable[[str], None] = print,
             clear: Callable[[], None] = lambda: None) -> int:
    last: Optional[List[Finding]] = None
    last_skipped: List[SkippedFile] = []
    clear()
    while True:
        out("")
        out(banner())
        out(f"\n{RED}   STATIC CODE SCANNER  v{__version__}{RESET}\n")
        out("[1] Start Scan")
        out("[2] Scan GitHub repo")
        out("[3] View last results")
        out("[4] Save last report (JSON)")
        out("[5] Downloaded repos")
        out("[6] Exit\n")
        try:
            choice = input_fn("[+] Option: ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0

        if choice == "1":
            try:
                path = _clean_path(input_fn("[+] Folder or file to scan: "))
            except (EOFError, KeyboardInterrupt):
                return 0
            if not path or not os.path.exists(path):
                out(f"\n{YELLOW}Path not found.{RESET}")
                continue
            last_skipped = []
            last = scan([path], skipped=last_skipped)
            if find_manifests([path]) and _ask_deps(input_fn):
                try:
                    last = sorted(last + check_deps(find_manifests([path])),
                                  key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line, x.column))
                except DepsError as exc:
                    out(f"\n{YELLOW}Dependency check failed: {exc}{RESET}")
            if is_git_repo(path) and input_fn(
                    "[+] Also scan the git history for leaked secrets? [Y/n]: ").strip().lower() != "n":
                try:
                    last = sorted(last + scan_history(path, last),
                                  key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line, x.column))
                except HistoryError as exc:
                    out(f"\n{YELLOW}History scan failed: {exc}{RESET}")
            results_screen(last, last_skipped, input_fn, out, clear)
            clear()
        elif choice == "2":
            try:
                link = _clean_path(input_fn("[+] GitHub link (https://github.com/owner/repo): "))
                if not is_repo_url(link):
                    out(f"\n{YELLOW}That is not a GitHub repository link.{RESET}")
                    continue
                keep = input_fn("[+] Keep the downloaded copy to browse? [Y/n]: ").strip().lower() != "n"
                deps = _ask_deps(input_fn)
            except (EOFError, KeyboardInterrupt):
                return 0
            out(f"\n{DIM}Downloading and scanning...{RESET}")
            last_skipped = []
            warnings: List[str] = []
            try:
                last = scan_repo(link, skipped=last_skipped, keep=keep, deps=deps, warnings=warnings)
            except RepoError as exc:
                out(f"\n{YELLOW}{exc}{RESET}")
                continue
            for w in warnings:
                out(f"\n{YELLOW}{w[0].upper() + w[1:]}{RESET}")
            notes = [f"Copy kept in {download_path(*parse_repo_url(link))}", "Delete it in option [5]."] \
                if keep else []
            results_screen(last, last_skipped, input_fn, out, clear, notes)
            clear()
        elif choice == "3":
            if last is None:
                out(f"\n{YELLOW}Run a scan first.{RESET}")
                continue
            results_screen(last, last_skipped, input_fn, out, clear)
            clear()
        elif choice == "4":
            if last is None:
                out(f"\n{YELLOW}Run a scan first.{RESET}")
                continue
            target = _clean_path(input_fn("[+] Save as (default: codesentry-report.json): ")) \
                or "codesentry-report.json"
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(as_json(last) + "\n")
            out(f"\n{GREEN}Saved to {os.path.abspath(target)}{RESET}")
        elif choice == "5":
            _manage_downloads(input_fn, out)
        elif choice == "6":
            return 0
        else:
            out(f"\n{YELLOW}Invalid option.{RESET}")


def start() -> int:
    _setup_console()
    return run_menu(clear=_clear_screen)
