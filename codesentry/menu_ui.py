# menu_ui.py
# Interactive terminal menu (banner + numbered options). Opens when codesentry runs with no arguments.

import os
import sys
from typing import Callable, List, Optional

from . import __version__
from .scan_engine import scan, SkippedFile, Finding
from .report_output import as_json
from .repo_fetch import is_repo_url, scan_repo, RepoError

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


def _print_findings(findings: List[Finding], out: Callable[[str], None]) -> None:
    if not findings:
        out(f"\n{GREEN}No issues found.{RESET}")
        return
    for f in findings:
        color = SEV_COLOR.get(f.severity, "")
        out(f"\n{color}[{f.severity}]{RESET} {f.rule_id}  {f.file}:{f.line}")
        out(f"    {f.name} ({f.cwe})")
        out(f"    {DIM}> {f.snippet}{RESET}")
        out(f"    fix: {f.fix}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_COLOR}
    out(f"\nTotal: {len(findings)} | {RED}HIGH: {counts['HIGH']}{RESET} | "
        f"{YELLOW}MEDIUM: {counts['MEDIUM']}{RESET} | {CYAN}LOW: {counts['LOW']}{RESET}")


def run_menu(input_fn: Callable[[str], str] = input,
             out: Callable[[str], None] = print) -> int:
    last: Optional[List[Finding]] = None
    while True:
        out("")
        out(banner())
        out(f"\n{RED}   STATIC CODE SCANNER  v{__version__}{RESET}\n")
        out("[1] Start Scan")
        out("[2] Scan GitHub repo")
        out("[3] Save last report (JSON)")
        out("[4] Exit\n")
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
            skipped: List[SkippedFile] = []
            last = scan([path], skipped=skipped)
            _print_findings(last, out)
            for s in skipped:
                out(f"{DIM}skipped {s.file}: {s.reason}{RESET}")
        elif choice == "2":
            try:
                link = _clean_path(input_fn("[+] GitHub link (https://github.com/owner/repo): "))
            except (EOFError, KeyboardInterrupt):
                return 0
            if not is_repo_url(link):
                out(f"\n{YELLOW}That is not a GitHub repository link.{RESET}")
                continue
            out(f"\n{DIM}Downloading and scanning...{RESET}")
            skipped = []
            try:
                last = scan_repo(link, skipped=skipped)
            except RepoError as exc:
                out(f"\n{YELLOW}{exc}{RESET}")
                continue
            _print_findings(last, out)
            for s in skipped:
                out(f"{DIM}skipped {s.file}: {s.reason}{RESET}")
        elif choice == "3":
            if last is None:
                out(f"\n{YELLOW}Run a scan first.{RESET}")
                continue
            target = _clean_path(input_fn("[+] Save as (default: codesentry-report.json): ")) \
                or "codesentry-report.json"
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(as_json(last) + "\n")
            out(f"\n{GREEN}Saved to {os.path.abspath(target)}{RESET}")
        elif choice == "4":
            return 0
        else:
            out(f"\n{YELLOW}Invalid option.{RESET}")


def start() -> int:
    _setup_console()
    return run_menu()
