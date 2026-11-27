# menu_ui.py
# Interactive terminal menu (banner + numbered options). Opens when codesentry runs with no arguments.

import os
import shutil
import sys
import webbrowser
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from . import __version__
from .scan_engine import scan, SkippedFile, Finding
from .rules_db import SEVERITY_ORDER
from .history_scan import scan_history, is_git_repo, HistoryError
from .deps_check import check_deps, find_manifests, DepsError
from .report_output import as_json, as_text, as_html
from .clipboard import copy_text, ClipboardError
from .site_scan import scan_site, SiteError, normalize_url
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


_HOME_VARS = ("$env:USERPROFILE", "$HOME", "$env:HOME")


def _clean_path(raw: str) -> str:
    """Drag-and-drop adds quotes around paths; strip them. Also understands ~, $HOME,
    $env:USERPROFILE (PowerShell style) and %VAR% / $VAR."""
    path = raw.strip().strip('"').strip("'")
    for var in _HOME_VARS:
        if path.lower().startswith(var.lower()) and path[len(var):len(var) + 1] in ("", "\\", "/"):
            path = os.path.expanduser("~") + path[len(var):]
            break
    return os.path.expandvars(os.path.expanduser(path))


def _clear_screen() -> None:
    sys.stdout.write("\033[2J\033[3J\033[H")
    sys.stdout.flush()


def _per_page() -> int:
    rows = shutil.get_terminal_size((80, 24)).lines
    return max(1, (rows - 14) // 5)        # each finding takes 5 lines, the frame about 14


class _Quit(Exception):
    """Input closed (Ctrl+C / Ctrl+Z): leave the program."""


class _Back(Exception):
    """The person typed B on a screen that asks for input: back to the menu."""


class _Ui:
    """Every screen of the menu goes through here, so they all look the same:
    a clean screen, a `CODESENTRY > TITLE` header, the content, a prompt.
    It also remembers where each clickable line was drawn (for the mouse)."""

    def __init__(self, input_fn, out, clear, mouse=None):
        self._input, self._print, self._clear, self._mouse = input_fn, out, clear, mouse
        self._row, self._hot = 1, {}

    def clear(self) -> None:
        self._clear()
        self._row, self._hot = 1, {}

    def out(self, text: str = "", hot=None) -> None:
        """Print a line. `hot` makes it clickable: a command for the whole line, or a list of
        (first column, last column, command) for buttons side by side."""
        self._print(text)
        if hot is not None:
            segs = [(1, max(1, len(text)), hot)] if isinstance(hot, str) else hot
            self._hot.setdefault(self._row + len(text) - len(text.lstrip("\n")), []).extend(segs)
        self._row += text.count("\n") + 1

    def screen(self, title: str, notice: str = "", back: bool = False) -> None:
        self.clear()
        self.out(f"{RED}CODESENTRY{RESET} {DIM}>{RESET} {title}")
        self.out(f"{DIM}{'-' * 60}{RESET}")
        if back:
            self.out(f"{DIM}[B] Back  (type B and press Enter at any question){RESET}")
        if notice:
            self.out(f"\n{notice}")
        self.out("")

    def ask(self, prompt: str, back: bool = False) -> str:
        try:
            value = self._input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            raise _Quit()
        if back and value.lower() in ("b", "back"):
            raise _Back()
        return value

    def choose(self, prompt: str, wheel: bool = False, any_click: bool = False) -> str:
        """One key or one click (no Enter needed) when the terminal allows it, else typed."""
        if self._mouse is not None:
            fits = self._row <= shutil.get_terminal_size((80, 24)).lines   # rows only line up if nothing scrolled
            try:
                got = self._mouse.choose(prompt, self._hot if fits else {}, wheel, any_click)
            except KeyboardInterrupt:
                raise _Quit()
            if got is not None:
                return got
        return self.ask(prompt)

    def ask_yes(self, prompt: str) -> bool:
        """[Y/n]: Enter means yes. B goes back."""
        return self.ask(prompt, back=True).lower() != "n"

    def message(self, title: str, text: str, color: str = YELLOW) -> None:
        self.screen(title)
        self.out(f"{color}{text}{RESET}")
        self.out(f"\n{DIM}{'-' * 60}{RESET}")
        self.choose("[Enter] Back ", any_click=True)


def _buttons(prefix: str, items) -> tuple:
    """A line of buttons plus the column range of each one: ('Page 1/3  [N]ext ...', segments)."""
    text, segs = prefix, []
    for label, cmd in items:
        segs.append((len(text) + 1, len(text) + len(label), cmd))
        text += label + "  "
    return text.rstrip(), segs


_FILTERS = {"h": "HIGH", "m": "MEDIUM", "l": "LOW"}


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line, x.column))


def results_screen(ui: _Ui, findings: List[Finding], skipped: List[SkippedFile],
                   notes: Sequence[str] = ()) -> None:
    """Results in their own screen: pages, a severity filter, save and Back."""
    only: Optional[str] = None
    page, notice = 0, ""
    size = _per_page()
    while True:
        shown = [f for f in findings if only is None or f.severity == only]
        pages = max(1, -(-len(shown) // size))
        page = min(page, pages - 1)
        ui.screen("RESULTS", notice)
        notice = ""
        counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEV_COLOR}
        ui.out(f"Total: {len(findings)} | {RED}HIGH: {counts['HIGH']}{RESET} | "
               f"{YELLOW}MEDIUM: {counts['MEDIUM']}{RESET} | {CYAN}LOW: {counts['LOW']}{RESET}"
               + (f"   {DIM}(showing {only}){RESET}" if only else ""))
        if not findings:
            ui.out(f"\n{GREEN}No issues found.{RESET}")
        elif not shown:
            ui.out(f"\n{YELLOW}No {only} findings.{RESET}")
        for i, f in enumerate(shown[page * size:(page + 1) * size], page * size + 1):
            color = SEV_COLOR.get(f.severity, "")
            ui.out(f"\n{DIM}{i:>3}{RESET} {color}[{f.severity}]{RESET} {f.rule_id}  {f.file}:{f.line}")
            ui.out(f"    {f.name} ({f.cwe})")
            ui.out(f"    {DIM}> {f.snippet}{RESET}")
            ui.out(f"    fix: {f.fix}")
        if page == pages - 1:
            for sk in skipped:
                ui.out(f"\n{DIM}skipped {sk.file}: {sk.reason}{RESET}")
            for note in notes:
                ui.out(f"\n{YELLOW}{note}{RESET}")
        ui.out(f"\n{DIM}{'-' * 60}{RESET}")
        for prefix, items in ((f"Page {page + 1}/{pages}   ", [
                ("[N]ext", "n"), ("[P]rev", "p"), ("[H]igh", "h"), ("[M]edium", "m"), ("[L]ow", "l"),
                ("[A]ll", "a")]),
                ("", [("[C]opy", "c"), ("[R]eport HTML", "r"), ("[S]ave JSON", "s"), ("[B]ack", "b")])):
            line, segs = _buttons(prefix, items)
            ui.out(line, hot=segs)
        cmd = ui.choose("[+] Command: ", wheel=True).lower()
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
            notice = _save_report(ui, findings)
        elif cmd in ("c", "copy"):
            notice = _copy_report(shown)
        elif cmd in ("r", "report", "html"):
            notice = _html_report(ui, findings, skipped)
        else:
            notice = f"{YELLOW}Unknown command.{RESET}"


def _save_report(ui: _Ui, findings: List[Finding]) -> str:
    try:
        target = _clean_path(ui.ask("[+] Save as (default: codesentry-report.json, B = cancel): ", back=True)) \
            or "codesentry-report.json"
    except _Back:
        return f"{DIM}Cancelled.{RESET}"
    try:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(as_json(findings) + "\n")
    except OSError as exc:
        return f"{YELLOW}Could not save: {exc.strerror or exc}{RESET}"
    return f"{GREEN}Saved to {os.path.abspath(target)}{RESET}"


def _copy_report(findings: List[Finding]) -> str:
    if not findings:
        return f"{YELLOW}Nothing to copy.{RESET}"
    try:
        copy_text(as_text(findings))
    except ClipboardError as exc:
        return f"{YELLOW}Could not copy: {exc}{RESET}"
    return f"{GREEN}Copied {len(findings)} finding(s) to the clipboard.{RESET}"


def _html_report(ui: _Ui, findings: List[Finding], skipped: List[SkippedFile]) -> str:
    try:
        target = _clean_path(ui.ask("[+] Save as (default: codesentry-report.html, B = cancel): ", back=True)) \
            or "codesentry-report.html"
        try:
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(as_html(findings, __version__, skipped))
        except OSError as exc:
            return f"{YELLOW}Could not save: {exc.strerror or exc}{RESET}"
        path = os.path.abspath(target)
        if ui.ask_yes("[+] Open it in the browser now? [Y/n]: "):
            try:
                webbrowser.open(Path(path).as_uri())
            except Exception:
                return f"{GREEN}Saved to {path}{RESET}  {YELLOW}(could not open the browser){RESET}"
        return f"{GREEN}Saved to {path}{RESET}"
    except _Back:
        return f"{DIM}Cancelled.{RESET}"


def _export(ui: _Ui, findings: List[Finding], skipped: List[SkippedFile]) -> None:
    ui.screen("EXPORT REPORT", back=True)
    ui.out("[1] HTML report (opens in the browser)")
    ui.out("[2] JSON file")
    ui.out("[3] Copy results to the clipboard\n")
    pick = ui.ask("[+] Option: ", back=True)
    if pick == "1":
        notice = _html_report(ui, findings, skipped)
    elif pick == "2":
        notice = _save_report(ui, findings)
    elif pick == "3":
        notice = _copy_report(findings)
    else:
        notice = f"{YELLOW}Invalid option.{RESET}"
    ui.screen("EXPORT REPORT", notice)
    ui.choose("[Enter] Back ", any_click=True)


def _size(n: int) -> str:
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} MB"


def _manage_downloads(ui: _Ui) -> None:
    notice = ""
    while True:
        items = list_downloads()
        ui.screen("DOWNLOADED REPOS", notice)
        notice = ""
        if not items:
            ui.out("No downloaded repos.")
            ui.out(f"\n{DIM}{'-' * 60}{RESET}")
            ui.choose("[Enter] Back ", any_click=True)
            return
        ui.out(f"Kept in {downloads_dir()}\n")
        for i, (name, size) in enumerate(items, 1):
            ui.out(f"  [{i}] {name.replace('__', '/', 1)}  ({_size(size)})")
        ui.out("\n  [A] Delete all     [B] Back")
        ui.out(f"\n{DIM}{'-' * 60}{RESET}")
        pick = ui.ask("[+] Delete which? (number) ").lower()
        if pick in ("", "b", "back"):
            return
        if pick == "a":
            notice = f"{GREEN}Deleted {delete_all_downloads()} download(s).{RESET}"
        elif pick.isdigit() and 1 <= int(pick) <= len(items):
            delete_download(items[int(pick) - 1][0])
            notice = f"{GREEN}Deleted.{RESET}"
        else:
            notice = f"{YELLOW}Invalid option.{RESET}"


def _scan_local(ui: _Ui):
    ui.screen("SCAN", back=True)
    ui.out(f"{DIM}Drag a folder or file here, or type its path.{RESET}\n")
    path = _clean_path(ui.ask("[+] Folder or file to scan: ", back=True))
    if not path or not os.path.exists(path):
        ui.message("SCAN", "Path not found.")
        return None
    notes: List[str] = []
    skipped: List[SkippedFile] = []
    manifests = find_manifests([path])
    check = bool(manifests) and ui.ask_yes("[+] Also check dependencies online (OSV.dev)? [Y/n]: ")
    history = is_git_repo(path) and ui.ask_yes("[+] Also scan the git history for leaked secrets? [Y/n]: ")
    ui.out(f"\n{DIM}Scanning...{RESET}")
    found = scan([path], skipped=skipped)
    if check:
        try:
            found += check_deps(manifests)
        except DepsError as exc:
            notes.append(f"Dependency check failed: {exc}")
    if history:
        try:
            found += scan_history(path, found)
        except HistoryError as exc:
            notes.append(f"History scan failed: {exc}")
    return _sorted(found), skipped, notes


def _scan_github(ui: _Ui):
    ui.screen("SCAN GITHUB REPO", back=True)
    link = _clean_path(ui.ask("[+] GitHub link (https://github.com/owner/repo): ", back=True))
    if not is_repo_url(link):
        ui.message("SCAN GITHUB REPO", "That is not a GitHub repository link.")
        return None
    keep = ui.ask_yes("[+] Keep the downloaded copy to browse? [Y/n]: ")
    deps = ui.ask_yes("[+] Also check dependencies online (OSV.dev)? [Y/n]: ")
    ui.out(f"\n{DIM}Downloading and scanning...{RESET}")
    skipped: List[SkippedFile] = []
    warnings: List[str] = []
    try:
        found = scan_repo(link, skipped=skipped, keep=keep, deps=deps, warnings=warnings)
    except RepoError as exc:
        ui.message("SCAN GITHUB REPO", str(exc))
        return None
    notes = [w[0].upper() + w[1:] for w in warnings]
    if keep:
        notes += [f"Copy kept in {download_path(*parse_repo_url(link))}. Delete it in [6] Downloaded repos."]
    return found, skipped, notes


def _scan_site(ui: _Ui):
    ui.screen("SCAN WEBSITE", back=True)
    ui.out(f"{DIM}Passive check: headers, cookies, TLS, CORS, exposed files. About 30 plain requests, nothing is attacked.{RESET}\n")
    raw = ui.ask("[+] Website address (e.g. https://example.com): ", back=True)
    try:
        url = normalize_url(raw)
    except SiteError as exc:
        ui.message("SCAN WEBSITE", str(exc))
        return None
    answer = ui.ask("[+] Do you own this site or have permission to test it? [y/N]: ", back=True).lower()
    if answer not in ("y", "yes", "s", "sim"):
        ui.message("SCAN WEBSITE", "Only scan sites you own or have permission to test.")
        return None
    ui.out(f"\n{DIM}Checking {url} ...{RESET}")
    warnings: List[str] = []
    try:
        found = scan_site(url, warnings=warnings)
    except SiteError as exc:
        ui.message("SCAN WEBSITE", str(exc)[0].upper() + str(exc)[1:])
        return None
    return found, [], [w[0].upper() + w[1:] for w in warnings]


def run_menu(input_fn: Callable[[str], str] = input,
             out: Callable[[str], None] = print,
             clear: Callable[[], None] = lambda: None,
             mouse=None) -> int:
    ui = _Ui(input_fn, out, clear, mouse)
    last: Optional[List[Finding]] = None
    last_skipped: List[SkippedFile] = []
    try:
        while True:
            ui.clear()
            ui.out(banner())
            ui.out(f"\n{RED}   STATIC CODE SCANNER  v{__version__}{RESET}\n")
            for number, label in enumerate(("Start Scan", "Scan GitHub repo", "Scan website", "View last results",
                                            "Export last report", "Downloaded repos", "Exit"), 1):
                ui.out(f"[{number}] {label}", hot=str(number))
            ui.out("")
            choice = ui.choose("[+] Option: ")

            if choice in ("1", "2", "3"):
                try:
                    result = {"1": _scan_local, "2": _scan_github, "3": _scan_site}[choice](ui)
                except _Back:
                    continue
                if result:
                    last, last_skipped, notes = result
                    results_screen(ui, last, last_skipped, notes)
            elif choice == "4":
                if last is None:
                    ui.message("RESULTS", "Run a scan first.")
                else:
                    results_screen(ui, last, last_skipped)
            elif choice == "5":
                if last is None:
                    ui.message("EXPORT REPORT", "Run a scan first.")
                else:
                    try:
                        _export(ui, last, last_skipped)
                    except _Back:
                        continue
            elif choice == "6":
                _manage_downloads(ui)
            elif choice == "7":
                return 0
            else:
                ui.message("MENU", "Invalid option.")
    except _Quit:
        return 0


def start() -> int:
    _setup_console()
    from .term_input import Mouse
    return run_menu(clear=_clear_screen, mouse=Mouse())
