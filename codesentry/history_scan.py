# history_scan.py
# Secrets that were committed once and later removed are still in the git history.
# Reads `git log -p` of a local repository; never runs anything from the repo.

import os
import re
import subprocess
from typing import Iterable, List, Optional, Set, Tuple

from .scan_engine import Finding, _scan_lines, _excluder, read_ignore_file
from .rules_db import SEVERITY_ORDER

MAX_COMMITS = 5000
MAX_BYTES = 100_000_000
MAX_LINE = 2000
TIMEOUT = 120
_SKIP_DIRS = {"node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".tox"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


class HistoryError(Exception):
    pass


def is_git_repo(path: str) -> bool:
    return os.path.isdir(path) and os.path.exists(os.path.join(path, ".git"))


def _git_log(path: str) -> str:
    # The scanned folder may come from someone else (a zip with its .git inside), and git reads that
    # folder's own .git/config. log.showSignature makes `git log` verify signed commits by running
    # gpg.program, which that config can point anywhere: switch it off, like the clone switches off hooks.
    cmd = ["git", "-c", "core.quotepath=off", "-c", "log.showSignature=false", "log", "--all", "--reverse",
           "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", f"-n{MAX_COMMITS}",
           "--format=@@commit %H", "--", "."]
    try:
        out = subprocess.run(cmd, cwd=path, capture_output=True, timeout=TIMEOUT,
                             env={**os.environ, "GIT_PAGER": "cat", "GIT_TERMINAL_PROMPT": "0"})
    except FileNotFoundError as exc:
        raise HistoryError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise HistoryError("reading the history took too long") from exc
    if out.returncode != 0:
        raise HistoryError("could not read the git history")
    if len(out.stdout) > MAX_BYTES:
        raise HistoryError("the history is too large to scan")
    return out.stdout.decode("utf-8", errors="replace")


def _is_excluded(excluded, root: str, file: str) -> bool:
    """The file itself or any folder above it matches an exclude pattern (e.g. `tests`)."""
    parts = file.split("/")
    return any(excluded(os.path.join(root, *parts[:i])) for i in range(1, len(parts) + 1))


def scan_history(path: str, current: Iterable[Finding] = (), min_severity: str = "LOW",
                 exclude_globs: Iterable[str] = (), use_ignore_file: bool = True) -> List[Finding]:
    """Secret findings in lines that were ever added to the repo, reported once at the commit
    that added them. Honors --exclude and .codesentryignore like the normal scan. Secrets still present in the current files are skipped: the normal scan
    already reports those."""
    root = os.path.abspath(path)
    # Secrets are compared by the hash of their value, not by the masked snippet: two different keys
    # under the same name mask to the same 'api_key = "****"'.
    still_here: Set[Tuple[str, str]] = {
        (os.path.relpath(f.file, root).replace(os.sep, "/"), f.fingerprint or f.snippet) for f in current}
    threshold = SEVERITY_ORDER[min_severity]
    globs = list(exclude_globs) + (read_ignore_file(root) if use_ignore_file else [])
    excluded = _excluder(root, globs)
    found: List[Finding] = []
    seen: Set[Tuple[str, str, str]] = set()
    commit = ""
    file: Optional[str] = None
    lines: List[str] = []
    numbers: List[int] = []

    def flush() -> None:
        if file and lines:
            ext = os.path.splitext(file)[1].lower()
            if os.path.basename(file).startswith(".env"):
                ext = ".env"
            for f in _scan_lines(lines, ext, file):
                if not f.rule_id.startswith("CS-SEC") or SEVERITY_ORDER[f.severity] < threshold:
                    continue
                same = f.fingerprint or f.snippet
                key = (f.rule_id, file, same)
                if key in seen or (file, same) in still_here:
                    continue
                seen.add(key)
                f.line = numbers[f.line - 1]
                f.file = f"{file} (commit {commit[:7]})"
                f.fix += " It stays in the git history: revoke or rotate it."
                found.append(f)

    num = 0
    for raw in _git_log(root).splitlines():
        if raw.startswith("@@commit "):
            flush(); lines, numbers, file = [], [], None
            commit = raw[9:].strip()
        elif raw.startswith("diff --git "):
            flush(); lines, numbers, file = [], [], None
        elif raw.startswith("+++ "):
            target = raw[4:]
            file = target[2:] if target.startswith("b/") else None
            if file and (set(file.split("/")) & _SKIP_DIRS or _is_excluded(excluded, root, file)):
                file = None
        elif raw.startswith("@@"):
            m = _HUNK.match(raw)
            num = int(m.group(1)) if m else 0
        elif raw.startswith("+") and file:
            if len(raw) <= MAX_LINE:
                lines.append(raw[1:]); numbers.append(num)
            num += 1
    flush()
    found.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line))
    return found
