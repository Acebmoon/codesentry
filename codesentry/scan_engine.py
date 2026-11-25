# scan_engine.py
# Core scanning logic: walks files, applies rules, returns findings.

import os
import re
import fnmatch
from dataclasses import dataclass, asdict
from typing import Callable, Iterable, List, NamedTuple, Optional

from .rules_db import RULES, SEVERITY_ORDER, PLACEHOLDER_HINTS, CODE_EXTS, CONFIG_EXTS, is_placeholder

DEFAULT_EXCLUDE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
                        "dist", "build", ".idea", ".vscode", "target", ".tox"}
SCAN_EXTS = CODE_EXTS | CONFIG_EXTS | {".html", ".md", ".txt"}
MAX_FILE_BYTES = 1_000_000
IGNORE_MARKERS = ("nosec", "codesentry:ignore")
# Generic rules where placeholder values (changeme, your_key...) are not real secrets.
# The test itself is each rule's `check` (see rules_db).
PLACEHOLDER_RULES = {"CS-SEC-007", "CS-SEC-008"}

# An ignore marker counts only after a comment opener and as a whole word, so
# "nosecurity" or a string like "nosecure-..." do not silence the line.
# "codesentry:ignore[CS-SEC-007, CS-CFG-002]" silences only the listed rules.
# Two searches, not one regex: a single "opener.*?marker" pattern restarts at
# every "#" and is quadratic on a long line.
_COMMENT = re.compile(r"#|//|/\*|<!--|--")
_MARKER = re.compile(r"(?<![\w:-])(?:nosec|codesentry:ignore)(?![\w-])(?:\[(?P<ids>[^\]]*)\])?")


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    cwe: str
    file: str
    line: int
    snippet: str
    fix: str
    column: int = 1

    def to_dict(self):
        return asdict(self)


class SkippedFile(NamedTuple):
    file: str
    reason: str


def mask(value: str, reveal: int = 0) -> str:
    """Hide a secret entirely; `reveal` keeps a fixed public prefix such as "AKIA"."""
    v = value.strip()
    return (v[:reveal] if 0 < reveal < len(v) else "") + "****"


def _is_placeholder(text: str) -> bool:
    return is_placeholder(text)


def _silenced(line: str) -> Optional[frozenset]:
    """None: nothing is silenced. Empty set: every rule. Otherwise the listed ids."""
    opener = _COMMENT.search(line)
    m = _MARKER.search(line, opener.end()) if opener else None
    if not m:
        return None
    ids = m.group("ids")
    return frozenset(i.upper() for i in re.split(r"[\s,]+", ids) if i) if ids else frozenset()


def _glob_regex(glob: str) -> "re.Pattern":
    """A glob over "/"-separated paths: "*" and "?" stay in one folder, "**" crosses folders."""
    g = glob.replace(os.sep, "/").lstrip("/")
    while g.startswith("./"):
        g = g[2:]
    out, i = [], 0
    while i < len(g):
        if g.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif g.startswith("**", i):
            out.append(".*")
            i += 2
        elif g[i] == "*":
            out.append("[^/]*")
            i += 1
        elif g[i] == "?":
            out.append("[^/]")
            i += 1
        elif g[i] == "[" and g.find("]", i + 2) != -1:
            j = g.find("]", i + 2)
            body = g[i + 1:j]
            out.append("[" + ("^" + body[1:] if body.startswith("!") else body).replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(g[i]))
            i += 1
    return re.compile("".join(out), re.IGNORECASE if os.path.normcase("A") == "a" else 0)


def _excluder(root: str, exclude_globs: Iterable[str]) -> Callable[[str], bool]:
    """Exclude a path when a glob matches it relative to `root` ("tests/*",
    "**/fixtures/**"), its file or folder name ("*.min.js", "tests") or, as
    before, the path as given."""
    globs = [g for g in exclude_globs if g]
    relative = [_glob_regex(g) for g in globs]

    def excluded(p: str) -> bool:
        if not globs:
            return False
        rel = os.path.relpath(p, root).replace(os.sep, "/")
        name = os.path.basename(p)
        return (any(r.fullmatch(rel) for r in relative)
                or any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(p, g) for g in globs))

    return excluded


IGNORE_FILE = ".codesentryignore"


def read_ignore_file(folder: str) -> List[str]:
    """Globs from `<folder>/.codesentryignore`: one per line, blank lines and '#' comments skipped."""
    try:
        with open(os.path.join(folder, IGNORE_FILE), "r", encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh]
    except OSError:
        return []
    return [ln for ln in lines if ln and not ln.startswith("#")]


def iter_files(path: str, exclude_globs: Iterable[str] = ()) -> Iterable[str]:
    if os.path.isdir(path):
        exclude_globs = list(exclude_globs) + read_ignore_file(path)
    if os.path.isfile(path):
        if not _excluder(os.path.dirname(path) or ".", exclude_globs)(path):
            yield path
        return
    excluded = _excluder(path, exclude_globs)
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS
                   and not excluded(os.path.join(root, d))]
        for name in files:
            full = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if (ext in SCAN_EXTS or name.startswith(".env")) and not excluded(full):
                yield full


def _secret_snippet(rule, match) -> str:
    """The match with only its secret masked: `password = "****"`, `AKIA****`."""
    text = match.group(0)
    if "secret" not in rule.pattern.groupindex or match.start("secret") < 0:
        return mask(text, rule.reveal)
    a = match.start("secret") - match.start()
    b = match.end("secret") - match.start()
    return (text[:a] + mask(match.group("secret"), rule.reveal) + text[b:])[:120]


def _scan_lines(lines: Iterable[str], ext: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for num, line in enumerate(lines, 1):
        silenced = _silenced(line)
        for rule in RULES:
            if rule.exts is not None and ext not in rule.exts:
                continue
            if silenced is not None and (not silenced or rule.id in silenced):
                continue
            for match in rule.pattern.finditer(line):
                if rule.check is not None and not rule.check(match):
                    continue
                snippet = _secret_snippet(rule, match) if rule.secret else line.strip()[:120]
                findings.append(Finding(rule.id, rule.name, rule.severity, rule.cwe,
                                        path, num, snippet, rule.fix, match.start() + 1))
    return findings


def scan_file(path: str, max_file_bytes: Optional[int] = MAX_FILE_BYTES,
              skipped: Optional[List[SkippedFile]] = None) -> List[Finding]:
    """Scan one file. Files over `max_file_bytes` (0 or None: no limit) and
    unreadable files are not scanned, and are appended to `skipped` if given."""
    try:
        size = os.path.getsize(path)
        if max_file_bytes and size > max_file_bytes:
            if skipped is not None:
                skipped.append(SkippedFile(path, f"larger than {max_file_bytes} bytes ({size} bytes)"))
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError as exc:
        if skipped is not None:
            skipped.append(SkippedFile(path, f"could not be read ({exc.strerror or exc})"))
        return []

    ext = os.path.splitext(path)[1].lower()
    if os.path.basename(path).startswith(".env"):
        ext = ".env"
    return _scan_lines(lines, ext, path)


def scan(paths: Iterable[str], exclude_globs: Iterable[str] = (),
         min_severity: str = "LOW", max_file_bytes: Optional[int] = MAX_FILE_BYTES,
         skipped: Optional[List[SkippedFile]] = None) -> List[Finding]:
    threshold = SEVERITY_ORDER[min_severity]
    exclude_globs = list(exclude_globs)
    results: List[Finding] = []
    for p in paths:
        for f in iter_files(p, exclude_globs):
            results += [x for x in scan_file(f, max_file_bytes, skipped)
                        if SEVERITY_ORDER[x.severity] >= threshold]
    results.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line, x.column))
    return results
