# scan_engine.py
# Core scanning logic: walks files, applies rules, returns findings.

import os
import fnmatch
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional

from .rules_db import RULES, SEVERITY_ORDER, PLACEHOLDER_HINTS, CODE_EXTS, CONFIG_EXTS

DEFAULT_EXCLUDE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
                        "dist", "build", ".idea", ".vscode", "target", ".tox"}
SCAN_EXTS = CODE_EXTS | CONFIG_EXTS | {".html", ".md", ".txt"}
MAX_FILE_BYTES = 1_000_000
IGNORE_MARKERS = ("nosec", "codesentry:ignore")
# Generic rules where placeholder values (changeme, your_key...) are not real secrets.
PLACEHOLDER_RULES = {"CS-SEC-007", "CS-SEC-008"}


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

    def to_dict(self):
        return asdict(self)


def mask(value: str) -> str:
    v = value.strip()
    return v if len(v) <= 8 else v[:4] + "****" + v[-2:]


def _is_placeholder(text: str) -> bool:
    low = text.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


def iter_files(path: str, exclude_globs: Iterable[str] = ()) -> Iterable[str]:
    exclude_globs = list(exclude_globs)

    def excluded(p: str) -> bool:
        return any(fnmatch.fnmatch(p, g) or fnmatch.fnmatch(os.path.basename(p), g)
                   for g in exclude_globs)

    if os.path.isfile(path):
        if not excluded(path):
            yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS
                   and not excluded(os.path.join(root, d))]
        for name in files:
            full = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if (ext in SCAN_EXTS or name.startswith(".env")) and not excluded(full):
                yield full


def scan_file(path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return findings
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return findings

    ext = os.path.splitext(path)[1].lower()
    if os.path.basename(path).startswith(".env"):
        ext = ".env"

    for num, line in enumerate(lines, 1):
        if any(m in line for m in IGNORE_MARKERS):
            continue
        for rule in RULES:
            if rule.exts is not None and ext not in rule.exts:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            if rule.id in PLACEHOLDER_RULES and _is_placeholder(match.group(0)):
                continue
            snippet = mask(match.group(0)) if rule.secret else line.strip()[:120]
            findings.append(Finding(rule.id, rule.name, rule.severity, rule.cwe,
                                    path, num, snippet, rule.fix))
    return findings


def scan(paths: Iterable[str], exclude_globs: Iterable[str] = (),
         min_severity: str = "LOW") -> List[Finding]:
    threshold = SEVERITY_ORDER[min_severity]
    results: List[Finding] = []
    for p in paths:
        for f in iter_files(p, exclude_globs):
            results += [x for x in scan_file(f)
                        if SEVERITY_ORDER[x.severity] >= threshold]
    results.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line))
    return results
