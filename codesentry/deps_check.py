# deps_check.py
# Dependency check: known vulnerabilities in pinned packages, using the OSV.dev API.
# Only package names and versions are sent. Opt-in (--deps / menu question).

import os
import re
import json
import fnmatch
import urllib.request
from typing import Dict, Iterable, List, Optional

from .scan_engine import Finding, iter_files
from .rules_db import SEVERITY_ORDER

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
TIMEOUT = 20
MAX_DETAILS = 150          # vulnerability records fetched per run
OSV_BATCH_SIZE = 1000      # the most queries OSV.dev takes in one batch
# A package key in package-lock.json v2/v3: "node_modules/qs", "node_modules/a/node_modules/qs".
_LOCK_KEY = re.compile(r'^\s*"((?:[^"]*/)?node_modules/[^"]+)"\s*:')
_VERSION = re.compile(r"\d+(?:\.\d+)*(?:[-+.\w]*)?$")
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)")
_SEVERITY = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class DepsError(Exception):
    """The OSV service could not be reached or answered badly."""


class Dep:
    __slots__ = ("name", "version", "ecosystem", "file", "line")

    def __init__(self, name: str, version: str, ecosystem: str, file: str, line: int):
        self.name, self.version, self.ecosystem, self.file, self.line = name, version, ecosystem, file, line


def _is_requirements(name: str) -> bool:
    return fnmatch.fnmatch(name.lower(), "requirements*.txt")


def is_manifest(path: str) -> bool:
    name = os.path.basename(path)
    return name in ("package.json", "package-lock.json") or _is_requirements(name)


def find_manifests(paths: Iterable[str], exclude_globs: Iterable[str] = (),
                   use_ignore_file: bool = True) -> List[str]:
    found: List[str] = []
    for p in paths:
        found += [f for f in iter_files(p, exclude_globs, use_ignore_file) if is_manifest(f)]
    return found


def _parse_requirements(path: str) -> List[Dep]:
    deps: List[Dep] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for num, line in enumerate(fh, 1):
            m = _PIN.match(line.split("#", 1)[0])
            if m:
                deps.append(Dep(m.group(1), m.group(2), "PyPI", path, num))
    return deps


def _parse_package_json(path: str, unchecked: Optional[List[str]] = None) -> List[Dep]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    deps: List[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        # The dependency's own line, inside its section: the name can appear earlier ("scripts").
        start = next((i for i, t in enumerate(lines, 1) if f'"{section}"' in t), 0)
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            version = spec.strip().lstrip("^~=v ")      # ^1.2.3 -> 1.2.3 (lowest allowed)
            if not _VERSION.match(version):
                if unchecked is not None:                # *, latest, git urls, ranges
                    unchecked.append(f"{name} {spec.strip() or '(empty)'}")
                continue
            line = next((i for i, t in enumerate(lines, 1) if i > start and f'"{name}"' in t), start or 1)
            deps.append(Dep(name, version, "npm", path, line))
    return deps


def _parse_package_lock(path: str, unchecked: Optional[List[str]] = None) -> List[Dep]:
    """Installed versions from package-lock.json, transitive dependencies included."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    deps: List[Dep] = []

    def add(name: str, version: object, line: int) -> None:
        if isinstance(version, str) and _VERSION.match(version):
            deps.append(Dep(name, version, "npm", path, line))
        elif unchecked is not None:
            unchecked.append(f"{name} {version}")

    packages = data.get("packages")
    if isinstance(packages, dict):                       # lockfileVersion 2 and 3
        first_line: Dict[str, int] = {}
        for i, t in enumerate(lines, 1):
            m = _LOCK_KEY.match(t)
            if m:
                first_line.setdefault(m.group(1), i)
        for key, info in packages.items():
            if not key or not isinstance(info, dict) or info.get("link"):
                continue                                 # "" is the project itself
            add(info.get("name") or key.rsplit("node_modules/", 1)[-1], info.get("version"), first_line.get(key, 1))
        return deps

    def walk(block: object) -> None:                     # lockfileVersion 1
        if not isinstance(block, dict):
            return
        for name, info in block.items():
            if isinstance(info, dict):
                add(name, info.get("version"), next((i for i, t in enumerate(lines, 1) if f'"{name}"' in t), 1))
                walk(info.get("dependencies"))

    walk(data.get("dependencies"))
    return deps


def read_deps(manifests: Iterable[str], unchecked: Optional[List[str]] = None) -> List[Dep]:
    """Pinned dependencies. A package.json with a package-lock.json next to it is read from the lock,
    which has the installed versions (not the lowest one the range allows) and the transitive ones.
    Specs that cannot be checked (ranges, `latest`, git links) go to `unchecked` when given."""
    paths = list(manifests)
    locked = {os.path.dirname(os.path.abspath(p)) for p in paths if os.path.basename(p) == "package-lock.json"}
    deps: List[Dep] = []
    for path in paths:
        name = os.path.basename(path)
        try:
            if name == "package-lock.json":
                deps += _parse_package_lock(path, unchecked)
            elif name == "package.json":
                if os.path.dirname(os.path.abspath(path)) not in locked:
                    deps += _parse_package_json(path, unchecked)
            else:
                deps += _parse_requirements(path)
        except OSError:
            continue
    # The same package and version twice in one file (nested copies in a lock) is checked once.
    seen = set()
    unique: List[Dep] = []
    for d in deps:
        key = (d.file, d.ecosystem, d.name.lower(), d.version)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def not_checked_warning(unchecked: List[str], shown: int = 10) -> str:
    """One line for the dependencies that have no pinned version to look up."""
    more = f" and {len(unchecked) - shown} more" if len(unchecked) > shown else ""
    return f"{len(unchecked)} dependencies not checked (no pinned version): {', '.join(unchecked[:shown])}{more}"


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "codesentry"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "codesentry"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _severity(vuln: dict) -> str:
    raw = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return _SEVERITY.get(raw, "MEDIUM")


def _version_key(version: str) -> tuple:
    """Order versions well enough to find the affected range: 1.10 > 1.9, 1.0.0-rc.1 < 1.0.0."""
    main, _, pre = str(version).strip().lstrip("vV=").partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in main.split("+", 1)[0].split(".")]
    nums += [0] * (4 - len(nums))
    tail = (1,) if not pre else (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))
    return tuple(nums), tail


def _fixed_version(vuln: dict, dep: Dep) -> Optional[str]:
    """The fix of the affected range that contains the dependency's version. An advisory can list
    several ranges (0 to 1.5.0, and 2.0.0 to 2.3.0): 2.1.0 needs 2.3.0, not the first fix listed."""
    first_fixed: Optional[str] = None
    current = _version_key(dep.version)
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != dep.ecosystem:
            continue
        if str(pkg.get("name", "")).lower().replace("_", "-") != dep.name.lower().replace("_", "-"):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue                      # commit hashes are not versions
            introduced: Optional[str] = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = str(ev["introduced"])
                elif "fixed" in ev:
                    fixed = str(ev["fixed"])
                    first_fixed = first_fixed or fixed
                    if introduced is not None and _version_key(introduced) <= current < _version_key(fixed):
                        return fixed
                    introduced = None
                elif "last_affected" in ev:
                    introduced = None
    return first_fixed


def check_deps(manifests: Iterable[str], min_severity: str = "LOW",
               unchecked: Optional[List[str]] = None) -> List[Finding]:
    """Findings for pinned dependencies with known vulnerabilities. Raises DepsError
    if OSV.dev cannot be reached. Dependencies that cannot be checked go to `unchecked`."""
    deps = read_deps(manifests, unchecked)
    if not deps:
        return []
    try:
        results: List[dict] = []
        for i in range(0, len(deps), OSV_BATCH_SIZE):    # a lock file can list thousands of packages
            batch = _post(OSV_BATCH, {"queries": [
                {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                for d in deps[i:i + OSV_BATCH_SIZE]]})
            results += batch.get("results", [])
        ids: List[str] = []
        for r in results:
            for v in (r or {}).get("vulns", []):
                if v["id"] not in ids:
                    ids.append(v["id"])
        details: Dict[str, dict] = {i: _get(OSV_VULN + i) for i in ids[:MAX_DETAILS]}
    except (OSError, ValueError, KeyError) as exc:
        raise DepsError(f"could not reach OSV.dev ({exc})") from exc

    threshold = SEVERITY_ORDER[min_severity]
    findings: List[Finding] = []
    for dep, res in zip(deps, results):
        covered = set()                       # the same flaw often has a GHSA and a PYSEC id
        vulns = sorted((res or {}).get("vulns", []), key=lambda v: (not v["id"].startswith("GHSA"), v["id"]))
        for v in vulns:
            vuln = details.get(v["id"], {})
            names = {v["id"], *vuln.get("aliases", [])}
            if names & covered:
                continue
            covered |= names
            sev = _severity(vuln)
            if SEVERITY_ORDER[sev] < threshold:
                continue
            cwes = (vuln.get("database_specific") or {}).get("cwe_ids") or []
            fixed = _fixed_version(vuln, dep)
            summary = vuln.get("summary") or (vuln.get("details") or "known vulnerability").strip().splitlines()[0][:100]
            findings.append(Finding(
                v["id"], f"{dep.name} {dep.version}: {summary}"[:140], sev,
                cwes[0] if cwes else "CWE-1395", dep.file, dep.line,
                f"{dep.name} {dep.version}",
                f"Upgrade {dep.name} to {fixed} or later" if fixed else f"Upgrade {dep.name} to a patched version"))
    findings.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line))
    return findings
