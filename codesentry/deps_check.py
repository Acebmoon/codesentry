# deps_check.py
# Dependency check: known vulnerabilities in pinned packages, using the OSV.dev API.
# Only package names and versions are sent. Opt-in (--deps / menu question).

import os
import re
import json
import fnmatch
import ssl
import urllib.request
from typing import Dict, Iterable, List, Optional

from .scan_engine import Finding, iter_files
from .rules_db import SEVERITY_ORDER

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
TIMEOUT = 20
MAX_DETAILS = 150          # vulnerability records fetched per run
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
    return name == "package.json" or _is_requirements(name)


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


def _parse_package_json(path: str) -> List[Dep]:
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
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            version = spec.strip().lstrip("^~=v ")      # ^1.2.3 -> 1.2.3 (lowest allowed)
            if not _VERSION.match(version):
                continue                                # *, latest, git urls, ranges
            line = next((i for i, t in enumerate(lines, 1) if f'"{name}"' in t), 1)
            deps.append(Dep(name, version, "npm", path, line))
    return deps


def read_deps(manifests: Iterable[str]) -> List[Dep]:
    deps: List[Dep] = []
    for path in manifests:
        try:
            deps += _parse_package_json(path) if os.path.basename(path) == "package.json" \
                else _parse_requirements(path)
        except OSError:
            continue
    return deps


_CA_FILES = ("/etc/ssl/cert.pem",                       # macOS, Alpine
             "/etc/ssl/certs/ca-certificates.crt",      # Debian, Ubuntu, Arch
             "/etc/pki/tls/certs/ca-bundle.crt")        # Fedora, RHEL


def _ssl_context() -> ssl.SSLContext:
    """Default TLS context; falls back to the system CA files when Python ships without any
    (python.org builds on macOS, frozen binaries)."""
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0) > 0:
        return ctx
    for path in _CA_FILES:
        if os.path.isfile(path):
            try:
                ctx.load_verify_locations(cafile=path)
                return ctx
            except (ssl.SSLError, OSError):
                continue
    try:
        import certifi  # type: ignore
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass
    return ctx


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "codesentry"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "codesentry"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _severity(vuln: dict) -> str:
    raw = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return _SEVERITY.get(raw, "MEDIUM")


def _fixed_version(vuln: dict, dep: Dep) -> Optional[str]:
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != dep.ecosystem:
            continue
        if str(pkg.get("name", "")).lower().replace("_", "-") != dep.name.lower().replace("_", "-"):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue                      # commit hashes are not versions
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return str(ev["fixed"])
    return None


def check_deps(manifests: Iterable[str], min_severity: str = "LOW") -> List[Finding]:
    """Findings for pinned dependencies with known vulnerabilities. Raises DepsError
    if OSV.dev cannot be reached."""
    deps = read_deps(manifests)
    if not deps:
        return []
    try:
        batch = _post(OSV_BATCH, {"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in deps]})
        results = batch.get("results", [])
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
