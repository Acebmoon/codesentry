# repo_fetch.py
# Scan a public GitHub repository by link: shallow clone to a temp folder, scan, delete.

import os
import re
import shutil
import stat
import subprocess
import tempfile
from typing import List, Optional, Tuple

from .scan_engine import Finding, SkippedFile, scan, MAX_FILE_BYTES
from .rules_db import SEVERITY_ORDER
from .deps_check import check_deps, find_manifests, DepsError

_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))"
    r"/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:/(?:tree|blob)/.*)?/?$")
CLONE_TIMEOUT = 120


def downloads_dir() -> str:
    """Where kept copies live: ~/.codesentry/downloads (CODESENTRY_HOME overrides ~/.codesentry)."""
    base = os.environ.get("CODESENTRY_HOME") or os.path.join(os.path.expanduser("~"), ".codesentry")
    return os.path.join(base, "downloads")


def download_path(owner: str, repo: str) -> str:
    return os.path.join(downloads_dir(), f"{owner}__{repo}")


def _folder_size(path: str) -> int:
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(path) for f in fs
               if os.path.isfile(os.path.join(d, f)))


def list_downloads() -> List[Tuple[str, int]]:
    """(name, size in bytes) of every kept copy, sorted by name."""
    root = downloads_dir()
    if not os.path.isdir(root):
        return []
    return sorted((n, _folder_size(os.path.join(root, n))) for n in os.listdir(root)
                  if os.path.isdir(os.path.join(root, n)) and not os.path.islink(os.path.join(root, n)))


def delete_download(name: str) -> bool:
    """Delete one kept copy by its name. Only direct children of the downloads folder qualify."""
    root = downloads_dir()
    target = os.path.join(root, name)
    if (not name or name != os.path.basename(name) or name in (".", "..")
            or not os.path.isdir(target) or os.path.islink(target)):
        return False
    _rmtree(target)
    return True


def delete_all_downloads() -> int:
    return sum(1 for name, _ in list_downloads() if delete_download(name))


class RepoError(Exception):
    """A readable problem: bad link, repo not found, git missing, timeout."""


def parse_repo_url(text: str) -> Optional[Tuple[str, str]]:
    """('owner', 'repo') for a github.com repository link, otherwise None."""
    m = _URL.match(text.strip())
    if not m or m.group("repo") in (".", ".."):
        return None
    return m.group("owner"), m.group("repo")


def is_repo_url(text: str) -> bool:
    return parse_repo_url(text) is not None


def _clone_url(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}.git"


def _clone(url: str, dest: str) -> None:
    # Arguments as a list (no shell); hooks disabled; no credential prompt.
    cmd = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.symlinks=false",
           "clone", "--depth", "1", "--no-tags", "--quiet", "--", url, dest]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env)
    except FileNotFoundError:
        raise RepoError("git is not installed or not in PATH")
    except subprocess.TimeoutExpired:
        raise RepoError(f"clone took longer than {CLONE_TIMEOUT}s")
    if proc.returncode != 0:
        raise RepoError("could not clone (repository not found, private, or no network)")


def _rmtree(path: str) -> None:
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)  # git marks pack files read-only on Windows
        func(p)
    shutil.rmtree(path, onerror=onerror)


def _drop_links_and_git(root: str) -> None:
    """Never follow links out of the clone, and skip git internals."""
    git_dir = os.path.join(root, ".git")
    if os.path.isdir(git_dir):
        _rmtree(git_dir)  # not ignore_errors: git pack files are read-only on Windows
    for folder, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(folder, name)
            if os.path.islink(p):
                os.unlink(p)


def scan_repo(link: str, min_severity: str = "LOW", exclude_globs=(),
              max_file_bytes: Optional[int] = MAX_FILE_BYTES,
              skipped: Optional[List[SkippedFile]] = None, keep: bool = False,
              deps: bool = False, warnings: Optional[List[str]] = None) -> List[Finding]:
    """Findings for a GitHub repo, with paths shown as owner/repo/path. The clone is
    deleted afterwards, unless keep=True: then it stays in downloads_dir() until
    delete_download(). deps=True also checks pinned dependencies online
    (OSV.dev); a failure is added to `warnings`. The repo's own .codesentryignore is not honored."""
    parsed = parse_repo_url(link)
    if not parsed:
        raise RepoError("not a GitHub repository link (expected https://github.com/owner/repo)")
    owner, repo = parsed
    if keep:
        os.makedirs(downloads_dir(), exist_ok=True)
        root = download_path(owner, repo)
        if os.path.isdir(root):
            _rmtree(root)
        tmp = None
    else:
        tmp = tempfile.mkdtemp(prefix="codesentry-")
        root = os.path.join(tmp, "repo")
    try:
        _clone(_clone_url(owner, repo), root)
        _drop_links_and_git(root)
        inner: List[SkippedFile] = []
        found = scan([root], exclude_globs, min_severity, max_file_bytes, inner, use_ignore_file=False)
        prefix = f"{owner}/{repo}"

        def shown(p: str) -> str:
            return prefix + "/" + os.path.relpath(p, root).replace(os.sep, "/")

        if deps:
            try:
                found += check_deps(find_manifests([root], exclude_globs, use_ignore_file=False), min_severity)
            except DepsError as exc:
                if warnings is not None:
                    warnings.append(str(exc))
        found.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line, x.column))
        for f in found:
            f.file = shown(f.file)
        if skipped is not None:
            skipped.extend(SkippedFile(shown(s.file), s.reason) for s in inner)
        return found
    except BaseException:
        if keep and os.path.isdir(root):
            _rmtree(root)  # never leave a half-downloaded copy behind
        raise
    finally:
        if tmp:
            _rmtree(tmp)
