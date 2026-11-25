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

_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))"
    r"/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:/(?:tree|blob)/.*)?/?$")
CLONE_TIMEOUT = 120


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
    shutil.rmtree(os.path.join(root, ".git"), ignore_errors=True)
    for folder, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(folder, name)
            if os.path.islink(p):
                os.unlink(p)


def scan_repo(link: str, min_severity: str = "LOW", exclude_globs=(),
              max_file_bytes: Optional[int] = MAX_FILE_BYTES,
              skipped: Optional[List[SkippedFile]] = None) -> List[Finding]:
    """Findings for a GitHub repo, with paths shown as owner/repo/path. The temp
    clone is always deleted. The repo's own .codesentryignore is not honored."""
    parsed = parse_repo_url(link)
    if not parsed:
        raise RepoError("not a GitHub repository link (expected https://github.com/owner/repo)")
    owner, repo = parsed
    tmp = tempfile.mkdtemp(prefix="codesentry-")
    try:
        root = os.path.join(tmp, "repo")
        _clone(_clone_url(owner, repo), root)
        _drop_links_and_git(root)
        inner: List[SkippedFile] = []
        found = scan([root], exclude_globs, min_severity, max_file_bytes, inner, use_ignore_file=False)
        prefix = f"{owner}/{repo}"

        def shown(p: str) -> str:
            return prefix + "/" + os.path.relpath(p, root).replace(os.sep, "/")

        for f in found:
            f.file = shown(f.file)
        if skipped is not None:
            skipped.extend(SkippedFile(shown(s.file), s.reason) for s in inner)
        return found
    finally:
        _rmtree(tmp)
