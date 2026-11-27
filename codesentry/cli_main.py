# cli_main.py
# Command-line entry point.

import os
import sys
import argparse

from . import __version__
from .scan_engine import scan, MAX_FILE_BYTES
from .report_output import as_text, as_json, as_sarif, as_html
from .rules_db import SEVERITY_ORDER
from .deps_check import check_deps, find_manifests, not_checked_warning, DepsError
from .history_scan import scan_history, is_git_repo, HistoryError
from .repo_fetch import is_repo_url, scan_repo, RepoError


def _file_size(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 (no limit) or more")
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codesentry",
        description="Find hardcoded secrets and common vulnerabilities in source code.")
    p.add_argument("paths", nargs="*", help="files, folders or GitHub repo links to scan (no paths: open the menu)")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif", "html"], default="text",
                   help="output format (default: text)")
    p.add_argument("-s", "--min-severity", choices=list(SEVERITY_ORDER), default="LOW",
                   type=str.upper, help="only report findings at or above this level")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH", type=str.upper,
                   help="exit with code 1 if a finding at or above this level exists (default: HIGH)")
    p.add_argument("-e", "--exclude", action="append", default=[], metavar="GLOB",
                   help="glob to skip (repeatable), relative to the scanned folder or a "
                        "file/folder name; '**' crosses folders, e.g. --exclude 'tests/*'")
    p.add_argument("--max-file-size", type=_file_size, default=MAX_FILE_BYTES, metavar="BYTES",
                   help=f"skip files larger than this and list them on stderr "
                        f"(default: {MAX_FILE_BYTES}; 0 = no limit)")
    p.add_argument("--keep", action="store_true",
                   help="keep the downloaded copy of GitHub repos (see the menu to delete it)")
    p.add_argument("--deps", action="store_true",
                   help="also check pinned dependencies (requirements.txt, package.json) "
                        "for known vulnerabilities via OSV.dev (sends package names and versions)")
    p.add_argument("--history", action="store_true",
                   help="also look for secrets in the git history of local repositories (committed once, later removed)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to a file")
    p.add_argument("-v", "--version", action="version", version=f"codesentry {__version__}")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.paths:
        if sys.stdin.isatty():
            from .menu_ui import start
            return start()
        parser.error("the following arguments are required: paths")

    links = [p for p in args.paths if not os.path.exists(p) and is_repo_url(p)]
    local = [p for p in args.paths if p not in links]
    missing = [p for p in local if not os.path.exists(p)]
    if missing:
        print(f"Path not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    skipped = []
    findings = scan(local, args.exclude, args.min_severity, args.max_file_size, skipped) if local else []
    warnings = []
    if args.deps and local:
        unchecked: list = []
        try:
            findings += check_deps(find_manifests(local, args.exclude), args.min_severity, unchecked)
        except DepsError as exc:
            warnings.append(f"dependency check failed: {exc}")
        if unchecked:
            warnings.append(not_checked_warning(unchecked))
    if args.history:
        for p in local:
            if not is_git_repo(p):
                warnings.append(f"{p} is not the root of a git repository, history skipped")
                continue
            try:
                findings += scan_history(p, findings, args.min_severity, args.exclude)
            except HistoryError as exc:
                warnings.append(f"{p}: {exc}")
    for link in links:
        try:
            findings += scan_repo(link, args.min_severity, args.exclude, args.max_file_size, skipped,
                                  args.keep, args.deps, warnings)
        except RepoError as exc:
            print(f"codesentry: {link}: {exc}", file=sys.stderr)
            return 2
    findings.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line, x.column))
    for w in warnings:
        print(f"codesentry: {w}", file=sys.stderr)
    for s in skipped:
        print(f"codesentry: skipped {s.file}: {s.reason}", file=sys.stderr)

    if args.format == "json":
        report = as_json(findings)
    elif args.format == "html":
        report = as_html(findings, __version__, skipped)
    elif args.format == "sarif":
        report = as_sarif(findings, __version__, skipped)
    else:
        report = as_text(findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= limit for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
