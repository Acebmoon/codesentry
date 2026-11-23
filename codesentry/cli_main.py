# cli_main.py
# Command-line entry point.

import os
import sys
import argparse

from . import __version__
from .scan_engine import scan
from .report_output import as_text, as_json, as_sarif
from .rules_db import SEVERITY_ORDER


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codesentry",
        description="Find hardcoded secrets and common vulnerabilities in source code.")
    p.add_argument("paths", nargs="+", help="files or folders to scan")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text",
                   help="output format (default: text)")
    p.add_argument("-s", "--min-severity", choices=list(SEVERITY_ORDER), default="LOW",
                   type=str.upper, help="only report findings at or above this level")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH", type=str.upper,
                   help="exit with code 1 if a finding at or above this level exists (default: HIGH)")
    p.add_argument("-e", "--exclude", action="append", default=[], metavar="GLOB",
                   help="glob to skip (repeatable), e.g. --exclude 'tests/*'")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to a file")
    p.add_argument("-v", "--version", action="version", version=f"codesentry {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        print(f"Path not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    findings = scan(args.paths, args.exclude, args.min_severity)

    if args.format == "json":
        report = as_json(findings)
    elif args.format == "sarif":
        report = as_sarif(findings, __version__)
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
