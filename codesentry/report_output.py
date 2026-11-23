# report_output.py
# Output formatters: text, JSON and SARIF 2.1.0 (GitHub code scanning).

import json
from typing import List, Sequence

from .scan_engine import Finding, SkippedFile
from .rules_db import RULES, SEVERITY_ORDER

_SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def as_text(findings: List[Finding]) -> str:
    if not findings:
        return "No issues found."
    out = []
    for f in findings:
        out.append(f"[{f.severity}] {f.rule_id} {f.file}:{f.line}")
        out.append(f"    {f.name} ({f.cwe})")
        out.append(f"    > {f.snippet}")
        out.append(f"    fix: {f.fix}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    out.append(f"\nTotal: {len(findings)} | HIGH: {counts['HIGH']} | "
               f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']}")
    return "\n".join(out)


def as_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False)


def as_sarif(findings: List[Finding], version: str, skipped: Sequence[SkippedFile] = ()) -> str:
    rules = [{
        "id": r.id,
        "name": r.name,
        "shortDescription": {"text": r.name},
        "help": {"text": r.fix},
        "properties": {"tags": [r.cwe]},
    } for r in RULES]
    results = [{
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.name}. {f.fix}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file.replace("\\", "/")},
            "region": {"startLine": f.line, "startColumn": f.column},
        }}],
    } for f in findings]
    run = {
        "tool": {"driver": {"name": "CodeSentry", "version": version, "rules": rules}},
        "results": results,
    }
    if skipped:
        # Files that were not scanned are not "clean": say so in the run.
        run["invocations"] = [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [{
                "level": "warning",
                "message": {"text": f"File not scanned: {s.reason}."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": s.file.replace("\\", "/")}}}],
            } for s in skipped],
        }]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(doc, indent=2)
