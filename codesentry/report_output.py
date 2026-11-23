# report_output.py
# Output formatters: text, JSON and SARIF 2.1.0 (GitHub code scanning).

import json
from typing import List

from .scan_engine import Finding
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


def as_sarif(findings: List[Finding], version: str) -> str:
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
            "region": {"startLine": f.line},
        }}],
    } for f in findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeSentry", "version": version, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
