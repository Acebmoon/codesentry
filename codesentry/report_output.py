# report_output.py
# Output formatters: text, JSON and SARIF 2.1.0 (GitHub code scanning).

import html
import json
from datetime import datetime, timezone
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


_HTML_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0c0c0c;color:#d6d6d6;font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
main{max-width:880px;margin:0 auto;padding:40px 20px 60px}
h1{margin:0;font-size:28px;letter-spacing:.35em;color:#ff5f5f;font-weight:700}
.sub{color:#6c6c6c;margin:4px 0 28px}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px;border-top:1px solid #262626;border-bottom:1px solid #262626;padding:14px 0}
.bar button{background:none;color:#d6d6d6;border:1px solid #2a2a2a;padding:5px 12px;font:inherit;cursor:pointer}
.bar button:hover{border-color:#555}
.bar button.on{border-color:#ff5f5f;color:#ff5f5f}
.f{border-left:3px solid #444;padding:6px 0 6px 14px;margin:0 0 20px}
.f.HIGH{border-color:#ff5f5f}.f.MEDIUM{border-color:#ffd75f}.f.LOW{border-color:#5fd7d7}
.top{color:#8a8a8a;word-break:break-all}
.sev{font-weight:700}.HIGH .sev{color:#ff5f5f}.MEDIUM .sev{color:#ffd75f}.LOW .sev{color:#5fd7d7}
.name{margin:2px 0}
pre{margin:6px 0;padding:8px 10px;background:#141414;color:#9e9e9e;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.fix{color:#8a8a8a}
.ok{color:#5fd75f}
.note{color:#6c6c6c;margin-top:30px}
.hide{display:none}
"""

_HTML_JS = """
var btns=document.querySelectorAll('.bar button'),cards=document.querySelectorAll('.f');
btns.forEach(function(b){b.addEventListener('click',function(){
btns.forEach(function(x){x.classList.remove('on')});b.classList.add('on');
var s=b.getAttribute('data-sev');
cards.forEach(function(c){c.classList.toggle('hide',s!=='ALL'&&c.getAttribute('data-sev')!==s)});
});});
"""

_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"


def as_html(findings: List[Finding], version: str, skipped: Sequence[SkippedFile] = (),
            generated: str = "") -> str:
    """One self-contained page (no external files, no network). Everything that comes from the
    scanned code is escaped."""
    esc = html.escape
    generated = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    buttons = [f'<button class="on" data-sev="ALL">All {len(findings)}</button>'] + [
        f'<button data-sev="{s}">{s.title()} {counts[s]}</button>' for s in ("HIGH", "MEDIUM", "LOW")]
    cards = []
    for f in findings:
        cards.append(
            f'<article class="f {esc(f.severity)}" data-sev="{esc(f.severity)}">'
            f'<div class="top"><span class="sev">[{esc(f.severity)}]</span> {esc(f.rule_id)} &nbsp; '
            f'{esc(f.file)}:{f.line}</div>'
            f'<div class="name">{esc(f.name)} <span class="top">({esc(f.cwe)})</span></div>'
            f'<pre>{esc(f.snippet)}</pre>'
            f'<div class="fix">fix: {esc(f.fix)}</div></article>')
    body = "\n".join(cards) if cards else '<p class="ok">No issues found.</p>'
    notes = "".join(f'<div>skipped {esc(s.file)}: {esc(s.reason)}</div>' for s in skipped)
    note_block = f'<div class="note">{notes}</div>' if notes else ""
    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        f'<title>CodeSentry report</title><style>{_HTML_CSS}</style></head><body><main>'
        f'<h1>CODESENTRY</h1><div class="sub">static code scanner v{esc(version)} &middot; {esc(generated)}</div>'
        f'<div class="bar">{"".join(buttons)}</div>\n{body}\n{note_block}'
        f'<script>{_HTML_JS}</script></main></body></html>\n')
