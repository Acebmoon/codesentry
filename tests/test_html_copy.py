# test_html_copy.py
import re

import pytest

from codesentry import clipboard, menu_ui
from codesentry.cli_main import main
from codesentry.menu_ui import run_menu
from codesentry.report_output import as_html
from codesentry.scan_engine import Finding, scan


def _finding(**kw):
    base = dict(rule_id="CS-INJ-001", name="eval/exec call", severity="HIGH", cwe="CWE-95",
                file="app.py", line=3, snippet="x = eval(s)", fix="Avoid eval.")
    base.update(kw)
    return Finding(**base)


def test_html_is_one_self_contained_page():
    page = as_html([_finding(), _finding(severity="LOW", rule_id="CS-X")], "1.2.3", generated="today")
    assert page.startswith("<!DOCTYPE html>") and "CODESENTRY" in page and "v1.2.3" in page
    assert "All 2" in page and "High 1" in page and "Low 1" in page and "Medium 0" in page
    assert "app.py:3" in page and "Avoid eval." in page
    assert not re.search(r'(?:src|href)\s*=\s*["\']?https?:', page)         # nothing loaded from the network
    assert "Content-Security-Policy" in page


def test_html_escapes_everything_that_comes_from_the_scanned_code():
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    page = as_html([_finding(snippet=evil, file=evil, name=evil, fix=evil, rule_id=evil, cwe=evil)], "1")
    assert evil not in page
    assert page.count("<script>") == 1                       # only our own filter script
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_html_without_findings_and_with_skipped_files():
    from codesentry.scan_engine import SkippedFile
    page = as_html([], "1", [SkippedFile("big.bin", "larger than 10 bytes")])
    assert "No issues found." in page and "skipped big.bin" in page


def test_cli_html_format(tmp_path, capsys):
    src = tmp_path / "a.py"
    src.write_text("x = eval(s)\n")
    out = tmp_path / "r.html"
    assert main([str(src), "-f", "html", "-o", str(out)]) == 1
    assert "CS-INJ-001" in out.read_text(encoding="utf-8")


def test_copy_uses_an_available_tool(monkeypatch):
    calls = []
    monkeypatch.setattr(clipboard.os, "name", "posix")
    monkeypatch.setattr(clipboard.shutil, "which", lambda n: "/usr/bin/" + n if n == "xclip" else None)
    monkeypatch.setattr(clipboard.subprocess, "run", lambda cmd, **kw: calls.append((cmd, kw["input"])))
    clipboard.copy_text("héllo")
    assert calls == [(["xclip", "-selection", "clipboard"], "héllo".encode("utf-8"))]


def test_copy_without_any_clipboard_raises(monkeypatch):
    monkeypatch.setattr(clipboard.os, "name", "posix")
    monkeypatch.setattr(clipboard.shutil, "which", lambda n: None)
    monkeypatch.setattr(clipboard.sys.stdout, "isatty", lambda: False, raising=False)
    with pytest.raises(clipboard.ClipboardError):
        clipboard.copy_text("x")


def _feed(answers):
    it = iter(answers)
    return lambda prompt="": next(it)


@pytest.fixture
def src(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = eval(s)\npassword = 'hunter2hunter2'\n")
    return f


def test_results_screen_copy_and_html(src, tmp_path, monkeypatch):
    copied, opened = [], []
    monkeypatch.setattr(menu_ui, "copy_text", copied.append)
    monkeypatch.setattr(menu_ui.webbrowser, "open", opened.append)
    page = tmp_path / "out.html"
    lines = []
    # filter High, copy (only what is shown), HTML report -> open it, back, exit
    run_menu(_feed(["1", str(src), "h", "c", "r", str(page), "", "b", "6"]), lines.append)
    assert len(copied) == 1 and "CS-SEC-007" in copied[0] and "CS-INJ-001" in copied[0]
    assert "Copied" in "\n".join(lines)
    assert page.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert len(opened) == 1 and opened[0].startswith("file://")


def test_copy_failure_is_a_message_not_a_crash(src, monkeypatch):
    def boom(text):
        raise clipboard.ClipboardError("no tool")
    monkeypatch.setattr(menu_ui, "copy_text", boom)
    lines = []
    run_menu(_feed(["1", str(src), "c", "b", "6"]), lines.append)
    assert any("Could not copy: no tool" in l for l in lines)


def test_export_screen_has_html_json_and_copy(src, tmp_path, monkeypatch):
    copied = []
    monkeypatch.setattr(menu_ui, "copy_text", copied.append)
    monkeypatch.setattr(menu_ui.webbrowser, "open", lambda url: None)
    html_file, json_file = tmp_path / "r.html", tmp_path / "r.json"
    run_menu(_feed(["1", str(src), "b",
                    "4", "1", str(html_file), "n", "",        # HTML, don't open
                    "4", "2", str(json_file), "",             # JSON
                    "4", "3", "",                             # copy
                    "4", "9", "",                             # invalid
                    "6"]), lambda s: None)
    assert html_file.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert json_file.read_text(encoding="utf-8").startswith("[")
    assert len(copied) == 1 and "CS-INJ-001" in copied[0]
