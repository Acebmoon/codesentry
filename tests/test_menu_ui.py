# test_menu_ui.py
import pytest

from codesentry.menu_ui import run_menu, banner
from codesentry.cli_main import main


def _feed(answers):
    it = iter(answers)
    return lambda prompt="": next(it)


def test_banner_fits_80_columns():
    import re
    lines = re.sub(r"\x1b\[[0-9;]*m", "", banner()).split("\n")
    assert max(len(l) for l in lines) <= 80 and len(lines) == 12


def test_exit_option():
    assert run_menu(_feed(["6"]), lambda s: None) == 0


def test_scan_and_save(tmp_path):
    src = tmp_path / "app.py"
    src.write_text('password = "hunter2hunter2"\n')
    report = tmp_path / "r.json"
    lines = []
    run_menu(_feed(["1", f'"{src}"', "b", "4", str(report), "6"]), lines.append)
    assert any("CS-" in l for l in lines)
    assert report.read_text().startswith("[")


def test_invalid_path_and_option():
    lines = []
    run_menu(_feed(["9", "1", "/no/such/path", "6"]), lines.append)
    text = "\n".join(lines)
    assert "Invalid option" in text and "Path not found" in text


def test_save_without_scan():
    lines = []
    run_menu(_feed(["4", "6"]), lines.append)
    assert any("Run a scan first" in l for l in lines)


def test_no_args_non_interactive_fails(monkeypatch):
    class NoTty:
        def isatty(self):
            return False
    monkeypatch.setattr("sys.stdin", NoTty())
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2


def test_codesentryignore_file_is_honored(tmp_path):
    from codesentry.scan_engine import scan
    (tmp_path / "keep.py").write_text("x = eval(s)\n")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "bad.py").write_text("x = eval(s)\n")
    (tmp_path / ".codesentryignore").write_text("# skip fixtures\nfixtures\n")
    files = {f.file for f in scan([str(tmp_path)])}
    assert files == {str(tmp_path / "keep.py")}


def test_repo_scans_clean():
    import os
    from codesentry.scan_engine import scan
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert scan([root]) == []


def _findings_file(tmp_path, n=12):
    src = tmp_path / "many.py"
    src.write_text("".join(f'password{i} = "hunter2hunter{i}"\n' for i in range(n)) + "x = md5_sum\n"
                   "import hashlib; hashlib.md5(b'x')\n")
    return src


def test_results_screen_pages_filters_saves_and_goes_back(tmp_path, monkeypatch):
    monkeypatch.setattr("codesentry.menu_ui._per_page", lambda: 2)
    src = _findings_file(tmp_path)
    report = tmp_path / "out.json"
    cleared, lines = [], []
    run_menu(_feed(["1", str(src), "", "n", "p", "m", "a", "s", str(report), "", "b", "6"]),
             lines.append, lambda: cleared.append(1))
    text = "\n".join(lines)
    assert "RESULTS" in text and "Page 1/" in text and "Page 2/" in text
    assert "showing MEDIUM" in text and "Saved to" in text
    assert report.read_text().startswith("[")
    assert len(cleared) >= 5                       # every screen change starts clean


def test_results_screen_back_returns_to_the_menu(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("x = 1\n")
    lines = []
    run_menu(_feed(["1", str(src), "b", "6"]), lines.append)
    text = "\n".join(lines)
    assert "No issues found" in text and text.count("STATIC CODE SCANNER") == 2
