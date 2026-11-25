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
    assert run_menu(_feed(["3"]), lambda s: None) == 0


def test_scan_and_save(tmp_path):
    src = tmp_path / "app.py"
    src.write_text('password = "hunter2hunter2"\n')
    report = tmp_path / "r.json"
    lines = []
    run_menu(_feed(["1", f'"{src}"', "2", str(report), "3"]), lines.append)
    assert any("CS-" in l for l in lines)
    assert report.read_text().startswith("[")


def test_invalid_path_and_option():
    lines = []
    run_menu(_feed(["9", "1", "/no/such/path", "3"]), lines.append)
    text = "\n".join(lines)
    assert "Invalid option" in text and "Path not found" in text


def test_save_without_scan():
    lines = []
    run_menu(_feed(["2", "3"]), lines.append)
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
