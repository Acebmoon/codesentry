# test_menu_ui.py
import pytest

from codesentry.menu_ui import run_menu, banner
from codesentry.cli_main import main


def _feed(answers):
    it = iter(answers)
    return lambda prompt="": next(it)


def test_banner_has_five_rows():
    assert banner().count("\n") == 4


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
