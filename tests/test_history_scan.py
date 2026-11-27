# test_history_scan.py
import os
import subprocess

import pytest

from codesentry.cli_main import main
from codesentry.history_scan import scan_history, is_git_repo
from codesentry.menu_ui import run_menu

SECRET = 'password = "hunter2hunter2"\n'


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo, check=True,
                   capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "config.py").write_text("DEBUG = 1\n" + SECRET)
    (tmp_path / "keep.py").write_text('token = "abcdefghijklmnop1234"\n')
    _git(tmp_path, "add", "."); _git(tmp_path, "commit", "-qm", "first")
    (tmp_path / "config.py").write_text("DEBUG = 1\n")           # secret removed...
    _git(tmp_path, "commit", "-qam", "remove secret")             # ...but still in history
    return tmp_path


def test_finds_a_removed_secret_at_the_commit_that_added_it(repo):
    found = scan_history(str(repo))
    removed = [f for f in found if f.file.startswith("config.py")]
    assert len(removed) == 1
    f = removed[0]
    assert f.rule_id.startswith("CS-SEC") and f.line == 2 and "(commit " in f.file
    assert "hunter2" not in f.snippet and "revoke" in f.fix


def test_secret_still_in_the_files_is_left_to_the_normal_scan(repo):
    from codesentry.scan_engine import scan
    current = scan([str(repo)])
    assert any(f.file.endswith("keep.py") for f in current)
    assert not any(f.file.startswith("keep.py") for f in scan_history(str(repo), current))


def test_is_git_repo(repo, tmp_path_factory):
    assert is_git_repo(str(repo)) and not is_git_repo(str(tmp_path_factory.mktemp("plain")))


def test_cli_history_flag(repo, capsys, tmp_path_factory):
    assert main([str(repo), "--history"]) == 1
    out = capsys.readouterr().out
    assert "config.py (commit" in out
    main([str(repo)])
    assert "(commit" not in capsys.readouterr().out          # off by default
    plain = tmp_path_factory.mktemp("plain")
    main([str(plain), "--history"])
    assert "not the root of a git repository" in capsys.readouterr().err


def _feed(answers):
    it = iter(answers)
    return lambda prompt="": next(it)


def test_menu_asks_about_history_only_for_git_folders(repo, tmp_path_factory):
    lines = []
    run_menu(_feed(["1", str(repo), "", "b", "6"]), lines.append)
    assert any("(commit " in l for l in lines)
    plain = tmp_path_factory.mktemp("plain")
    run_menu(_feed(["1", str(plain), "b", "6"]), lambda s: None)    # no extra prompt


def test_exclude_globs_and_ignore_file_apply_to_history(repo):
    assert scan_history(str(repo), exclude_globs=["config.py"]) == [] or \
        not any(f.file.startswith("config.py") for f in scan_history(str(repo), exclude_globs=["config.py"]))
    (repo / ".codesentryignore").write_text("config.py\n")
    assert not any(f.file.startswith("config.py") for f in scan_history(str(repo)))


def _signed_commit(repo):
    """A commit with a (fake) signature, written directly as a git object."""
    _git(repo, "init", "-q")
    (repo / "a.txt").write_text("x\n")
    _git(repo, "add", ".")
    tree = subprocess.run(["git", "write-tree"], cwd=repo, capture_output=True, check=True).stdout.decode().strip()
    body = (f"tree {tree}\nauthor T <t@t> 1700000000 +0000\ncommitter T <t@t> 1700000000 +0000\n"
            "gpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n\nsigned\n")
    sha = subprocess.run(["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=repo, input=body.encode(),
                         capture_output=True, check=True).stdout.decode().strip()
    _git(repo, "update-ref", "HEAD", sha)


def test_history_does_not_run_programs_from_the_scanned_repo_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _signed_commit(repo)
    marker = tmp_path / "RAN"
    if os.name == "nt":
        program = tmp_path / "fake-gpg.bat"
        program.write_text(f'@echo off\r\necho ran > "{marker}"\r\nexit /b 1\r\n')
    else:
        program = tmp_path / "fake-gpg.sh"
        program.write_text(f'#!/bin/sh\necho ran > "{marker}"\nexit 1\n')
        program.chmod(0o755)
    # What a folder handed over by someone else can carry in its own .git/config.
    _git(repo, "config", "log.showSignature", "true")
    _git(repo, "config", "gpg.program", str(program).replace("\\", "/"))
    subprocess.run(["git", "log", "-1"], cwd=repo, capture_output=True)
    if not marker.exists():
        pytest.skip("this git does not verify signatures on log")
    marker.unlink()
    scan_history(str(repo))
    assert not marker.exists()


def test_excluded_folder_hides_its_files_in_the_history(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text(SECRET)
    _git(tmp_path, "add", "."); _git(tmp_path, "commit", "-qm", "fixture")
    assert scan_history(str(tmp_path))                                   # found without an ignore
    (tmp_path / ".codesentryignore").write_text("tests\n")
    assert scan_history(str(tmp_path)) == []
    assert scan_history(str(tmp_path), use_ignore_file=False)
