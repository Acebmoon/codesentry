# test_repo_fetch.py
import os
import subprocess

import pytest

from codesentry import repo_fetch
from codesentry.repo_fetch import parse_repo_url, scan_repo, RepoError
from codesentry.cli_main import main


@pytest.mark.parametrize("text,expected", [
    ("https://github.com/Acebmoon/codesentry", ("Acebmoon", "codesentry")),
    ("github.com/Acebmoon/codesentry.git", ("Acebmoon", "codesentry")),
    ("https://github.com/Acebmoon/codesentry/tree/main/docs", ("Acebmoon", "codesentry")),
    ("https://github.com/Acebmoon/codesentry/", ("Acebmoon", "codesentry")),
    ("https://evil.com/github.com/a/b", None),
    ("https://github.com/a", None),
    ("https://github.com/a/b;rm -rf", None),
    ("--upload-pack=x", None),
    ("./local/folder", None),
])
def test_parse_repo_url(text, expected):
    assert parse_repo_url(text) == expected


@pytest.fixture
def local_repo(tmp_path, monkeypatch):
    src = tmp_path / "origin"
    src.mkdir()
    (src / "app.py").write_text("x = eval(s)\n")
    (src / ".codesentryignore").write_text("app.py\n")
    try:
        os.symlink("/etc/hostname", src / "link.py")
    except (OSError, NotImplementedError):
        pass
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t")
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(src)] + cmd, check=True, env=env)
    monkeypatch.setattr(repo_fetch, "_clone_url", lambda o, r: "file://" + str(src))
    return src


def test_scan_repo_finds_issue_and_cleans_up(local_repo, tmp_path, monkeypatch):
    made = []
    real = repo_fetch.tempfile.mkdtemp
    monkeypatch.setattr(repo_fetch.tempfile, "mkdtemp", lambda **k: made.append(real(**k)) or made[-1])
    found = scan_repo("https://github.com/o/r")
    assert [f.rule_id for f in found] == ["CS-INJ-001"]   # remote .codesentryignore is not honored
    assert found[0].file == "o/r/app.py"
    assert made and not os.path.exists(made[0])


def test_scan_repo_bad_link():
    with pytest.raises(RepoError):
        scan_repo("https://example.com/x/y")


def test_cli_scans_link(local_repo, capsys):
    code = main(["https://github.com/o/r"])
    assert code == 1 and "o/r/app.py" in capsys.readouterr().out


def test_cli_reports_clone_failure(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(repo_fetch, "_clone_url", lambda o, r: "file://" + str(tmp_path / "nope"))
    assert main(["https://github.com/o/r"]) == 2
    assert "could not clone" in capsys.readouterr().err
