# test_deps_check.py
import json

import pytest

from codesentry import deps_check
from codesentry.cli_main import main
from codesentry.menu_ui import run_menu


def _fake_osv(monkeypatch, vulns_by_name):
    """Pretend to be OSV.dev: vulns_by_name maps package name -> list of vuln ids."""
    def post(url, payload):
        return {"results": [{"vulns": [{"id": i} for i in vulns_by_name.get(q["package"]["name"], [])]}
                            for q in payload["queries"]]}

    def get(url):
        vid = url.rsplit("/", 1)[1]
        return {"id": vid, "summary": "Bad thing", "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
                "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}]}
    monkeypatch.setattr(deps_check, "_post", post)
    monkeypatch.setattr(deps_check, "_get", get)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# deps\nflask==2.0.1  # web\nrequests[socks]==2.31.0 ; python_version>'3'\nnumpy>=1.0\n-r other.txt\n")
    (tmp_path / "package.json").write_text(json.dumps(
        {"dependencies": {"lodash": "^4.17.15", "left-pad": "*", "mylib": "git+https://x/y.git"},
         "devDependencies": {"mocha": "~8.0.0"}}, indent=2))
    return tmp_path


def test_reads_only_pinned_and_numeric_versions(project):
    deps = deps_check.read_deps(deps_check.find_manifests([str(project)]))
    got = {(d.ecosystem, d.name, d.version) for d in deps}
    assert got == {("PyPI", "flask", "2.0.1"), ("PyPI", "requests", "2.31.0"),
                   ("npm", "lodash", "4.17.15"), ("npm", "mocha", "8.0.0")}


def test_reports_vulnerable_dependency_with_fix(project, monkeypatch):
    _fake_osv(monkeypatch, {"flask": ["GHSA-aaaa"]})
    findings = deps_check.check_deps(deps_check.find_manifests([str(project)]))
    assert len(findings) == 1
    f = findings[0]
    assert (f.rule_id, f.severity, f.cwe, f.line) == ("GHSA-aaaa", "HIGH", "CWE-79", 2)
    assert f.file.endswith("requirements.txt") and "2.2.5" in f.fix and "flask 2.0.1" in f.snippet


def test_min_severity_filters(project, monkeypatch):
    _fake_osv(monkeypatch, {"flask": ["GHSA-aaaa"]})
    monkeypatch.setattr(deps_check, "_get", lambda url: {"id": "X", "database_specific": {"severity": "LOW"}})
    assert deps_check.check_deps(deps_check.find_manifests([str(project)]), "HIGH") == []


def test_network_failure_raises_deps_error(project, monkeypatch):
    def boom(*a):
        raise OSError("offline")
    monkeypatch.setattr(deps_check, "_post", boom)
    with pytest.raises(deps_check.DepsError):
        deps_check.check_deps(deps_check.find_manifests([str(project)]))


def test_no_manifests_means_no_network(tmp_path, monkeypatch):
    monkeypatch.setattr(deps_check, "_post", lambda *a: pytest.fail("no request expected"))
    assert deps_check.check_deps([]) == []


def test_cli_deps_flag(project, monkeypatch, capsys):
    _fake_osv(monkeypatch, {"flask": ["GHSA-aaaa"]})
    assert main([str(project), "--deps"]) == 1
    assert "GHSA-aaaa" in capsys.readouterr().out
    assert main([str(project)]) == 0          # off by default: nothing sent


def test_cli_deps_offline_warns_but_still_scans(project, monkeypatch, capsys):
    monkeypatch.setattr(deps_check, "_post", lambda *a: (_ for _ in ()).throw(OSError("offline")))
    assert main([str(project), "--deps"]) == 0
    assert "dependency check failed" in capsys.readouterr().err


def _feed(answers):
    it = iter(answers)
    return lambda prompt="": next(it)


def test_menu_asks_about_deps_only_when_manifests_exist(project, tmp_path, monkeypatch):
    _fake_osv(monkeypatch, {"flask": ["GHSA-aaaa"]})
    lines = []
    run_menu(_feed(["1", str(project), "", "b", "6"]), lines.append)   # Enter = yes
    assert any("GHSA-aaaa" in l for l in lines)
    empty = tmp_path / "empty"
    empty.mkdir()
    run_menu(_feed(["1", str(empty), "b", "6"]), lambda s: None)
    monkeypatch.setattr(deps_check, "_post", lambda *a: pytest.fail("said no: nothing may be sent"))
    run_menu(_feed(["1", str(project), "n", "b", "6"]), lambda s: None)   # no extra prompt, would StopIteration


def test_same_flaw_with_two_ids_is_reported_once_and_git_ranges_are_not_versions(project, monkeypatch):
    _fake_osv(monkeypatch, {"flask": ["PYSEC-1", "GHSA-aaaa", "GHSA-other"]})

    def get(url):
        vid = url.rsplit("/", 1)[1]
        aliases = {"PYSEC-1": ["CVE-1"], "GHSA-aaaa": ["CVE-1"], "GHSA-other": ["CVE-2"]}[vid]
        return {"id": vid, "aliases": aliases, "summary": "s", "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"}, "ranges": [
                    {"type": "GIT", "events": [{"fixed": "deadbeef"}]},
                    {"type": "ECOSYSTEM", "events": [{"fixed": "2.2.5"}]}]}]}
    monkeypatch.setattr(deps_check, "_get", get)
    findings = deps_check.check_deps(deps_check.find_manifests([str(project)]))
    assert sorted(f.rule_id for f in findings) == ["GHSA-aaaa", "GHSA-other"]
    assert all("2.2.5" in f.fix and "deadbeef" not in f.fix for f in findings)
