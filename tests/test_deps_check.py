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


@pytest.fixture
def locked(tmp_path):
    """A project with package-lock.json v3: the installed version, a transitive package twice."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.0.0"}}, indent=2))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"express": "^4.0.0"}},
        "node_modules/express": {"version": "4.17.1"},
        "node_modules/qs": {"version": "6.5.2"},
        "node_modules/body-parser/node_modules/qs": {"version": "6.5.2"},
        "node_modules/local-lib": {"link": True},
    }}, indent=2))
    return tmp_path


def test_lock_file_gives_installed_and_transitive_versions(locked):
    deps = deps_check.read_deps(deps_check.find_manifests([str(locked)]))
    assert {(d.name, d.version) for d in deps} == {("express", "4.17.1"), ("qs", "6.5.2")}
    assert all(d.file.endswith("package-lock.json") for d in deps)     # the package.json range is not read


def test_lock_finding_points_at_the_package_line(locked, monkeypatch):
    _fake_osv(monkeypatch, {"qs": ["GHSA-qs"]})
    monkeypatch.setattr(deps_check, "_get", lambda url: {"id": "GHSA-qs", "summary": "s",
                        "database_specific": {"severity": "HIGH"}, "affected": []})
    [f] = deps_check.check_deps(deps_check.find_manifests([str(locked)]))
    lines = (locked / "package-lock.json").read_text().splitlines()
    assert f.file.endswith("package-lock.json") and '"node_modules/qs"' in lines[f.line - 1]


def test_lock_file_version_1(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}, indent=2))
    deps = deps_check.read_deps([str(tmp_path / "package-lock.json")])
    assert {(d.name, d.version) for d in deps} == {("a", "1.0.0"), ("b", "2.0.0")}


def test_specs_that_cannot_be_checked_are_listed(project, monkeypatch, capsys):
    unchecked = []
    deps_check.read_deps(deps_check.find_manifests([str(project)]), unchecked)
    assert sorted(unchecked) == ["left-pad *", "mylib git+https://x/y.git"]
    _fake_osv(monkeypatch, {})
    main([str(project), "--deps"])
    assert "2 dependencies not checked" in capsys.readouterr().err


def test_queries_go_in_batches(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("".join(f"pkg{i}==1.0.{i}\n" for i in range(5)))
    sizes = []
    monkeypatch.setattr(deps_check, "OSV_BATCH_SIZE", 2)
    monkeypatch.setattr(deps_check, "_post", lambda url, p: sizes.append(len(p["queries"])) or
                        {"results": [{} for _ in p["queries"]]})
    assert deps_check.check_deps([str(tmp_path / "requirements.txt")]) == []
    assert sizes == [2, 2, 1]


def test_fix_comes_from_the_range_that_contains_the_version():
    vuln = {"affected": [{"package": {"ecosystem": "npm", "name": "lib"}, "ranges": [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.0"}]}]}]}
    fixed = lambda v: deps_check._fixed_version(vuln, deps_check.Dep("lib", v, "npm", "x", 1))  # noqa: E731
    assert (fixed("2.1.0"), fixed("1.2.0")) == ("2.3.0", "1.5.0")
    key = deps_check._version_key
    assert key("1.10.0") > key("1.9.9") and key("2.0.0-rc.1") < key("2.0.0") and key("1.2") == key("1.2.0")


def test_package_json_line_is_the_dependency_not_a_script(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"scripts": {"minimist": "node x.js"}, "dependencies": {"minimist": "1.2.0"}}, indent=2))
    [d] = deps_check.read_deps([str(tmp_path / "package.json")])
    lines = (tmp_path / "package.json").read_text().splitlines()
    assert '"minimist": "1.2.0"' in lines[d.line - 1]
