# test_scan_engine.py
# Unit tests for the scanner and CLI.

import json
from codesentry.scan_engine import scan
from codesentry.cli_main import main


def _write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return str(f)


def _ids(findings):
    return {f.rule_id for f in findings}


def test_detects_aws_key_and_masks_it(tmp_path):
    p = _write(tmp_path, "a.py", 'k = "AKIAIOSFODNN7EXAMPLE"\n')
    res = scan([p])
    assert "CS-SEC-001" in _ids(res)
    assert "IOSFODNN7EX" not in res[0].snippet


def test_detects_hardcoded_password(tmp_path):
    p = _write(tmp_path, "a.py", 'password = "Sup3rS3cretValue"\n')
    assert "CS-SEC-007" in _ids(scan([p]))


def test_placeholder_is_ignored(tmp_path):
    p = _write(tmp_path, "a.py", 'password = "changeme123"\n')
    assert "CS-SEC-007" not in _ids(scan([p]))


def test_python_rules(tmp_path):
    code = ('import os, pickle\n'
            'os.system("ls " + x)\n'
            'pickle.loads(d)\n'
            'requests.get(u, verify=False)\n')
    ids = _ids(scan([_write(tmp_path, "a.py", code)]))
    assert {"CS-INJ-002", "CS-DES-001", "CS-CRY-002"} <= ids


def test_c_rules_only_apply_to_c_files(tmp_path):
    c = _write(tmp_path, "a.c", "strcpy(a, b);\n")
    py = _write(tmp_path, "b.py", "strcpy(a, b)\n")
    assert "CS-MEM-001" in _ids(scan([c]))
    assert "CS-MEM-001" not in _ids(scan([py]))


def test_inline_ignore(tmp_path):
    p = _write(tmp_path, "a.py", 'x = eval(s)  # nosec\n')
    assert scan([p]) == []


def test_exclude_glob(tmp_path):
    _write(tmp_path, "skip.py", "x = eval(s)\n")
    assert scan([str(tmp_path)], exclude_globs=["skip.py"]) == []


def test_min_severity_filter(tmp_path):
    p = _write(tmp_path, "a.py", 'h = "0.0.0.0"\nx = eval(s)\n')
    res = scan([p], min_severity="HIGH")
    assert _ids(res) == {"CS-INJ-001"}


def test_cli_exit_codes_and_json(tmp_path, capsys):
    bad = _write(tmp_path, "bad.py", "x = eval(s)\n")
    good = _write(tmp_path, "good.py", "x = 1\n")
    assert main([good]) == 0
    capsys.readouterr()
    assert main([bad, "-f", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["rule_id"] == "CS-INJ-001"
    assert main([str(tmp_path / "nope")]) == 2


def test_sarif_output_is_valid_json(tmp_path, capsys):
    bad = _write(tmp_path, "bad.py", "x = eval(s)\n")
    main([bad, "-f", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "CS-INJ-001"
