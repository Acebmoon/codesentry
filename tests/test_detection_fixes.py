# test_detection_fixes.py
# Regression tests for missed secrets, masking, excludes, skipped files and
# ignore markers. Every secret in this file is invented.

import json
import os
import time

from codesentry.cli_main import main
from codesentry.scan_engine import mask, scan, scan_file

SECRET = "Xk9#mQ2!pL"
SEC = "CS-SEC-007"


def _write(tmp_path, name, content):
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return str(f)


def _found(tmp_path, name, content, rule=None):
    return [f for f in scan_file(_write(tmp_path, name, content))
            if rule is None or f.rule_id == rule]


# ------------------------------------------------------------ keys never seen

def test_quoted_keys_are_detected(tmp_path):
    assert len(_found(tmp_path, "a.json", '{"password": "%s"}\n' % SECRET, SEC)) == 1
    assert len(_found(tmp_path, "b.py", 'cfg = {"api_key": "%s"}\n' % SECRET, SEC)) == 1
    assert len(_found(tmp_path, "c.py", "headers = {'x-api-key': '%s'}\n" % SECRET, SEC)) == 1


def test_quoted_keys_need_a_map_entry_and_a_value_that_is_not_a_version(tmp_path):
    # a multi-line JSON entry is still a key
    assert len(_found(tmp_path, "a.json", '{\n  "client_secret": "%s",\n  "x": 1\n}\n' % SECRET, SEC)) == 1
    # dependency names in package.json / lockfiles
    assert _found(tmp_path, "package.json", '{"@tokenizer/token": "^0.3.0", "js-tokens": "~4.0.0"}\n', SEC) == []
    # a ternary between two strings is not a key and a value
    assert _found(tmp_path, "b.ts", "const mode = sms ? 'sms-token' : 'screen-signature';\n", SEC) == []


def test_prefixed_and_camel_case_keys_are_detected(tmp_path):
    for i, line in enumerate([
        'DB_PASSWORD = "%s"\n',
        'client_secret = "%s"\n',
        'const clientSecret = "%s";\n',
        'self._password = "%s"\n',
        'export GITHUB_TOKEN="%s"\n',
    ]):
        assert len(_found(tmp_path, f"k{i}.ts", line % SECRET, SEC)) == 1, line


# ------------------------------------------------------------ every match

def test_every_match_on_a_line_is_reported_with_its_column(tmp_path):
    line = 'cfg = {password: "%s", token: "Zr7$wN4@vB"}\n' % SECRET
    found = _found(tmp_path, "a.js", line, SEC)
    assert [f.column for f in found] == [line.index("password") + 1, line.index("token") + 1]


# ------------------------------------------------------------ passphrases

def test_passphrases_are_detected_but_ui_text_is_not(tmp_path):
    assert len(_found(tmp_path, "a.py", "senha = 'minha senha forte 2024'\n", SEC)) == 1
    assert len(_found(tmp_path, "b.py", 'auth_header = "Bearer 9f8a7b6c5d4e3f2a1b0c"\n', SEC)) == 1
    for i, text in enumerate([
        'const m = { password: "Senha incorreta" };\n',
        'secret_hint = "Do not share this!"\n',
        'secret_question = "What was your first car in 1999?"\n',
        'password_rule = "Use at least 8 characters with 1 digit and 1 symbol"\n',
    ]):
        assert _found(tmp_path, f"t{i}.ts", text, SEC) == [], text


# ------------------------------------------------------------ placeholders

def test_placeholder_hints_look_at_the_value_as_whole_words(tmp_path):
    assert len(_found(tmp_path, "a.py", 'password = "Contest#2024"\n', SEC)) == 1
    assert len(_found(tmp_path, "b.py", 'secret = "Latest-Build-9x"\n', SEC)) == 1
    # a hint in the key name does not hide the value
    assert len(_found(tmp_path, "c.py", 'token_example_field = "%s"\n' % SECRET, SEC)) == 1
    for i, value in enumerate(["changeme123", "<your-password>", "${DB_PASS}", "test-secret-value",
                               "your_api_key_here", "xxxxxxxx", "{{ db_pass }}"]):
        assert _found(tmp_path, f"p{i}.py", 'password = "%s"\n' % value, SEC) == [], value


def test_url_credentials_placeholders(tmp_path):
    rule = "CS-SEC-008"
    assert len(_found(tmp_path, "a.py", 'DSN = "postgres://admin:Contest2024@db.internal/app"\n', rule)) == 1
    assert _found(tmp_path, "b.py", 'DSN = "https://user:<password>@example.com/x"\n', rule) == []


# ------------------------------------------------------------ 0.0.0.0

def test_bind_all_needs_the_whole_address(tmp_path):
    rule = "CS-CFG-002"
    assert _found(tmp_path, "a.py", 'ALLOWED = "10.0.0.0/8"\n', rule) == []
    assert _found(tmp_path, "b.py", 'X = "100.0.0.0"\n', rule) == []
    for i, line in enumerate(['HOST = "0.0.0.0"\n', 'bind = "0.0.0.0:8080"\n', 'print("listens on 0.0.0.0.")\n']):
        assert len(_found(tmp_path, f"c{i}.py", line, rule)) == 1, line


# ------------------------------------------------------------ excludes

def test_exclude_globs_are_relative_to_the_scanned_folder(tmp_path, monkeypatch):
    for name in ("tests/t.py", "sub/deep/d.py", "keep.py"):
        _write(tmp_path, name, "x = eval(s)\n")
    monkeypatch.chdir(tmp_path)

    def left(*globs):
        return sorted(os.path.relpath(f.file).replace(os.sep, "/") for f in scan(["."], globs))

    assert left("tests/*") == ["keep.py", "sub/deep/d.py"]
    assert left("./tests/*") == ["keep.py", "sub/deep/d.py"]
    assert left("sub/**") == ["keep.py", "tests/t.py"]
    assert left("**/deep/*") == ["keep.py", "tests/t.py"]
    assert left("tests") == ["keep.py", "sub/deep/d.py"]        # a folder name still works
    assert left("keep.py") == ["sub/deep/d.py", "tests/t.py"]    # a file name still works
    assert len(scan([str(tmp_path)], ["tests/*", "sub/**"])) == 1  # and with an absolute path


# ------------------------------------------------------------ skipped files

def test_large_files_are_reported_as_skipped(tmp_path, capsys):
    big = _write(tmp_path, "big.py", 'password = "%s"\n' % SECRET + "#" * 1_100_000 + "\n")
    skipped = []
    assert scan([big], skipped=skipped) == []
    assert [s.file for s in skipped] == [big]
    assert "larger than" in skipped[0].reason

    assert main([big, "-f", "sarif"]) == 0
    out = capsys.readouterr()
    assert "skipped" in out.err and "big.py" in out.err
    note = json.loads(out.out)["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("big.py")

    assert main([big, "--max-file-size", "0"]) == 1  # 0 = no limit: the secret is found


# ------------------------------------------------------------ ignore markers

def test_ignore_markers_must_be_a_word_in_a_comment(tmp_path):
    assert len(_found(tmp_path, "a.py", 'api_key = "%s"  # docs: nosecurity.md\n' % SECRET)) == 1
    assert len(_found(tmp_path, "b.py", 'token = "nosecure-%s"\n' % SECRET)) == 1
    assert _found(tmp_path, "c.py", "x = eval(s)  # nosec\n") == []
    assert _found(tmp_path, "d.js", "x = eval(s); // codesentry:ignore\n") == []
    assert _found(tmp_path, "e.yaml", "bind: 0.0.0.0  # nosec\n") == []


def test_ignore_markers_can_name_the_rules(tmp_path):
    line = 'x = eval(s); password = "%s"  # codesentry:ignore[CS-SEC-007]\n' % SECRET
    assert [f.rule_id for f in _found(tmp_path, "a.py", line)] == ["CS-INJ-001"]
    line = 'x = eval(s); password = "%s"  # nosec[CS-INJ-001, CS-SEC-007]\n' % SECRET
    assert _found(tmp_path, "b.py", line) == []


# ------------------------------------------------------------ long lines

def test_long_minified_lines_scan_in_linear_time(tmp_path):
    # Each line used to take seconds (100k chars) to minutes (1M): unanchored or
    # unbounded repeats were retried at every position of the line.
    lines = ["a" * 100_000, "token_" * 16_000, "aB3-_" * 20_000, "#" * 100_000, 'a:"x' * 25_000]
    p = _write(tmp_path, "min.py", "\n".join(lines) + "\n")
    start = time.perf_counter()
    scan_file(p, max_file_bytes=0)
    assert time.perf_counter() - start < 5


# ------------------------------------------------------------ masking

def test_only_the_secret_is_masked_and_it_never_shows(tmp_path, capsys):
    p = _write(tmp_path, "a.py", 'password = "%s"\n' % SECRET)
    [finding] = [f for f in scan([p]) if f.rule_id == SEC]
    assert finding.snippet == 'password = "****"'
    for fmt in ("text", "json", "sarif"):
        main([p, "-f", fmt])
        assert SECRET[-3:] not in capsys.readouterr().out, fmt
    assert mask("hunter2") == "****"
    assert mask("AKIAIOSFODNN7EXAMPLE", reveal=4) == "AKIA****"
