# test_false_positives.py
# Things CodeSentry used to flag by mistake (found scanning a real training repo).

from codesentry.scan_engine import scan_file


def _ids(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return [f.rule_id for f in scan_file(str(p))]


def test_commented_out_code_is_not_flagged(tmp_path):
    assert _ids(tmp_path, "a.js", '//eval("page" + id + " = 1");\n') == []
    assert _ids(tmp_path, "b.py", "# x = eval(s)\n") == []
    assert _ids(tmp_path, "c.js", "/* x = eval(s) */\n") == []


def test_secret_in_a_comment_is_still_flagged(tmp_path):
    assert "CS-SEC-007" in _ids(tmp_path, "a.py", '# password = "Zx9!hunter2hunter2"\n')


def test_variable_as_password_value_is_not_a_secret(tmp_path):
    for value in ("$pass_new", "${DB_PASSWORD}", "{{ password }}", "%s", ":pw"):
        assert "CS-SEC-007" not in _ids(tmp_path, "a.php", f"password = '{value}'\n"), value
    assert "CS-SEC-007" in _ids(tmp_path, "b.php", "password = 'Zx9!hunter2hunter2'\n")


def test_prepared_statement_is_not_sql_concatenation(tmp_path):
    line = "$d = $db->prepare( 'UPDATE users SET n = (n + 1) WHERE user = (:user) LIMIT 1;' );\n"
    assert _ids(tmp_path, "a.php", line) == []


def test_ui_text_with_update_is_not_sql(tmp_path):
    line = "cell.innerHTML = '<input type=\"button\" value=\"Update\" onclick=\"f(' + u['id'] + ')\" />';\n"
    assert "CS-INJ-005" not in _ids(tmp_path, "a.js", line)


def test_real_sql_concatenation_is_still_flagged(tmp_path):
    assert "CS-INJ-005" in _ids(tmp_path, "a.py", 'q = "SELECT * FROM t WHERE id = " + uid\n')
    assert "CS-INJ-016" in _ids(tmp_path, "b.js", "db.query(`SELECT * FROM t WHERE id = ${id}`)\n")


def test_jwt_verify_false_is_not_a_tls_finding_and_commented_debug_is_ignored(tmp_path):
    from codesentry.scan_engine import scan
    f = tmp_path / "a.py"
    f.write_text("decoded = jwt.decode(token, verify = False)\n"
                 "# app.run(debug = True, host = '0.0.0.0')\n"
                 "requests.get(url, verify=False)\n")
    ids = [x.rule_id for x in scan([str(f)])]
    assert "CS-JWT-001" in ids
    assert ids.count("CS-CRY-002") == 1            # only the requests call
    assert "CS-CFG-001" not in ids and "CS-CFG-002" not in ids
