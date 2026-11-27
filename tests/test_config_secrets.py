# test_config_secrets.py
# CS-SEC-023: secrets written without quotes in config files (.env, YAML, INI, .properties).

import pytest

from codesentry.report_output import as_json, as_text
from codesentry.scan_engine import scan_file

VALUE = "Xk9#mQ2!pL"


def _ids(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return [f.rule_id for f in scan_file(str(p))]


@pytest.mark.parametrize("name,text", [
    (".env", f"DB_PASSWORD={VALUE}\n"),
    (".env.production", f"export API_TOKEN={VALUE}\n"),
    ("app.yaml", f"db:\n  password: {VALUE}\n"),
    ("app.yml", f"- client_secret: {VALUE}\n"),
    ("db.ini", f"[db]\npassword = {VALUE} ; prod\n"),
    ("app.properties", f"db.password={VALUE}\n"),
    ("app.conf", f"apiKey: {VALUE}\n"),
    (".env", f"# OLD_SECRET={VALUE}\n"),          # commented out, but still in the file
])
def test_unquoted_secret_in_config_is_found(tmp_path, name, text):
    assert _ids(tmp_path, name, text).count("CS-SEC-023") == 1


@pytest.mark.parametrize("line", [
    "PASSWORD=${DB_PASS}",
    "TOKEN=changeme",
    "AUTH_ENABLED=true",
    "TOKEN_TTL=3600",
    "TOKEN_URL=https://auth.example.com/token",
    "PASSWORD_FILE=/run/secrets/db",
    "API_KEY=sk-ant-...",
    "API_KEY=",
    "AUTH_MODE=oauth2",
])
def test_config_values_that_are_not_secrets(tmp_path, line):
    assert "CS-SEC-023" not in _ids(tmp_path, ".env", line + "\n")


@pytest.mark.parametrize("text", [
    "password: !vault |\n",
    "tokenizer: bert-base-uncased\n",
    "author: MariaSilva1\n",
])
def test_yaml_tags_and_keys_that_only_start_alike(tmp_path, text):
    assert "CS-SEC-023" not in _ids(tmp_path, "app.yaml", text)


def test_quoted_value_is_left_to_cs_sec_007(tmp_path):
    ids = _ids(tmp_path, ".env", f'API_TOKEN="{VALUE}"\n')
    assert ids.count("CS-SEC-007") == 1 and "CS-SEC-023" not in ids


def test_not_applied_to_source_code(tmp_path):
    assert "CS-SEC-023" not in _ids(tmp_path, "settings.py", f"DB_PASSWORD={VALUE}\n")


def test_the_value_is_masked(tmp_path):
    p = tmp_path / ".env"
    p.write_text(f"DB_PASSWORD={VALUE}\n")
    found = scan_file(str(p))
    assert found and all(VALUE[i:i + 4] not in as_text(found) + as_json(found) for i in range(len(VALUE) - 3))
