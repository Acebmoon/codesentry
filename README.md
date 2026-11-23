# CodeSentry

Fast, dependency-free static scanner that finds **hardcoded secrets** and **common vulnerabilities** in your source code.

- Zero dependencies (pure Python 3.10+)
- Detects secrets, injection, unsafe deserialization, weak crypto, memory-unsafe C calls and risky configs
- Every finding includes a CWE id and a fix suggestion
- Secrets are masked in reports
- Output as text, JSON or **SARIF** (GitHub code scanning)
- CI-friendly exit codes

## Install

```bash
pip install git+https://github.com/Acebmoon/codesentry.git
```

Or from a clone:

```bash
git clone https://github.com/Acebmoon/codesentry.git
cd codesentry
pip install .
```

## Usage

```bash
codesentry path/to/project
codesentry app.py src/ --min-severity MEDIUM
codesentry . --exclude "tests/*" --format json -o report.json
codesentry . --format sarif -o results.sarif
python -m codesentry .
```

| Option | Description |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif` |
| `-s, --min-severity` | Report only `LOW`, `MEDIUM` or `HIGH` and above |
| `--fail-on` | Exit code 1 if a finding at/above this level exists (default `HIGH`) |
| `-e, --exclude` | Glob to skip, repeatable. Matched against the path relative to the scanned folder (`tests/*`, `sub/**`, `**/fixtures/*`) and against the file or folder name (`*.min.js`, `tests`) |
| `--max-file-size` | Skip files larger than this many bytes (default `1000000`, `0` = no limit). Skipped files are listed on stderr and, in SARIF, under `invocations` |
| `-o, --output` | Write the report to a file |

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` usage error.

Secrets are masked in every format: only the secret itself is hidden (`password = "****"`), and typed tokens keep their public prefix (`AKIA****`).

## Ignoring false positives

Add a `nosec` or `codesentry:ignore` comment to the line, in any comment style (`#`, `//`, `/* */`, `<!-- -->`, `--`). The marker must be a whole word inside the comment, so `nosecurity` or a string containing "nosec" do not silence anything.

To silence only some rules, list them: `# codesentry:ignore[CS-SEC-007]` or `// nosec[CS-INJ-001, CS-CFG-002]`.

## Rules

| ID | Detects | CWE |
|---|---|---|
| CS-SEC-001..008 | AWS/GitHub/Slack/Google keys, private keys, JWT, hardcoded passwords, credentials in URLs | CWE-798 |
| CS-INJ-001 | `eval` / `exec` | CWE-95 |
| CS-INJ-002/003/004 | OS command execution, `shell=True`, `Runtime.exec` | CWE-78 |
| CS-INJ-005 | SQL built by concatenation | CWE-89 |
| CS-INJ-006 | `innerHTML` / `document.write` | CWE-79 |
| CS-DES-001/002 | `pickle.load`, unsafe `yaml.load` | CWE-502 |
| CS-CRY-001/002/003 | MD5/SHA-1, TLS verification off, non-crypto RNG | CWE-327/295/338 |
| CS-MEM-001 | `gets`, `strcpy`, `sprintf`, `strcat` | CWE-120 |
| CS-CFG-001/002 | Debug enabled, bind to `0.0.0.0` | CWE-489/668 |

## GitHub Actions

```yaml
- uses: actions/checkout@v4
- run: pip install git+https://github.com/Acebmoon/codesentry.git
- run: codesentry . --fail-on HIGH
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Limitations

CodeSentry is pattern-based: it may produce false positives and cannot replace a full security review or a data-flow SAST tool. Use it as a fast first line of defense.

## License

MIT
