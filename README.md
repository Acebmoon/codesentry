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

## Windows executable and menu

Run `codesentry` with no arguments to open the interactive menu (banner, numbered options, JSON report export).
The Windows `.exe` is built by GitHub Actions and attached to each release as `codesentry-windows.exe`:
double-click it, or run it from a terminal.

Other platforms (attached to each release too):

| System | File | Install |
|---|---|---|
| Debian / Ubuntu | `codesentry_<version>_amd64.deb` | `sudo apt install ./codesentry_*_amd64.deb`, then run `codesentry` |
| Fedora / RHEL | `codesentry-<version>-1.x86_64.rpm` | `sudo dnf install ./codesentry-*.x86_64.rpm` |
| Arch Linux | `codesentry-<version>-1-x86_64.pkg.tar.zst` | `sudo pacman -U codesentry-*.pkg.tar.zst` |
| macOS Apple Silicon | `codesentry-macos-arm64.tar.gz` | `tar -xzf codesentry-macos-arm64.tar.gz` |
| macOS Intel | `codesentry-macos-intel.tar.gz` | `tar -xzf codesentry-macos-intel.tar.gz` |

The macOS and Windows binaries are not code-signed. On macOS run `xattr -d com.apple.quarantine codesentry` once
(or right-click > Open); on Windows click "More info > Run anyway" in SmartScreen.

To build it yourself:

```
py -m pip install pyinstaller
py -m PyInstaller --onefile --name codesentry exe_entry.py
```

## Website check

`codesentry --site https://example.com --i-have-permission` (or menu option 3, `Scan website`) runs a **passive** check of a live site: about 100 plain GET/OPTIONS requests, a few at a time. Nothing is guessed, fuzzed, logged into or exploited, so only use it on sites you own or may test (the flag and the menu question exist for that). Add `--deps` (or answer Y in the menu) to also check the JavaScript libraries the site loads against OSV.dev; only library names and versions are sent.

| Area | What it looks for |
|---|---|
| Transport | plain HTTP, HTTPS redirecting to HTTP, no redirect to HTTPS, untrusted or soon-to-expire certificate, TLS 1.0/1.1 still accepted, missing or short HSTS, mixed content |
| Headers | missing or weak Content-Security-Policy (`unsafe-inline`, wildcards), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy; server and framework versions |
| Cookies | missing `Secure`, `HttpOnly`, `SameSite`; pages that set a cookie and can be cached |
| CORS and methods | origin reflection (worse with credentials), `*` with credentials, PUT/DELETE/TRACE enabled |
| Exposed files | about 90 paths: `.git`, `.env`, `.htpasswd`, backups and SQL dumps, logs, `phpinfo()`, Spring Boot Actuator, debug consoles, Swagger/OpenAPI, phpMyAdmin, WordPress extras, directory listings. Each one is verified by its content, so a custom 404 page or a single-page app that answers 200 for everything is not reported |
| Page content | debug consoles, stack traces and SQL/PHP errors, password forms over HTTP or using GET, POST forms without a CSRF token, third-party scripts without integrity, comments that mention passwords or tokens, `robots.txt` pointing at sensitive-looking paths |
| JavaScript | secrets (same rules as the code scan), Supabase `service_role` keys (HIGH) and anon keys (a reminder to check Row Level Security), other embedded JWTs, development and private addresses, source maps left on the server, libraries with known vulnerabilities (`--deps`) |

Findings use the rule ids `CS-WEB-001..034` (library findings carry the OSV id) and appear in every format (`-f html`, `json`, `sarif`). A passive scan sees configuration and leaks; it cannot find logic bugs, injection or broken access control, which need a human or an active scanner.

## Ignoring false positives

Add a `nosec` or `codesentry:ignore` comment to the line, in any comment style (`#`, `//`, `/* */`, `<!-- -->`, `--`). The marker must be a whole word inside the comment, so `nosecurity` or a string containing "nosec" do not silence anything.

To silence only some rules, list them: `# codesentry:ignore[CS-SEC-007]` or `// nosec[CS-INJ-001, CS-CFG-002]`.

## Rules

CodeSentry ships 122 rules. Every finding shows its rule ID, CWE and a fix suggestion. List them with `python -c "from codesentry.rules_db import RULES; [print(r.id, r.severity, r.name) for r in RULES]"`.

| Area | Rule IDs | What it catches |
|---|---|---|
| Secrets | CS-SEC-001..023 | AWS, GitHub, GitLab, Slack, npm, Stripe, SendGrid, Telegram, Google, Azure, AI-provider keys; private/PGP keys; JWTs; hardcoded passwords, quoted or unquoted in config files (`.env`, YAML, INI, `.properties`); credentials in URLs and Basic headers; ASP.NET machineKey |
| Injection | CS-INJ-001..015 | `eval`/`exec`, OS commands, SQL/NoSQL/LDAP/XPath built from variables, SSTI, PHP command calls, LLM output executed as code |
| Files and requests | CS-PTH, CS-LFI, CS-SSR, CS-RED, CS-UPL | path traversal, file inclusion, SSRF, open redirects, unsafe uploads |
| XSS and DOM | CS-XSS-001..005 | `dangerouslySetInnerHTML`, `v-html`, HTML sinks, `postMessage('*')`, message listeners |
| Web config | CS-CSR, CS-COR, CS-CFG-003/004, CS-HST, CS-SES, CS-GQL, CS-PRO | disabled CSRF, loose CORS, trust proxy, wildcard hosts, cookie flags, GraphQL introspection, prototype pollution |
| Auth and crypto | CS-JWT, CS-CRY, CS-TLS | unverified JWTs, ECB/DES/RC4, fast password hashes, weak RNG, disabled TLS checks |
| Deserialization and XML | CS-DES-001..011, CS-XXE | pickle, PHP `unserialize`, Java/.NET/Ruby/Node gadgets, ViewState MAC off, XXE |
| CI/CD | CS-CI-001..009 | untrusted GitHub context in `run:`, `pull_request_target`, `write-all`, unpinned actions, remote scripts piped to a shell |
| Kubernetes and Docker | CS-K8S-001..007 | privileged pods, host namespaces, root, docker.sock, anonymous access |
| Cloud and Terraform | CS-IAM, CS-TF | wildcard principals/actions, public ACLs, open security groups, IMDSv1, unencrypted storage |
| Frameworks | CS-CFG-005..010 | Spring Actuator/H2, Laravel/PHP debug, ASP.NET trace and debug |
| Memory safety and misc | CS-MEM-001, CS-CFG-001/002 | `gets`/`strcpy`, debug mode, bind to `0.0.0.0` |

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

## Acknowledgements

The extra rule packs (`CS-SEC-009` and up) were designed after studying the vulnerability classes documented in [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) (code MIT, content CC BY 4.0). That project is an offensive bug-bounty toolkit; CodeSentry only borrows the *classes of weakness* and detects them in your own source. All patterns here were written from scratch.

## Ignoring files

Put a `.codesentryignore` in the folder you scan, one glob per line (`#` for comments), e.g. `tests` or `build/**`.
CodeSentry also reads it automatically. Single lines can be silenced with `# codesentry:ignore[CS-XXX-000]`.

## Scanning a GitHub repository

```
codesentry https://github.com/owner/repo
```

Or pick "Scan GitHub repo" in the menu. CodeSentry makes a shallow clone into a temporary folder (needs `git`),
scans it and deletes it. A `/tree/<branch>` link scans that branch (or tag). Public repositories only; nothing from the repository is ever executed, and its
`.codesentryignore` is not applied. Use it to review code you are allowed to check and to report problems to the owner.

Add `--keep` to keep the downloaded copy. In the menu you choose whether to keep it, can show the last results again
(option 4) and delete downloaded repos one by one or all at once (option 6). Copies are stored in
`~/.codesentry/downloads`.

## Checking dependencies

`--deps` also checks pinned packages in `package-lock.json` (the installed versions, transitive dependencies included), `requirements*.txt` (`name==1.2.3`) and `package.json` when there is no lock next to it (`^1.2.3` is read as 1.2.3) for known vulnerabilities, using [OSV.dev](https://osv.dev). Specs without a pinned version (ranges, `latest`, git links) are listed in a warning:

```
codesentry . --deps
codesentry https://github.com/owner/repo --deps
```

Only package names and versions are sent, and only when you use `--deps` (the menu asks first, default yes). If OSV.dev can't be reached, the code scan still runs and a warning is printed.

## Git history

`--history` looks for secrets in the git history of a local repository: ones that were committed once and removed later are still in old commits. Each one is reported at the commit that added it, and needs to be revoked or rotated (deleting the line isn't enough). Secrets still present in the current files are left to the normal scan. `--exclude` and `.codesentryignore` apply. The menu asks when the folder is a git repository. The folder's own git config cannot make `git log` run a signature program (`log.showSignature` is switched off).

## Menu screens and mouse

Every menu action opens its own screen with a `CODESENTRY > TITLE` header and a way back, so messages never mix with the menu. In a terminal that supports it (Windows Terminal, PowerShell, most Linux/macOS terminals) you can click menu lines and buttons and use the mouse wheel to change page; keys work without pressing Enter (`1`-`6` in the menu, `N`/`P`/`H`/`M`/`L`/`A`/`S`/`B` in the results, `Esc` goes back). If the mouse isn't available the menu falls back to typing a choice and pressing Enter.

## HTML report and copying results

`codesentry . -f html -o report.html` writes a single self-contained page (dark theme, severity filter buttons, nothing loaded from the network; everything from the scanned code is escaped). In the menu, the results screen has `[R]eport HTML` (saves it and offers to open it in the browser) and `[C]opy` (copies the findings that are on screen, so a severity filter limits what is copied). Menu option 5, `Export last report`, offers HTML, JSON or the clipboard.

## Results screen

In the menu, a scan opens its own results screen: `N`/`P` change page (Enter = next), `H`/`M`/`L` filter by severity, `A` shows all, `S` saves JSON and `B` goes back to the menu. Option 3 reopens the last results.
