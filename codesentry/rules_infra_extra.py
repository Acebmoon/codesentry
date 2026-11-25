# rules_infra_extra.py
# Extra rule pack: CI/CD workflows, Kubernetes/Docker, cloud IAM/Terraform and
# framework configuration (Spring, Laravel, ASP.NET, PHP).

from .rules_db import make_rule as _r

YAML = frozenset({".yml", ".yaml"})
TF = frozenset({".tf"})
JSON_ = frozenset({".json"})
SH = frozenset({".sh"})
IAC = YAML | TF | JSON_
INFRA_FILES = YAML | SH | JSON_ | frozenset({".conf"})
PROPS = frozenset({".properties"}) | YAML

# GitHub Actions contexts an outsider can control (titles, bodies, branch names, messages).
_UNTRUSTED = (
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|head_commit\.(?:message|author\.(?:name|email))"
    r"|workflow_run\.(?:head_branch|head_commit\.message|head_commit\.author\.(?:name|email))"
    r"|commits\[[^\]]*\]\.(?:message|author\.(?:name|email)))|head_ref)\s*\}\}"
)

INFRA_RULES = [
    # ------------------------------------------------------------ GitHub Actions
    _r("CS-CI-001", "Untrusted GitHub context inside a run/script step", "HIGH", "CWE-77",
       r"\b(?:run|script)\s*:[^\n]*" + _UNTRUSTED,
       "Pass the value through env: and reference it as a shell variable instead of ${{ }}.", exts=YAML),
    _r("CS-CI-002", "Untrusted GitHub context expanded in a workflow", "MEDIUM", "CWE-77",
       r"^(?!\s*-?\s*(?:run|script)\s*:)[^\n]*" + _UNTRUSTED,
       "If this lands in a shell script, move it to env: first.", exts=YAML),
    _r("CS-CI-003", "pull_request_target trigger", "MEDIUM", "CWE-94",
       r"\bpull_request_target\b",
       "It runs with secrets on fork PRs: never check out or run the PR's code in it.", exts=YAML),
    _r("CS-CI-004", "Checkout of the pull request head", "MEDIUM", "CWE-94",
       r"ref\s*:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}",
       "Do not run untrusted PR code in a privileged workflow.", exts=YAML),
    _r("CS-CI-005", "Workflow permissions: write-all", "MEDIUM", "CWE-250",
       r"^\s*permissions\s*:\s*write-all\b",
       "Grant only the permissions each job needs.", exts=YAML),
    _r("CS-CI-006", "Action pinned to a moving branch", "MEDIUM", "CWE-829",
       r"^\s*-?\s*uses\s*:\s*[\w.-]+/[\w./-]+@(?:master|main|latest|HEAD)\b",
       "Pin third-party actions to a release tag or commit SHA.", exts=YAML),
    _r("CS-CI-007", "Remote script piped into a shell", "MEDIUM", "CWE-494",
       r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
       "Download, verify a checksum or signature, then run.", exts=YAML | SH),
    _r("CS-CI-008", "Secret echoed in a workflow step", "MEDIUM", "CWE-532",
       r"echo\s+[\"']?\$\{\{\s*secrets\.",
       "Never print secrets; logs are readable by anyone with repo access.", exts=YAML),
    _r("CS-CI-009", "Self-hosted runner", "LOW", "CWE-829",
       r"runs-on\s*:\s*\[?[^\n]*self-hosted",
       "Do not run fork PRs on self-hosted runners; keep them ephemeral.", exts=YAML),
    # ------------------------------------------------------------ Kubernetes / Docker
    _r("CS-K8S-001", "Privileged container", "HIGH", "CWE-250",
       r"\bprivileged\s*:\s*true\b",
       "Drop privileged mode; add only the specific capabilities needed.", exts=YAML),
    _r("CS-K8S-002", "Pod shares host network/PID/IPC", "MEDIUM", "CWE-250",
       r"\bhost(?:Network|PID|IPC)\s*:\s*true\b",
       "Remove host namespace sharing unless essential.", exts=YAML),
    _r("CS-K8S-003", "Container may run as root / escalate", "MEDIUM", "CWE-250",
       r"\ballowPrivilegeEscalation\s*:\s*true\b|\brunAsUser\s*:\s*0\b|\brunAsNonRoot\s*:\s*false\b",
       "Set runAsNonRoot: true and allowPrivilegeEscalation: false.", exts=YAML),
    _r("CS-K8S-004", "Docker socket mounted", "MEDIUM", "CWE-250",
       r"/(?:var/)?run/docker\.sock",
       "Access to the socket is root on the host; avoid mounting it.", exts=INFRA_FILES),
    _r("CS-K8S-005", "Anonymous / unauthenticated cluster access", "HIGH", "CWE-306",
       r"\bsystem:(?:anonymous|unauthenticated)\b|--anonymous-auth\s*=\s*true|--insecure-port\s*=\s*[1-9]|--insecure-bind-address|--authorization-mode\s*=\s*AlwaysAllow|\bread-only-port\s*[:=]\s*[1-9]",
       "Disable anonymous access and require authentication/RBAC.", exts=INFRA_FILES),
    _r("CS-K8S-006", "Kubernetes dashboard login skip", "MEDIUM", "CWE-306",
       r"--enable-skip-login|--disable-settings-authorizer|enableSkipButton\s*:\s*true",
       "Require authentication on the dashboard.", exts=INFRA_FILES),
    _r("CS-K8S-007", "docker run --privileged", "MEDIUM", "CWE-250",
       r"\bdocker\s+run\b[^\n]*--privileged\b",
       "Avoid --privileged; use --cap-add for specific needs.", exts=YAML | SH),
    # ------------------------------------------------------------ cloud IAM / Terraform
    _r("CS-IAM-001", "Policy allows any principal ('*')", "HIGH", "CWE-284",
       r"[\"']Principal[\"']\s*:\s*(?:[\"']\*[\"']|\{\s*[\"']AWS[\"']\s*:\s*[\"']\*[\"']\s*\})|identifiers\s*=\s*\[\s*\"\*\"\s*\]",
       "Name the exact accounts/roles allowed.", exts=IAC),
    _r("CS-IAM-002", "Policy allows every action ('*')", "MEDIUM", "CWE-250",
       r"[\"']Action[\"']\s*:\s*(?:[\"']\*[\"']|\[\s*[\"']\*[\"']\s*\])|\bactions\s*=\s*\[\s*\"\*\"\s*\]",
       "Apply least privilege: list only the actions required.", exts=IAC),
    _r("CS-IAM-003", "OIDC trust policy with wildcard subject", "MEDIUM", "CWE-284",
       r"token\.actions\.githubusercontent\.com:sub[\"']?\s*[:=]\s*[\"'][^\"']*\*",
       "Restrict sub to the exact repo and branch/environment.", exts=IAC),
    _r("CS-TF-001", "Public ACL on a cloud resource", "HIGH", "CWE-732",
       r"\bacl\s*=\s*\"(?:public-read|public-read-write|authenticated-read)\"",
       "Keep buckets private and serve through a CDN or signed URLs.", exts=TF),
    _r("CS-TF-002", "Security group open to the world", "MEDIUM", "CWE-284",
       r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"|ipv6_cidr_blocks\s*=\s*\[\s*\"::/0\"|\bCidrIp\s*:\s*[\"']?0\.0\.0\.0/0",
       "Limit ingress to the networks that need it.", exts=IAC),
    _r("CS-TF-003", "Database/resource publicly accessible", "MEDIUM", "CWE-284",
       r"\bpublicly_accessible\s*=\s*true\b|\bPubliclyAccessible\s*:\s*[\"']?true\b",
       "Keep databases in private subnets.", exts=IAC),
    _r("CS-TF-004", "IMDSv1 allowed (http_tokens optional)", "MEDIUM", "CWE-1188",
       r"\bhttp_tokens\s*=\s*\"optional\"|\bHttpTokens\s*:\s*[\"']?optional\b",
       "Require IMDSv2 (http_tokens = \"required\") so SSRF cannot read role keys.", exts=IAC),
    _r("CS-TF-005", "Encryption / public-access block disabled", "MEDIUM", "CWE-311",
       r"\b(?:storage_encrypted|encrypted|kms_encrypted|enable_https_traffic_only|block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b",
       "Enable encryption and the public-access block.", exts=TF),
    # ------------------------------------------------------------ framework configuration
    _r("CS-CFG-005", "Spring Boot Actuator exposes every endpoint", "HIGH", "CWE-200",
       r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\*",
       "Expose only health/info and protect the rest with authentication.", exts=PROPS),
    _r("CS-CFG-006", "Actuator 'include: *' (YAML)", "MEDIUM", "CWE-200",
       r"^\s*include\s*:\s*[\"']?\*[\"']?\s*(?:#.*)?$",
       "If this is the Actuator exposure list, expose only what you need.", exts=YAML),
    _r("CS-CFG-007", "Spring H2 console / sensitive Actuator endpoint enabled", "HIGH", "CWE-489",
       r"spring\.h2\.console\.enabled\s*[=:]\s*true|management\.endpoint\.(?:shutdown|env|heapdump)\.enabled\s*[=:]\s*true|management\.security\.enabled\s*[=:]\s*false|management\.endpoints\.enabled-by-default\s*[=:]\s*true|spring\.h2\.console\.settings\.web-allow-others\s*[=:]\s*true",
       "Disable the H2 console and sensitive endpoints outside development.", exts=PROPS),
    _r("CS-CFG-008", "PHP/Laravel debug output enabled", "MEDIUM", "CWE-489",
       r"\bAPP_DEBUG\s*[=:]\s*[\"']?true\b|[\"']debug[\"']\s*=>\s*true\b|\bdisplay_errors\s*=\s*(?:On|1|true)\b",
       "Turn debug off in production; it leaks stack traces and environment values.",
       exts=frozenset({".env", ".php", ".ini"})),
    _r("CS-CFG-009", "PHP allow_url_include enabled", "HIGH", "CWE-98",
       r"\ballow_url_include\s*=\s*(?:On|1|true)\b",
       "Keep allow_url_include = Off.", exts=frozenset({".ini"})),
    _r("CS-CFG-010", "ASP.NET debug/trace/custom errors off", "MEDIUM", "CWE-489",
       r"(?i)<trace\s[^>]*enabled\s*=\s*[\"']true|<customErrors\s[^>]*mode\s*=\s*[\"']Off|<compilation\s[^>]*debug\s*=\s*[\"']true",
       "Disable tracing and debug compilation and show generic errors in production.",
       exts=frozenset({".config", ".aspx"})),
]
