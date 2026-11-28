# test_extra_rules.py
# Every extra rule must fire on a vulnerable sample and stay quiet on a safe one.
# Tokens are assembled at runtime so no real-looking secret sits in this file.

import pytest

from codesentry.scan_engine import scan_file
from codesentry.rules_db import RULES

A = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"  # invented filler, 32 chars
HEX32 = "0123456789abcdef" * 2


def _tok(*parts):
    return "".join(parts)


# (rule id, file name, vulnerable line, safe line or None)
CASES = [
    # ---- secrets
    ("CS-SEC-009", "a.py", _tok('k = "sk_', 'live_', A[:26], '"\n'), 'k = "sk_test_placeholder"\n'),
    ("CS-SEC-010", "a.py", _tok('k = "SG', '.', A[:22], '.', (A + A)[:43], '"\n'), None),
    ("CS-SEC-011", "a.js", _tok('t = "npm', '_', A + "wxyz", '"\n'), None),
    ("CS-SEC-012", "a.py", _tok('t = "glpat', '-', A[:20], '"\n'), None),
    ("CS-SEC-013", "a.py", _tok('u = "https://hooks.slack', '.com/services/', 'T0AAAAAAA/B0BBBBBBB/', A[:24], '"\n'), None),
    ("CS-SEC-014", "a.py", _tok('u = "https://discord', '.com/api/webhooks/', "1" * 18, "/", A + A[:20], '"\n'), None),
    ("CS-SEC-015", "a.py", _tok('t = "', "1234567890", ':AA', A + "x", '"\n'), None),
    ("CS-SEC-016", "a.py", _tok('s = "GOCSPX', '-', A[:28], '"\n'), None),
    ("CS-SEC-017", "a.cs", _tok('c = "AccountName=x;AccountKey=', A * 2, '=="\n'), None),
    ("CS-SEC-018", "a.py", _tok('k = "sk', '-ant-', A + A, '"\n'), None),
    ("CS-SEC-023", ".env", _tok("DB_PASSWORD=", A[:20], "\n"), "DB_PASSWORD=${DB_PASSWORD}\n"),
    ("CS-SEC-019", "a.py", _tok('t = "shp', 'at_', HEX32, '"\n'), None),
    ("CS-SEC-020", "a.txt", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n", None),
    ("CS-SEC-021", "a.py", _tok('h = {"Authorization": "Basic ', "dXNlcjpwYXNzd29yZDEyMw==", '"}\n'), 'h = {"Authorization": "Bearer " + t}\n'),
    ("CS-SEC-022", "web.config", _tok('<machineKey validationKey="', HEX32, '" decryptionKey="x" />\n'), '<machineKey validationKey="AutoGenerate" />\n'),
    # ---- injection
    ("CS-INJ-007", "a.py", "return render_template_string(request.args['t'])\n", 'return render_template_string("<p>hi</p>")\n'),
    ("CS-INJ-008", "a.js", "res.send(ejs.render(req.query.tpl))\n", "res.render('index', {q: req.query.q})\n"),
    ("CS-INJ-009", "a.js", "child_process.exec('ls ' + dir)\n", "child_process.execFile('ls', [dir])\n"),
    ("CS-INJ-010", "a.php", "system('ping ' . $_GET['ip']);\n", "system('uptime');\n"),
    ("CS-INJ-016", "a.php", '$q = "SELECT * FROM users WHERE id = \'$id\'";\n', '$q = "SELECT * FROM users WHERE id = ?";\n'),
    ("CS-LFI-001", "a.php", "include($_GET['page'] . '.php');\n", "include 'header.php';\n"),
    ("CS-INJ-011", "a.js", "db.users.find({$where: 'this.a == 1'})\n", "db.users.find({a: 1})\n"),
    ("CS-INJ-012", "a.js", "User.findOne(req.body, cb)\n", "User.findOne({name: String(req.body.name)}, cb)\n"),
    ("CS-INJ-013", "a.py", 'flt = f"(uid={user})"\n', 'flt = "(objectClass=person)"\n'),
    ("CS-INJ-014", "a.py", 'tree.xpath("//u[@n=\'" + name + "\']")\n', 'tree.xpath("//user")\n'),
    ("CS-INJ-015", "a.py", "exec(completion.choices[0].text)\n", "print(completion.choices[0].text)\n"),
    # ---- XSS / DOM
    ("CS-XSS-001", "a.jsx", "<div dangerouslySetInnerHTML={{__html: x}} />\n", "<div>{x}</div>\n"),
    ("CS-XSS-002", "a.vue", '<p v-html="msg"></p>\n', '<p>{{ msg }}</p>\n'),
    ("CS-XSS-003", "a.js", "el.insertAdjacentHTML('beforeend', html)\n", "el.textContent = t\n"),
    ("CS-XSS-004", "a.js", "w.postMessage(data, '*')\n", "w.postMessage(data, 'https://app.example.org')\n"),
    ("CS-XSS-005", "a.js", "window.addEventListener('message', h)\n", "window.addEventListener('click', h)\n"),
    ("CS-RED-001", "a.js", "location.href = new URLSearchParams(location.search).get('next')\n", "location.href = '/home'\n"),
    ("CS-RED-002", "a.py", "return redirect(request.args.get('next'))\n", "return redirect(url_for('home'))\n"),
    ("CS-SSR-001", "a.py", "r = requests.get(request.args['url'])\n", "r = requests.get('https://api.internal/x')\n"),
    ("CS-SSR-002", "a.php", "echo file_get_contents($_GET['u']);\n", "echo file_get_contents('cfg.txt');\n"),
    ("CS-PTH-001", "a.py", "return send_file(request.args['f'])\n", "return send_file('static/logo.png')\n"),
    ("CS-PTH-002", "a.php", "unlink('/tmp/' . $_POST['f']);\n", "unlink('/tmp/x');\n"),
    ("CS-UPL-001", "a.py", "f.save(os.path.join(UP, f.filename))\n", "f.save(os.path.join(UP, secure_filename(f.filename)))\n"),
    # ---- web config
    ("CS-CSR-001", "a.py", "@csrf_exempt\n", "@login_required\n"),
    ("CS-COR-001", "a.py", "resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']\n", "resp.headers['Access-Control-Allow-Origin'] = 'https://a.example.org'\n"),
    ("CS-COR-002", "a.js", "app.use(cors({origin: true, credentials: true}))\n", "app.use(cors({origin: 'https://a.example.org'}))\n"),
    ("CS-COR-003", "a.py", "allow_origins = ['*']\n", "allow_origins = ['https://a.example.org']\n"),
    ("CS-CFG-003", "a.js", "app.set('trust proxy', true)\n", "app.set('trust proxy', 1)\n"),
    ("CS-CFG-004", "a.py", "ALLOWED_HOSTS = ['*']\n", "ALLOWED_HOSTS = ['app.example.org']\n"),
    ("CS-HST-001", "a.py", "h = request.META['HTTP_HOST']\n", "h = settings.BASE_URL\n"),
    ("CS-SES-001", "a.py", "SESSION_COOKIE_SECURE = False\n", "SESSION_COOKIE_SECURE = True\n"),
    ("CS-SES-002", "a.js", "res.cookie('s', v, {httpOnly: false})\n", "res.cookie('s', v, {httpOnly: true})\n"),
    ("CS-GQL-001", "a.js", "new ApolloServer({introspection: true})\n", "new ApolloServer({introspection: false})\n"),
    ("CS-PRO-001", "a.js", "_.merge(cfg, req.body)\n", "_.merge(cfg, defaults)\n"),
    ("CS-LLM-001", "a.ts", "new OpenAI({dangerouslyAllowBrowser: true})\n", "new OpenAI()\n"),
    # ---- JWT / crypto
    ("CS-JWT-001", "a.py", "jwt.decode(t, options={'verify_signature': False})\n", "jwt.decode(t, key, algorithms=['HS256'])\n"),
    ("CS-JWT-002", "a.js", "jwt.verify(t, k, {ignoreExpiration: true})\n", "jwt.verify(t, k)\n"),
    ("CS-JWT-003", "a.js", "const c = jwt.decode(token)\n", "const c = jwt.verify(token, k)\n"),
    ("CS-CRY-004", "a.py", "AES.new(k, AES.MODE_ECB)\n", "AES.new(k, AES.MODE_GCM)\n"),
    ("CS-CRY-005", "a.py", "DES.new(k, DES.MODE_CBC, iv)\n", "AES.new(k, AES.MODE_GCM)\n"),
    ("CS-CRY-006", "a.js", "const c = crypto.createCipher('aes192', pw)\n", "const c = crypto.createCipheriv('aes-256-gcm', k, iv)\n"),
    ("CS-CRY-007", "a.py", "h = hashlib.sha256(password.encode()).hexdigest()\n", "h = bcrypt.hashpw(password, salt)\n"),
    ("CS-CRY-008", "a.js", "const token = Math.random().toString(36)\n", "const token = crypto.randomBytes(16)\n"),
    ("CS-TLS-001", "a.py", "ctx = ssl._create_unverified_context()\n", "ctx = ssl.create_default_context()\n"),
    # ---- deserialization / XML
    ("CS-DES-003", "a.php", "$o = unserialize($_COOKIE['d']);\n", "$o = json_decode($d);\n"),
    ("CS-DES-004", "a.php", "$o = unserialize($data);\n", "$o = unserialize($data, ['allowed_classes' => false]);\n"),
    ("CS-DES-005", "A.java", "mapper.enableDefaultTyping();\n", "mapper.readValue(s, Foo.class);\n"),
    ("CS-DES-006", "A.java", "ObjectInputStream in = new ObjectInputStream(s);\n", None),
    ("CS-DES-007", "a.cs", "var f = new BinaryFormatter();\n", "var j = JsonSerializer.Deserialize<Foo>(s);\n"),
    ("CS-DES-008", "web.config", '<pages enableViewStateMac="false" />\n', '<pages enableViewStateMac="true" />\n'),
    ("CS-DES-009", "a.rb", "obj = Marshal.load(data)\n", "obj = JSON.parse(data)\n"),
    ("CS-DES-010", "a.py", "obj = yaml.unsafe_load(s)\n", "obj = yaml.safe_load(s)\n"),
    ("CS-DES-011", "a.js", "const s = require('node-serialize')\n", "const s = require('express')\n"),
    ("CS-XXE-001", "a.php", "$d->loadXML($x, LIBXML_NOENT);\n", "$d->loadXML($x);\n"),
    ("CS-XXE-002", "A.java", "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n", None),
    # ---- CI / Kubernetes / IaC
    ("CS-CI-001", "w.yml", "      - run: echo ${{ github.event.pull_request.title }}\n", "      - run: echo \"$TITLE\"\n"),
    ("CS-CI-002", "w.yml", "        name: ${{ github.event.pull_request.title }}\n", "        name: build\n"),
    ("CS-CI-003", "w.yml", "on: pull_request_target\n", "on: pull_request\n"),
    ("CS-CI-004", "w.yml", "          ref: ${{ github.event.pull_request.head.sha }}\n", "          ref: main\n"),
    ("CS-CI-005", "w.yml", "permissions: write-all\n", "permissions: read-all\n"),
    ("CS-CI-006", "w.yml", "      - uses: someorg/some-action@main\n", "      - uses: someorg/some-action@v4\n"),
    ("CS-CI-007", "setup.sh", "curl -fsSL https://x.example.org/i.sh | sudo bash\n", "curl -fsSLo i.sh https://x.example.org/i.sh\n"),
    ("CS-CI-008", "w.yml", "      - run: echo ${{ secrets.TOKEN }}\n", "      - run: ./deploy.sh\n"),
    ("CS-CI-009", "w.yml", "    runs-on: [self-hosted, linux]\n", "    runs-on: ubuntu-latest\n"),
    ("CS-K8S-001", "p.yaml", "        privileged: true\n", "        privileged: false\n"),
    ("CS-K8S-002", "p.yaml", "  hostNetwork: true\n", "  hostNetwork: false\n"),
    ("CS-K8S-003", "p.yaml", "        runAsUser: 0\n", "        runAsUser: 1000\n"),
    ("CS-K8S-004", "p.yaml", "    path: /var/run/docker.sock\n", "    path: /data\n"),
    ("CS-K8S-005", "p.yaml", "  - kind: User\n    name: system:anonymous\n", "  - kind: User\n    name: alice\n"),
    ("CS-K8S-006", "d.yaml", "    - --enable-skip-login\n", "    - --auto-generate-certificates\n"),
    ("CS-K8S-007", "run.sh", "docker run --privileged -it img\n", "docker run -it img\n"),
    ("CS-IAM-001", "p.json", '{"Principal": "*", "Effect": "Allow"}\n', '{"Principal": {"AWS": "arn:aws:iam::1:root"}}\n'),
    ("CS-IAM-002", "p.json", '{"Action": "*", "Effect": "Allow"}\n', '{"Action": "s3:GetObject"}\n'),
    ("CS-IAM-003", "t.json", '"token.actions.githubusercontent.com:sub": "repo:org/*"\n', '"token.actions.githubusercontent.com:sub": "repo:org/app:ref:refs/heads/main"\n'),
    ("CS-TF-001", "m.tf", '  acl = "public-read"\n', '  acl = "private"\n'),
    ("CS-TF-002", "m.tf", '  cidr_blocks = ["0.0.0.0/0"]\n', '  cidr_blocks = ["10.0.0.0/16"]\n'),
    ("CS-TF-003", "m.tf", "  publicly_accessible = true\n", "  publicly_accessible = false\n"),
    ("CS-TF-004", "m.tf", '  http_tokens = "optional"\n', '  http_tokens = "required"\n'),
    ("CS-TF-005", "m.tf", "  encrypted = false\n", "  encrypted = true\n"),
    ("CS-CFG-005", "application.properties", "management.endpoints.web.exposure.include=*\n", "management.endpoints.web.exposure.include=health,info\n"),
    ("CS-CFG-006", "application.yml", "      include: \"*\"\n", "      include: health\n"),
    ("CS-CFG-007", "application.properties", "spring.h2.console.enabled=true\n", "spring.h2.console.enabled=false\n"),
    ("CS-CFG-008", ".env", "APP_DEBUG=true\n", "APP_DEBUG=false\n"),
    ("CS-CFG-009", "php.ini", "allow_url_include = On\n", "allow_url_include = Off\n"),
    ("CS-CFG-010", "web.config", '<compilation debug="true" targetFramework="4.8" />\n', '<compilation debug="false" targetFramework="4.8" />\n'),
]


def _hits(tmp_path, name, content, rule_id):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return [x for x in scan_file(str(f)) if x.rule_id == rule_id]


@pytest.mark.parametrize("rule_id,name,bad,good", CASES, ids=[c[0] for c in CASES])
def test_rule_fires_on_vulnerable_code_and_not_on_safe_code(tmp_path, rule_id, name, bad, good):
    assert len(_hits(tmp_path, name, bad, rule_id)) >= 1, f"{rule_id} missed: {bad!r}"
    if good is not None:
        assert _hits(tmp_path, "safe_" + name, good, rule_id) == [], f"{rule_id} false positive: {good!r}"


def test_every_new_rule_has_a_test_case():
    tested = {c[0] for c in CASES}
    new = {r.id for r in RULES} - {
        r.id for r in RULES if r.id.startswith("CS-") and r.id in _ORIGINAL_IDS}
    assert new <= tested, f"rules without a test: {sorted(new - tested)}"


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_secret_in_new_rule_is_masked(tmp_path):
    line = _tok('k = "sk_', 'live_', A[:26], '"\n')
    [hit] = _hits(tmp_path, "a.py", line, "CS-SEC-009")
    assert hit.snippet.count("****") == 1 and A[:26] not in hit.snippet


# Rules that existed before the extra packs (kept so the coverage check above stays meaningful).
_ORIGINAL_IDS = {
    "CS-SEC-001", "CS-SEC-002", "CS-SEC-003", "CS-SEC-004", "CS-SEC-005", "CS-SEC-006",
    "CS-SEC-007", "CS-SEC-008", "CS-INJ-001", "CS-INJ-002", "CS-INJ-003", "CS-INJ-004",
    "CS-INJ-005", "CS-INJ-006", "CS-DES-001", "CS-DES-002", "CS-CRY-001", "CS-CRY-002",
    "CS-CRY-003", "CS-MEM-001", "CS-CFG-001", "CS-CFG-002",
}
