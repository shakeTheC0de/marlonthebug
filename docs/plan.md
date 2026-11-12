# MarlonTheBug — Master Plan

## Project Overview

**MarlonTheBug** is an offensive security auditing and exploitation platform designed for controlled penetration testing of owned infrastructure. The platform performs discovery, vulnerability detection, controlled exploitation, and provides hardening recommendations.

## Core Design Principles

1. **Modular Plugin Architecture** — Every capability is a self-contained plugin registered with the core engine
2. **Dual-Engine Design** — Separate Audit (detection) and Exploitation (action) engines with safety gates between them
3. **Workspace-Based Multi-Targeting** — Operate against multiple domains, IPs, and infrastructure from a single session
4. **Async-First** — Fully asynchronous I/O for scanning thousands of endpoints concurrently
5. **Scope-Guarded** — Strict domain/IP validation prevents unauthorized exploitation
6. **Professional Reporting** — CVSS 3.1 scoring, executive/technical reports in multiple formats

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.12+ |
| Async Runtime | asyncio + anyio |
| CLI Framework | Typer (commands) + Textual (TUI shell) |
| HTTP Client | httpx (async, HTTP/2) |
| HTML Parsing | BeautifulSoup4 + lxml |
| ORM | SQLAlchemy 2.0 (async) |
| Database (dev) | aiosqlite |
| Database (prod) | asyncpg + PostgreSQL |
| Reporting | Jinja2, WeasyPrint |
| Configuration | PyYAML + Pydantic |
| Logging | Loguru |
| Package Manager | uv (Astral) |
| Linting | ruff + mypy |
| Testing | pytest + pytest-asyncio |

---

## Phase Breakdown

### Phase 1 — Foundation + Reconnaissance (COMPLETE)

**Duration:** 4-6 weeks
**Status:** Implemented (41 tests passing)

#### Deliverables

| Component | Files | Description |
|---|---|---|
| Project Skeleton | `pyproject.toml`, `config/default.yaml`, `ruff.toml` | Full project setup, 30+ dependencies, lint/type config |
| Core Engine | `core/engine.py` | Orchestration engine, plugin lifecycle, scan coordination |
| Core Engine | `core/workspace.py` | Workspace manager with create/switch/delete, target scoping |
| Core Engine | `core/scope.py` | Domain/IP scope guard, exploitation confirmation gates |
| Core Engine | `core/scheduler.py` | Async task scheduler with semaphore-based concurrency |
| Core Engine | `core/pipeline.py` | Plugin chaining (recon → audit → exploit) |
| Core Engine | `core/events.py` | Async pub/sub event bus for inter-component communication |
| Database | `db/models.py` | 7 SQLAlchemy models: Workspace, Target, Finding, Exploit, Session, Listener, Pivot |
| Database | `db/repository.py` | Async repository pattern with full CRUD + statistics |
| Database | `db/migrations/` | Alembic migration setup |
| HTTP Engine | `http/client.py` | Async httpx wrapper with retry/backoff, TLS randomization |
| HTTP Engine | `http/session_pool.py` | Per-target cookie jars and connection reuse |
| HTTP Engine | `http/proxy.py` | SOCKS5/HTTP proxy rotation |
| HTTP Engine | `http/waf.py` | 10+ WAF signatures (Cloudflare, AWS, Akamai, ModSecurity, etc.) |
| Plugin System | `plugins/base.py` | Abstract BasePlugin with Finding dataclass and Severity enum |
| Plugin System | `plugins/registry.py` | Auto-discovery via importlib/pkgutil |
| Plugin System | `plugins/loader.py` | Hot-load system with dependency resolution |
| CLI | `cli/app.py` | 6 Typer command groups: workspace, recon, audit, exploit, sessions, report |
| CLI | `cli/console.py` | Full Textual TUI with command history, module context, status bar |
| Reporting | `output/cvss.py` | CVSS 3.1 vector parser and score calculator |
| Reporting | `output/reports.py` | JSON/Markdown/HTML report generator with Jinja2 |
| Reporting | `output/formatters.py` | JSON, Markdown, HTML formatters with severity badges |
| Collaborator | `collaborator/server.py` | Async DNS (UDP) + HTTP OOB callback server |
| Collaborator | `collaborator/token.py` | Per-scan unique tokens for callback correlation |
| Crawler | `crawler/spider.py` | Async spider with robots.txt, sitemap parsing, JS endpoint extraction |
| Listeners | `listeners/handler.py` | TCP + HTTP listener pool for reverse connections |
| Listeners | `listeners/session.py` | Session manager for active exploitation shells |
| Payloads | `exploit/payloads/generator.py` | Dynamic reverse shell generator for 10+ languages |
| Payloads | `exploit/payloads/reverse_shells.py` | 60+ reverse shell commands across all platforms |
| Payloads | `exploit/payloads/web_shells.py` | PHP, ASPX, JSP web shells |
| Payloads | `exploit/payloads/encoders.py` | 12 encoding methods (base64, URL, hex, XOR, etc.) |
| Exploit | `exploit/base.py` | BaseExploit ABC with check/run/cleanup lifecycle |
| Exploit | `exploit/registry.py` | Exploit discovery with finding-to-exploit mapping |
| Fuzzer | `fuzzer/engine.py` | Response analysis engine with baseline comparison |
| Fuzzer | `fuzzer/mutators.py` | 8 mutation strategies (case, encoding, whitespace, comments, etc.) |
| Fuzzer | `fuzzer/generators.py` | Context-aware payload generation by parameter type |
| Wordlists | `fuzzer/wordlists/` | 7 curated wordlists (subdomains, directories, params, SQLi, XSS, SSTI, LFI) |
| Recon | `plugins/recon/subdomain_enum.py` | CT logs (crt.sh) + DNS brute force |
| Recon | `plugins/recon/dns_bruteforce.py` | Async resolver with wildcard detection |
| Recon | `plugins/recon/tech_fingerprint.py` | 35+ tech signatures (servers, frameworks, CMS, CDNs, DBs, analytics) |
| Recon | `plugins/recon/endpoint_discovery.py` | Directory/file brute force with response analysis |
| Recon | `plugins/recon/js_analyzer.py` | Endpoint extraction, sourcemap parsing, 10+ secret patterns |
| Recon | `plugins/recon/secret_finder.py` | 25 regex rules for AWS, GitHub, Stripe, OpenAI keys, DB URIs, JWTs |
| Recon | `plugins/recon/git_leaks.py` | .git directory exposure detection + config/object scanning |
| Utilities | `utils/dns.py` | Async DNS resolver with zone transfer checking |
| Utilities | `utils/ssl_tls.py` | TLS version testing, cipher analysis, certificate validation, HSTS check |
| Utilities | `utils/headers.py` | 11 security header checks, CSP analysis, cookie flag audit, CORS analysis |
| Utilities | `utils/logging.py` | Loguru setup with rotation, retention, console + file sinks |
| Tests | `tests/test_core.py` | 41 tests covering CVSS, scope, workspace, events, fuzzer, encoders, headers, payloads, collaborator |

#### Key Metrics (Phase 1)
- **Python files:** 62
- **Lines of code:** ~3,500
- **Tests:** 41 (all passing)
- **Reconnaissance modules:** 7
- **WAF signatures:** 10+
- **Technology signatures:** 35+
- **Secret detection rules:** 25+
- **Reverse shells:** 60+
- **Payload encoders:** 12
- **Crawler patterns:** 20+ endpoint + secret patterns
- **Bundled wordlists:** 7 (subdomains, directories, parameters, SQLi, XSS, SSTI, LFI)

---

### Phase 2 — Web Auditing + Web Exploits (PLANNED)

**Duration:** 6-8 weeks

#### Web Audit Plugins
Each plugin detects, analyzes response, and yields CVSS-scored Findings:
- **SQL Injection** — Error-based, boolean blind, time-based, UNION-based; MySQL, PostgreSQL, MSSQL, Oracle dialects; NoSQL (MongoDB); GraphQL injection
- **XSS** — Reflected, stored, DOM-based; polyglot payloads; WAF evasion; headless verification via Playwright
- **SSRF** — URL-based, redirect chaining, blind SSRF with collaborator callbacks
- **CSRF** — Form token analysis, same-site cookie validation, CORS misconfig testing
- **Path Traversal** — Encoded sequences, OS-specific payloads (Linux/Windows)
- **LFI/RFI** — PHP wrappers, log poisoning, /proc/self, RFI with controlled server
- **File Upload** — Extension bypass, content-type manipulation, magic byte checks, polyglot files
- **SSTI** — Jinja2, Twig, Freemarker, Velocity, ERB detection and exploitation chains
- **Command Injection** — Blind, time-based, out-of-band; filter bypass techniques
- **Insecure Deserialization** — Python pickle, Java, PHP, .NET, Ruby YAML gadgets
- **RCE** — Framework-specific (Struts, Drupal, WordPress, Spring), OGNL injection
- **Open Redirect** — Parameter mining, header-based, JavaScript-based redirects
- **HTTP Request Smuggling** — CL.TE, TE.CL, TE.TE desync; H2.CL smuggling
- **WAF Bypass** — Payload fragmentation, encoding tricks, HTTP parameter pollution
- **Race Conditions** — TOCTOU, limit-overrun, multi-endpoint race windows
- **Business Logic** — Workflow discovery, state machine analysis, parameter tampering

#### Web Exploit Modules
Paired exploit modules for confirmed findings:
- **sqli_exploit** — Data extraction (tables, columns, rows), file read via LOAD_FILE, shell via INTO OUTFILE/UDF
- **rce_exploit** — Reverse shell delivery, command execution, persistence via known RCE vectors
- **upload_exploit** — Web shell delivery, MIME type bypass, extension filter bypass
- **ssti_exploit** — SSTI → RCE chains (Jinja2, Freemarker, Velocity, Twig)
- **lfi_exploit** — LFI → RCE via log poisoning, /proc/self/environ, php:// wrappers

---

### Phase 3 — Auth & API Security (PLANNED)

**Duration:** 4-5 weeks

#### Auth & Access Control Audit
- **IDOR/BOLA** — Object ID enumeration, pattern detection, UUID analysis
- **Broken Access Control** — Role-based endpoint testing, forced browsing, method tampering
- **Privilege Escalation** — Horizontal/vertical escalation, role enumeration
- **JWT Attacks** — None algorithm, HMAC confusion, key confusion (JWK/spoof), kid injection, weak secret brute-force
- **OAuth** — Redirect URI validation, state parameter, PKCE bypass, scope escalation, implicit flow
- **Session Fixation** — Token prediction, entropy analysis, logout CSRF
- **Credential Stuffing** — Multi-threaded auth testing, proxy rotation, lockout detection
- **MFA Bypass** — Response manipulation, rate limiting abuse, MFA fatigue

#### API Security Audit
- **REST** — OpenAPI/Swagger parsing, endpoint discovery, method fuzzing
- **GraphQL** — Introspection analysis, query depth, alias batching, field suggestion leaks
- **gRPC** — Reflection API enumeration, protobuf fuzzing, metadata manipulation
- **SOAP** — WSDL parsing, XXE in SOAP envelopes, WS-Security analysis
- **Mass Assignment** — Parameter discovery, hidden field enumeration, nested object injection
- **Excessive Data Exposure** — Over-fetching detection, field-level access control
- **Rate Limit Bypass** — Threshold detection, header/IP parameter rotation

#### Auth Exploit Modules
- **jwt_exploit** — Token forging, algorithm confusion exploitation, signature bypass
- **session_hijack** — Cookie theft via XSS→collaborator, session fixation exploitation

---

### Phase 4 — Cloud & Containers (PLANNED)

**Duration:** 3-4 weeks

#### Audit + Exploit
- **AWS IAM** — Policy enumeration, privilege escalation paths (Pacu-like), assume-role chaining, resource-based policy confusion. Exploit: automated IAM escalation chains
- **Metadata Abuse** — IMDSv1/v2 access, credential extraction, user-data parsing
- **Docker Breakout** — Capability enumeration, socket exposure, cgroup escape, overlayfs exploitation. Exploit: container breakout automation
- **Kubernetes** — RBAC analysis, pod security context, service account token abuse, etcd exposure, dashboard detection. Exploit: service account → cluster admin paths
- **Exposed Dashboards** — Grafana, Kibana, Jenkins, etc. default credential testing

---

### Phase 5 — CI/CD & Supply Chain (PLANNED)

**Duration:** 2-3 weeks

- **Dependency Confusion** — Package manager analysis (npm, PyPI, RubyGems), namespace squatting detection. Exploit: malicious package deployment simulation
- **Secrets Leakage** — CI/CD log scanning, environment variable exposure, build artifact analysis
- **CI/CD Pipeline** — GitHub Actions workflow injection, GitLab CI variable leakage, Jenkins script console abuse

---

### Phase 6 — AI/LLM Security (PLANNED)

**Duration:** 2-3 weeks

- **Prompt Injection** — Direct/indirect injection, system prompt extraction, role-playing bypass
- **Tool-Call Hijacking** — Function call manipulation, parameter injection, side-channel via tool outputs
- **RAG Poisoning** — Document injection, embedding confusion, retrieval manipulation
- **Model Data Exfiltration** — Weight extraction probing, model inversion, membership inference

---

## Architecture

### Dual-Engine Design

```
┌──────────────────────────────────────────────────────────────┐
│                  CLI / TUI Interactive Shell                  │
│          (workspace-based, multi-target, session-aware)       │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌───────────────────────────┐  ┌──────────────────────────┐  │
│  │     AUDIT ENGINE          │  │  EXPLOITATION ENGINE     │  │
│  │  (Detection + Analysis)   │  │  (Exploit + Post-Exploit)│  │
│  │                           │  │                          │  │
│  │  • Reconnaissance plugins │  │  • Payload generator      │  │
│  │  • Web auditing plugins   │  │  • Reverse shells         │  │
│  │  • API security plugins   │  │  • Web shells             │  │
│  │  • Auth/access plugins    │  │  • Encoders/obfuscators   │  │
│  │  • Cloud/container        │  │  • TCP/HTTP/DNS listeners │  │
│  │  • CI/CD/supply chain     │  │  • Session manager        │  │
│  │  • AI/LLM security        │  │  • Post-exploit modules   │  │
│  └─────────────┬─────────────┘  │  • Pivot/lateral movement │  │
│                │                 └──────────────┬───────────┘  │
│                └───────────────┬────────────────┘               │
│                                ▼                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    CORE SERVICES                           │  │
│  │                                                           │  │
│  │  HTTP Engine │ Fuzzer │ OOB Collaborator │ Crawler        │  │
│  │  Database    │ Scope Guard │ Event Bus │ Output/Reports   │  │
│  │  Config      │ Logging │ Scheduler                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Workspace-Based Multi-Target System

```
Workspace "acme-audit"
├── Scope
│   ├── Domains: example.com, api.example.com, staging.example.internal
│   ├── IP Ranges: 10.0.1.0/24
│   └── Excluded: *.cdn.example.com
├── Targets (discovered + added)
│   ├── example.com (web, nginx+react)
│   ├── api.example.com (api, rest)
│   ├── admin.example.com (web, php+mysql)
│   ├── 10.0.1.5 (server, ssh+postgres)
│   └── 10.0.1.20 (container, docker+k8s)
├── Findings (CVSS scored)
│   ├── CRITICAL: .git exposed on admin.example.com
│   ├── HIGH: SQLi on example.com/products?id=
│   └── MEDIUM: Missing CSP on api.example.com
├── Exploits (paired with findings)
│   ├── sqli_exploit → database dump on example.com
│   └── git_leaks → credentials extracted from admin.example.com
└── Sessions (active shells)
    └── shell on 10.0.1.5 via sqli→rce chain
```

### CLI Design

```bash
# Launch interactive TUI
$ marlonthebug console

   __  ___          __             _______  __    ___           __
  /  |/  /__ _____ / /__  ___    /_  __/ / / /   / _ )__ _____/ /
 / /|_/ / _ \`/ __/ / _ \/ _ \    / / / /_/ /   / _  / // / _ / _ \
/_/  /_/\_,_/_/ /_/\___/_//_/   /_/  \__,_/   /____/\_,_/\_,_/_.__/

   v1.0.0 — Offensive Security Auditing & Exploitation Platform

marlonthebug> help
marlonthebug> workspace create --name "acme-audit"
marlonthebug> workspace add --domains "example.com,api.example.com"
marlonthebug> use recon/subdomain_enum
marlonthebug(subdomain_enum)> set threads 50
marlonthebug(subdomain_enum)> run
marlonthebug> sessions
marlonthebug> sessions -i 1
[www-data@web-prod-01]$ whoami

# CLI mode (non-interactive)
$ marlonthebug workspace create --name "scan1"
$ marlonthebug workspace add --domains "example.com"
$ marlonthebug recon run
$ marlonthebug audit run --category web
$ marlonthebug report generate --format html --output report.html
```

---

## Safety Architecture

MarlonTheBug includes strict safety controls:

1. **Scope Guard** — Validates every target against configurable allowed domains/IP ranges before any action
2. **Exploitation Disabled by Default** — Must be explicitly enabled per workspace via `scope.allow_exploitation`
3. **Confirmation Prompts** — Configurable `require_confirmation` flag prompts before each exploit execution
4. **Action Logging** — All exploit actions logged to `logs/marlonthebug.log` with timestamps
5. **Auto-Cleanup** — Optional cleanup of artifacts after session termination

```yaml
# config/default.yaml
scope:
  require_confirmation: true
  allow_exploitation: false
  allowed_domains: []
  excluded: []

exploitation:
  confirm_before_payload: true
  max_concurrent_sessions: 5
  auto_cleanup: true
  log_all_actions: true
```

---

## Development Commands

```bash
uv sync                     # Install dependencies
uv sync --group dev         # Install dev dependencies
uv run pytest               # Run tests (41/41 passing)
uv run pytest --cov=marlonthebug  # With coverage
uv run ruff check .         # Lint
uv run mypy marlonthebug/   # Type check
```
