# MarlonTheBug — Architecture Documentation

## Overview

MarlonTheBug is a modular, async-first offensive security platform built in Python. It uses a dual-engine architecture separating detection/analysis from exploitation/action, with strict safety gates between them.

## Directory Map

```
marlonthebug/
├── pyproject.toml              # Project config (uv, dependencies, tool settings)
├── config/default.yaml         # Default runtime configuration
├── alembic.ini                 # Database migration config
├── marlonthebug/
│   ├── main.py                 # CLI entry point
│   ├── __init__.py             # Version + logging init
│   │
│   ├── cli/                    # CLI / TUI Layer
│   │   ├── app.py              # Typer command groups (workspace, recon, audit, etc.)
│   │   ├── console.py          # Textual TUI interactive shell
│   │   ├── commands/           # Future: separated command modules
│   │   └── widgets/            # Future: custom TUI widgets
│   │
│   ├── core/                   # Core Engine
│   │   ├── engine.py           # Orchestration engine (plugin lifecycle, scan coordination)
│   │   ├── workspace.py        # Workspace manager (CRUD, multi-target scoping)
│   │   ├── scope.py            # Scope guard (domain/IP validation, exploitation gates)
│   │   ├── scheduler.py        # Async task scheduler (semaphore-based concurrency)
│   │   ├── pipeline.py         # Plugin chaining (recon → audit → exploit)
│   │   └── events.py           # Async pub/sub event bus
│   │
│   ├── http/                   # HTTP Engine
│   │   ├── client.py           # Async httpx wrapper (retry, backoff, UA rotation)
│   │   ├── session_pool.py     # Per-target cookie jars and connection reuse
│   │   ├── proxy.py            # SOCKS5/HTTP proxy rotation
│   │   └── waf.py              # WAF fingerprinting (10+ signatures)
│   │
│   ├── collaborator/           # OOB Server (Burp Collaborator equivalent)
│   │   ├── server.py           # Async DNS (UDP) + HTTP callback server
│   │   └── token.py            # Per-scan correlation tokens
│   │
│   ├── crawler/                # Intelligent Spider
│   │   └── spider.py           # Async crawler (robots.txt, sitemap, JS parsing)
│   │
│   ├── fuzzer/                 # Adaptive Fuzzer
│   │   ├── engine.py           # Response analysis engine with baseline comparison
│   │   ├── mutators.py         # 8 payload mutation strategies
│   │   ├── generators.py       # Context-aware payload generation by parameter type
│   │   └── wordlists/          # 7 curated wordlists
│   │
│   ├── db/                     # Database Layer
│   │   ├── base.py             # SQLAlchemy declarative base + type annotations
│   │   ├── models.py           # 7 models (Workspace, Target, Finding, Exploit, etc.)
│   │   ├── repository.py       # Async repository pattern with full CRUD
│   │   └── migrations/         # Alembic migration environment
│   │
│   ├── output/                 # Reporting Engine
│   │   ├── cvss.py             # CVSS 3.1 vector parser and calculator
│   │   ├── reports.py          # Report generator (JSON/Markdown/HTML)
│   │   ├── formatters.py       # Output formatters with severity badges
│   │   └── templates/          # Future: Jinja2 report templates
│   │
│   ├── listeners/              # Exploit Infrastructure
│   │   ├── handler.py          # TCP + HTTP listener pool
│   │   └── session.py          # Active session manager
│   │
│   ├── plugins/                # Plugin System
│   │   ├── base.py             # BasePlugin ABC + Finding dataclass + Severity enum
│   │   ├── registry.py         # Auto-discovery via importlib/pkgutil
│   │   ├── loader.py           # Hot-load system with dependency resolution
│   │   ├── recon/              # 7 reconnaissance plugins
│   │   │   ├── subdomain_enum.py    # CT logs + DNS brute force
│   │   │   ├── dns_bruteforce.py    # Async DNS resolution with wildcard detection
│   │   │   ├── tech_fingerprint.py  # 35+ tech signatures
│   │   │   ├── endpoint_discovery.py # Directory/file brute force
│   │   │   ├── js_analyzer.py       # JS endpoint + secret extraction
│   │   │   ├── secret_finder.py     # 25 regex rules for secrets
│   │   │   └── git_leaks.py         # .git exposure + content scanning
│   │   ├── web/                # Phase 2: Web auditing plugins
│   │   ├── auth/               # Phase 3: Auth & access control
│   │   ├── api/                # Phase 3: API security
│   │   ├── cloud/              # Phase 4: Cloud & containers
│   │   ├── cicd/               # Phase 5: CI/CD & supply chain
│   │   └── llm/                # Phase 6: AI/LLM security
│   │
│   ├── exploit/                # Exploitation Modules
│   │   ├── base.py             # BaseExploit ABC (check/run/cleanup lifecycle)
│   │   ├── registry.py         # Exploit registry with finding-to-exploit mapping
│   │   ├── payloads/           # Payload generation system
│   │   │   ├── generator.py    # Dynamic payload builder (10+ languages)
│   │   │   ├── reverse_shells.py  # 60+ reverse shell commands
│   │   │   ├── web_shells.py   # PHP/ASPX/JSP web shells
│   │   │   └── encoders.py     # 12 encoding methods
│   │   ├── webapp/             # Phase 2: Web exploit modules
│   │   ├── auth/               # Phase 3: Auth exploit modules
│   │   ├── infra/              # Phase 4: Infrastructure exploit modules
│   │   └── post/               # Post-exploitation modules
│   │
│   └── utils/                  # Shared Utilities
│       ├── dns.py              # Async DNS resolver + zone transfer
│       ├── ssl_tls.py          # TLS + certificate analyzer
│       ├── headers.py          # Security header + CSP + CORS + cookie analyzer
│       └── logging.py          # Loguru setup
│
└── tests/
    ├── conftest.py             # Pytest fixtures
    └── test_core.py            # 41 unit tests
```

## Data Flow

### Scan Pipeline

```
User Command
    │
    ▼
Engine.run_full(targets)
    │
    ├─► Engine.run_recon(targets)
    │       │
    │       ├─► PluginLoader loads recon plugins
    │       ├─► Pipeline.run_stage(RECON, plugins, targets)
    │       │       │
    │       │       ├─► plugin.setup(workspace)
    │       │       ├─► async for finding in plugin.run(target):
    │       │       │       yield finding → EventBus.emit(FINDING_CREATED)
    │       │       ├─► plugin.teardown()
    │       │       └─► return PipelineResult
    │       │
    │       └─► Findings saved to DB via Repository
    │
    ├─► Engine.run_audit(targets, categories=["web","api","auth"])
    │       │  (same flow but with audit plugins)
    │       └─► Uses recon-discovered targets and endpoints
    │
    └─► ReportGenerator.generate_json/markdown/html(findings)
```

### Exploitation Flow

```
User: exploit <finding-id>
    │
    ▼
ScopeGuard.check_exploitation(target)
    │ (validates target is in scope + exploitation enabled)
    ▼
ScopeGuard.confirm(target, "exploit")
    │ (user confirmation if required)
    ▼
ExploitRegistry.find_for_finding(plugin_name)
    │ (finds matching exploit module)
    ▼
exploit.check(target, finding)
    │ (verifies exploitability)
    ▼
PayloadGenerator.reverse_shell(config)
    │ (generates appropriate payload)
    ▼
ListenerPool.start(name, config)
    │ (starts TCP/HTTP listener)
    ▼
exploit.run(target, finding, payload)
    │ (delivers exploit, connects to listener)
    ▼
SessionManager.create(reader, writer, target)
    │ (creates session record)
    ▼
User: sessions -i <id>
    │ (interactive shell session)
    ▼
post/persistence, post/pivot, post/cleanup
```

## Key Design Decisions

### Why Async?
The platform needs to scan thousands of endpoints (subdomains, directories, parameters) concurrently. Async I/O allows hundreds of concurrent HTTP/DNS requests with minimal resource overhead.

### Why Plugin Architecture?
Security tools must be extensible. New vulnerability classes emerge constantly. A plugin system allows adding new modules without modifying core engine code.

### Why Dual Engine?
Separation of audit (detection) and exploitation (action) reduces accidental exploitation risks. The scope guard provides a single gate through which all exploit actions must pass.

### Why SQLite (initially)?
Zero-config deployment. Users can start scanning immediately without setting up PostgreSQL. The repository pattern allows seamless migration when needed.

### Why Workspace-Based?
Multi-target audits require scope management, target tracking, and finding organization. Workspaces group everything under a named project with independent scope configuration.

## Extension Guide

### Adding a New Reconnaissance Plugin

1. Create `marlonthebug/plugins/recon/my_scanner.py`:

```python
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

class MyScanner(BasePlugin):
    name = "my_scanner"
    version = "1.0.0"
    description = "My custom scanner"
    category = "recon"

    async def setup(self, workspace):
        self.workspace = workspace

    async def run(self, target, options=None):
        yield Finding(
            plugin_name=self.name,
            title="Found something",
            description="Description of finding",
            severity=Severity.HIGH,
            cvss_score=7.5,
            endpoint=target.host,
            target_host=target.host,
            category=self.category,
        )
```

The plugin is auto-discovered on next launch.

### Adding a New Exploit Module

1. Create `marlonthebug/exploit/webapp/my_exploit.py`:

```python
from marlonthebug.exploit.base import BaseExploit, ExploitResult

class MyExploit(BaseExploit):
    name = "my_exploit"
    category = "webapp"
    description = "Exploits my vulnerability"

    async def check(self, target, finding):
        # Verify exploitability
        return True

    async def run(self, target, finding, payload=None):
        # Execute exploit
        return ExploitResult(success=True, output="Exploited!")
```

2. Register the finding-to-exploit mapping:

```python
from marlonthebug.exploit.registry import ExploitRegistry
registry.map_finding("my_scanner", "webapp/my_exploit")
```

### Adding a New Wordlist

Place a `.txt` file in `marlonthebug/fuzzer/wordlists/` and reference it by name in the fuzzer configuration.
