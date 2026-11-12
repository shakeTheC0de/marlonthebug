# MarlonTheBug

**Offensive Security Auditing & Exploitation Platform**

A modern, modular, scalable platform for security auditing of websites, APIs, servers, and infrastructure. Built for controlled penetration testing of systems you own.

## Quick Start

```bash
# Clone and install
git clone https://github.com/marlonthebug/marlonthebug
cd marlonthebug
uv sync

# Launch interactive console
uv run marlonthebug console

# CLI commands
uv run marlonthebug workspace create --name "my-audit"
uv run marlonthebug workspace add --domains "example.com,api.example.com"
uv run marlonthebug recon run
uv run marlonthebug audit run --category web
uv run marlonthebug report generate --format html
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    CLI / TUI Shell (Textual + Typer)          │
├──────────────────────────────────────────────────────────────┤
│  Audit Engine (Detection + Analysis)                         │
│  ├── Reconnaissance  ├── Web Auditing  ├── API Security      │
│  ├── Auth & Access   ├── Cloud/Containers ├── CI/CD          │
│  └── AI/LLM Security                                        │
├──────────────────────────────────────────────────────────────┤
│  Exploitation Engine (Payload + Post-Exploit)                │
│  ├── Payload Gen  ├── Listeners  ├── Sessions  ├── Post     │
├──────────────────────────────────────────────────────────────┤
│  Core Services: HTTP Engine, Fuzzer, OOB, Crawler, DB       │
└──────────────────────────────────────────────────────────────┘
```

## Features

### Phase 1 — Foundation + Reconnaissance
- Interactive TUI console with full command set
- Workspace-based multi-target scoping
- Async HTTP engine with retry/backoff, proxy rotation, WAF fingerprinting
- Plugin system with auto-discovery
- CVSS 3.1 calculator and professional report generation
- OOB Collaborator for blind vulnerability detection
- Intelligent async crawler with JS endpoint extraction
- Listener infrastructure for reverse connections
- Adaptive fuzzing engine with mutation strategies
- **Reconnaissance plugins**: Subdomain enumeration, DNS brute force, technology fingerprinting, hidden endpoint discovery, JavaScript analysis, secret/credential detection, .git leaks

### Coming in Phase 2 — Web Auditing
SQLi, XSS, SSRF, CSRF, Path Traversal, LFI/RFI, File Upload, SSTI, Command Injection, Deserialization, RCE, Open Redirect, Request Smuggling, WAF Bypass, Race Conditions, Business Logic

### Coming in Phase 3-6
API Security, Auth & Access Control, Cloud & Containers, CI/CD Supply Chain, AI/LLM Security

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.12+ |
| Async | asyncio + anyio |
| CLI/TUI | Typer + Rich + Textual |
| HTTP | httpx (async, HTTP/2) |
| Parsing | BeautifulSoup4 + lxml |
| ORM | SQLAlchemy 2.0 (async) |
| DB | aiosqlite (dev) / asyncpg + PostgreSQL (prod) |
| Reports | Jinja2 (HTML/Markdown) |
| Config | PyYAML + Pydantic |
| Testing | pytest + pytest-asyncio |
| Linting | ruff + mypy |

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=marlonthebug

# Lint
uv run ruff check .

# Type check
uv run mypy marlonthebug/
```

## Safety & Scope

MarlonTheBug includes strict scope guards:
- Domain and IP-based target validation
- Exploitation must be explicitly enabled per workspace
- Confirmation prompts before exploit execution
- Full audit logging of all actions

**Always ensure you have explicit authorization before testing any system.**

## License

MIT
