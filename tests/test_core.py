"""Tests for MarlonTheBug core components."""

from pathlib import Path

import pytest

from marlonthebug import __version__
from marlonthebug.output.cvss import CVSS31 as CVSS


def test_version() -> None:
    assert __version__ == "2.0.0"


class TestCVSS:
    def test_critical_score(self) -> None:
        score = CVSS.quick_score("N", "L", "N", "N", "U", "H", "H", "H")
        assert score >= 9.0

    def test_high_score(self) -> None:
        score = CVSS.quick_score("N", "L", "L", "N", "U", "H", "H", "N")
        assert 7.0 <= score < 9.0

    def test_medium_score(self) -> None:
        score = CVSS.quick_score("N", "H", "L", "R", "U", "L", "L", "N")
        assert 0.0 < score < 10.0

    def test_low_score(self) -> None:
        score = CVSS.quick_score("L", "H", "H", "R", "U", "N", "N", "N")
        assert score >= 0.0

    def test_vector_parse(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cvss = CVSS.from_vector(vector)
        assert cvss.AV == "N"
        assert cvss.AC == "L"
        assert cvss.C == "H"
        assert cvss.base_score() >= 9.0

    def test_severity_mapping(self) -> None:
        assert CVSS.quick_score("N", "L", "N", "N", "U", "H", "H", "H") >= 9.0
        assert CVSS.quick_score("L", "H", "H", "R", "U", "N", "N", "N") < 4.0


class TestScope:
    def test_scope_guard_allows_matching_domain(self) -> None:
        from marlonthebug.core.scope import ScopeConfig, ScopeGuard

        config = ScopeConfig(allowed_domains=["*.example.com"])
        guard = ScopeGuard(config)
        assert guard.check("api.example.com")
        assert guard.check("admin.example.com")
        assert not guard.check("evil.com")

    def test_scope_guard_allows_matching_ip(self) -> None:
        from marlonthebug.core.scope import ScopeConfig, ScopeGuard

        config = ScopeConfig(allowed_ip_ranges=["10.0.1.0/24"])
        guard = ScopeGuard(config)
        assert guard.check("10.0.1.15")
        assert not guard.check("192.168.1.1")

    def test_scope_exclusion(self) -> None:
        from marlonthebug.core.scope import ScopeConfig, ScopeGuard

        config = ScopeConfig(
            allowed_domains=["*.example.com"],
            excluded=["*.cdn.example.com"],
        )
        guard = ScopeGuard(config)
        assert guard.check("api.example.com")
        assert not guard.check("static.cdn.example.com")

    def test_exploitation_disabled(self) -> None:
        from marlonthebug.core.scope import ScopeConfig, ScopeGuard

        config = ScopeConfig(allow_exploitation=False)
        guard = ScopeGuard(config)
        assert not guard.check_exploitation("example.com")

    def test_exploitation_enabled(self) -> None:
        from marlonthebug.core.scope import ScopeConfig, ScopeGuard

        config = ScopeConfig(
            allowed_domains=["example.com"],
            allow_exploitation=True,
            require_confirmation=False,
        )
        guard = ScopeGuard(config)
        assert guard.check_exploitation("example.com")


class TestPlugin:
    def test_finding_dataclass(self) -> None:
        from marlonthebug.plugins.base import Finding, Severity

        finding = Finding(
            plugin_name="test",
            title="Test Finding",
            description="A test finding",
            severity=Severity.HIGH,
            cvss_score=7.5,
            endpoint="/test",
            target_host="example.com",
        )
        d = finding.to_dict()
        assert d["plugin_name"] == "test"
        assert d["severity"] == "high"
        assert d["cvss_score"] == 7.5


class TestMutators:
    def test_case_mutations(self) -> None:
        from marlonthebug.fuzzer.mutators import Mutator

        mutator = Mutator()
        mutations = mutator.case_mutations("test")
        assert any("TEST" in m for m in mutations)
        assert any("test" in m for m in mutations)

    def test_encoding_mutations(self) -> None:
        from marlonthebug.fuzzer.mutators import Mutator

        mutator = Mutator()
        mutations = mutator.encoding_mutations("<>")
        assert any("%3c" in m.lower() for m in mutations)

    def test_mutate_return_count(self) -> None:
        from marlonthebug.fuzzer.mutators import Mutator

        mutator = Mutator()
        mutations = mutator.mutate("test", count=10)
        assert len(mutations) <= 10


class TestEncoder:
    def test_base64(self) -> None:
        from marlonthebug.exploit.payloads.encoders import Encoder

        encoded = Encoder.base64("test")
        import base64

        assert base64.b64decode(encoded).decode() == "test"

    def test_url_encode(self) -> None:
        from marlonthebug.exploit.payloads.encoders import Encoder

        assert Encoder.url("hello world") == "hello%20world"

    def test_hex_encode(self) -> None:
        from marlonthebug.exploit.payloads.encoders import Encoder

        assert "0x" in Encoder.hex("A")

    def test_encode_chain(self) -> None:
        from marlonthebug.exploit.payloads.encoders import encode_chain

        result = encode_chain("test", ["base64", "url"])
        assert result  # should produce valid output


class TestHeaders:
    def test_analyze_missing_headers(self) -> None:
        from marlonthebug.utils.headers import analyze_headers

        analysis = analyze_headers({})
        assert len(analysis.missing_headers) > 0
        assert analysis.score < 100

    def test_analyze_with_csp(self) -> None:
        from marlonthebug.utils.headers import analyze_headers

        analysis = analyze_headers(
            {
                "Content-Security-Policy": "default-src 'self'; base-uri 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
            }
        )
        assert analysis.score > 50
        assert analysis.csp_analysis.get("safe", False) is True

    def test_cookie_missing_flags(self) -> None:
        from marlonthebug.utils.headers import analyze_headers

        analysis = analyze_headers({"Set-Cookie": "session=abc123"})
        assert len(analysis.cookie_analysis) >= 1

    def test_cors_wildcard_issue(self) -> None:
        from marlonthebug.utils.headers import analyze_cors

        result = analyze_cors({"access-control-allow-origin": "*"})
        assert len(result["issues"]) > 0


class TestPayloads:
    def test_reverse_shell_generation(self) -> None:
        from marlonthebug.exploit.payloads.generator import OS, PayloadConfig, PayloadGenerator, PayloadType

        gen = PayloadGenerator()
        config = PayloadConfig(
            payload_type=PayloadType.REVERSE_SHELL,
            target_os=OS.LINUX,
            lhost="10.0.0.1",
            lport=4444,
        )
        payloads = gen.reverse_shell(config)
        assert len(payloads) > 0
        for p in payloads:
            assert "10.0.0.1" in p.command
            assert "4444" in p.command

    def test_web_shell_generation(self) -> None:
        from marlonthebug.exploit.payloads.generator import PayloadGenerator

        gen = PayloadGenerator()
        shells = gen.web_shell("php")
        assert len(shells) > 0
        assert any("system" in s.command for s in shells)

    def test_cheatsheet(self) -> None:
        from marlonthebug.exploit.payloads.generator import PayloadGenerator

        gen = PayloadGenerator()
        cheatsheet = gen.generate_cheatsheet("10.0.0.1", 4444)
        assert "bash" in cheatsheet
        assert "python" in cheatsheet


class TestCollaborator:
    def test_token_generation(self) -> None:
        from marlonthebug.collaborator.server import CollaboratorServer

        token1 = CollaboratorServer.generate_token(16)
        token2 = CollaboratorServer.generate_token(16)
        assert len(token1) == 16
        assert token1 != token2

    def test_callback_recording(self) -> None:
        from marlonthebug.collaborator.server import CollaboratorServer

        server = CollaboratorServer()
        server._record("test123", "1.2.3.4", "HTTP_GET", "/admin")
        assert server.has_callback("test123")
        callbacks = server.get_callbacks("test123")
        assert len(callbacks) == 1
        assert callbacks[0].source_ip == "1.2.3.4"


class TestWorkspace:
    def test_create_workspace(self, tmp_path: Path) -> None:
        from marlonthebug.core.workspace import WorkspaceManager

        mgr = WorkspaceManager(base_dir=tmp_path)
        ws = mgr.create("test-ws")
        assert ws.name == "test-ws"
        assert mgr.current == ws

    def test_add_target(self, tmp_path: Path) -> None:
        from marlonthebug.core.workspace import WorkspaceManager

        mgr = WorkspaceManager(base_dir=tmp_path)
        ws = mgr.create("test-ws")
        mgr.add_targets(domains=["example.com", "api.example.com"])
        assert "api.example.com" in ws.targets

    def test_list_workspaces(self, tmp_path: Path) -> None:
        from marlonthebug.core.workspace import WorkspaceManager

        mgr = WorkspaceManager(base_dir=tmp_path)
        mgr.create("ws1")
        mgr.create("ws2")
        workspaces = mgr.list_workspaces()
        assert "ws1" in workspaces
        assert "ws2" in workspaces

    def test_switch_workspace(self, tmp_path: Path) -> None:
        from marlonthebug.core.workspace import WorkspaceManager

        mgr = WorkspaceManager(base_dir=tmp_path)
        mgr.create("ws1")
        mgr.create("ws2")
        mgr.switch("ws1")
        assert mgr.current and mgr.current.name == "ws1"

    def test_delete_workspace(self, tmp_path: Path) -> None:
        from marlonthebug.core.workspace import WorkspaceManager

        mgr = WorkspaceManager(base_dir=tmp_path)
        mgr.create("ws1")
        mgr.delete("ws1")
        assert "ws1" not in mgr.list_workspaces()


class TestEvents:
    @pytest.mark.asyncio
    async def test_emit_event(self) -> None:
        from marlonthebug.core.events import Event, EventBus, EventType

        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe(EventType.FINDING_CREATED, handler)
        await bus.emit_now(
            Event(
                type=EventType.FINDING_CREATED,
                source="test",
                data={"key": "value"},
            )
        )
        assert len(received) == 1
        assert received[0].data["key"] == "value"

    @pytest.mark.asyncio
    async def test_wildcard_handler(self) -> None:
        from marlonthebug.core.events import Event, EventBus, EventType

        bus = EventBus()
        count = 0

        async def handler(event: Event) -> None:
            nonlocal count
            count += 1

        bus.subscribe(EventType.WILD, handler)
        await bus.emit_now(Event(type=EventType.SCAN_STARTED, source="test"))
        await bus.emit_now(Event(type=EventType.FINDING_CREATED, source="test"))
        assert count == 2


class TestFuzzer:
    def test_context_generators(self) -> None:
        from marlonthebug.fuzzer.generators import PayloadContext

        sql_payloads = PayloadContext.for_type("sqli")
        assert len(sql_payloads) > 0

        xss_payloads = PayloadContext.for_type("xss")
        assert len(xss_payloads) > 0

    def test_parameter_context(self) -> None:
        from marlonthebug.fuzzer.generators import PayloadContext

        payloads = PayloadContext.generate_for_parameter("id")
        assert len(payloads) > 0

        search_payloads = PayloadContext.generate_for_parameter("q")
        assert len(search_payloads) > 0


class TestTechFingerprinter:
    def test_signature_count(self) -> None:
        from marlonthebug.plugins.recon.tech_fingerprint import TECH_SIGNATURES

        assert len(TECH_SIGNATURES) > 20


class TestSecretFinder:
    def test_rules_count(self) -> None:
        from marlonthebug.plugins.recon.secret_finder import SECRET_RULES

        assert len(SECRET_RULES) > 15

    def test_aws_key_pattern(self) -> None:
        import re

        from marlonthebug.plugins.recon.secret_finder import SECRET_RULES

        aws_rule = next((r for r in SECRET_RULES if r["name"] == "AWS Access Key ID"), None)
        assert aws_rule is not None
        assert re.search(aws_rule["pattern"], "AKIAIOSFODNN7EXAMPLE")
        assert not re.search(aws_rule["pattern"], "not-a-key")
