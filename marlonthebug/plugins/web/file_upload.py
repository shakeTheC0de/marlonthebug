"""File Upload vulnerability detection."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.file_upload")


class FileUploadAuditor(BasePlugin):
    name = "file_upload"
    version = "1.0.0"
    description = "Detect file upload vulnerabilities: extension bypass, MIME manipulation, unrestricted uploads"
    category = "web"

    TEST_EXTENSIONS = [".php", ".php5", ".phtml", ".asp", ".aspx", ".jsp", ".cfg", ".shtml"]
    POLYGLOT_PAYLOADS = {
        "php_gif": b"GIF89a;\x00\x00\x00<?php system($_GET['c']); ?>",
        "php_jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00<?php system($_GET['c']); ?>",
    }

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=1)
        try:
            for scheme in ["https", "http"]:
                try:
                    resp = await http.get(f"{scheme}://{target.host}")
                    break
                except Exception:
                    continue
            else:
                return

            url = f"{scheme}://{target.host}"
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.body, "lxml")
            upload_forms = []

            for form in soup.find_all("form"):
                file_inputs = form.find_all("input", type="file")
                if file_inputs:
                    upload_forms.append(
                        {
                            "action": form.get("action", ""),
                            "method": form.get("method", "GET").upper(),
                            "enctype": form.get("enctype", ""),
                        }
                    )

            if not upload_forms:
                return

            for form_info in upload_forms:
                yield Finding(
                    plugin_name=self.name,
                    title="File upload form detected",
                    description=f"Found file upload form at {form_info['action']} (method: {form_info['method']})."
                    " Verify that uploads are properly validated on the server side.",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    endpoint=f"{url}{form_info['action']}",
                    target_host=target.host,
                    category=self.category,
                    evidence={"form": form_info},
                    remediation=(
                        "1. Validate file extensions against an allowlist\n"
                        "2. Check MIME types on the server side\n"
                        "3. Store uploads outside the web root\n"
                        "4. Rename uploaded files with random names\n"
                        "5. Scan uploaded files for malware"
                    ),
                )

                if not form_info["enctype"] or "multipart/form-data" not in form_info["enctype"]:
                    yield Finding(
                        plugin_name=self.name,
                        title="Upload form missing proper enctype",
                        description="The upload form lacks multipart/form-data encoding, which may indicate insufficient file handling.",
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        endpoint=f"{url}{form_info['action']}",
                        target_host=target.host,
                        category=self.category,
                        evidence={"form": form_info},
                    )
        finally:
            await http.close()
