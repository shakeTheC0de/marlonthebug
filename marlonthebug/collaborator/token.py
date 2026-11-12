"""Collaborator token management — per-scan unique tokens for callback correlation."""

import string
import secrets
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("marlonthebug.collaborator")


@dataclass
class CollaboratorToken:
    token: str
    plugin_name: str
    scan_id: str = ""
    target: str = ""
    purpose: str = ""

    @property
    def http_payload(self) -> str:
        return f"http://collaborator.local/{self.token}"

    @property
    def dns_payload(self) -> str:
        return f"{self.token}.oob.local"


class TokenManager:
    def __init__(self, length: int = 16) -> None:
        self.length = length
        self._tokens: dict[str, CollaboratorToken] = {}

    def create_token(self, plugin_name: str, scan_id: str = "", target: str = "", purpose: str = "") -> CollaboratorToken:
        token_str = self._generate()
        ct = CollaboratorToken(
            token=token_str,
            plugin_name=plugin_name,
            scan_id=scan_id,
            target=target,
            purpose=purpose,
        )
        self._tokens[token_str] = ct
        logger.debug("Created collaborator token %s for %s", token_str, plugin_name)
        return ct

    def get_token(self, token_str: str) -> CollaboratorToken | None:
        return self._tokens.get(token_str)

    def remove_token(self, token_str: str) -> None:
        self._tokens.pop(token_str, None)

    def _generate(self) -> str:
        chars = string.ascii_lowercase + string.digits
        while True:
            token = "".join(secrets.choice(chars) for _ in range(self.length))
            if token not in self._tokens:
                return token

    def active_count(self) -> int:
        return len(self._tokens)
