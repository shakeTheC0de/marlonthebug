"""Ed25519 signatures for offline intelligence bundles.

The bundle is signed as-is and the detached signature is stored next to it
(`intel-bundle.json.sig`) as base64. Verification uses the raw public key PEM,
which can be distributed with the bundle or configured in
``intel.signing_public_key``.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_SUFFIX = ".sig"


class SigningError(RuntimeError):
    """Raised when a key or signature is missing, invalid or unsafe."""


def generate_keypair(private_path: Path, public_path: Path, *, force: bool = False) -> tuple[Path, Path]:
    private_path = private_path.expanduser().resolve()
    public_path = public_path.expanduser().resolve()
    if not force and (private_path.exists() or public_path.exists()):
        raise SigningError("La clave ya existe; usa --force para sobrescribirla")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(private_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(private_bytes)
    finally:
        os.chmod(private_path, 0o600)
    public_path.write_bytes(public_bytes)
    return private_path, public_path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.expanduser().read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise SigningError(f"No se pudo leer la clave privada {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("La clave privada no es Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.expanduser().read_bytes())
    except (OSError, ValueError) as exc:
        raise SigningError(f"No se pudo leer la clave pública {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("La clave pública no es Ed25519")
    return key


def sign_bundle(bundle_path: Path, private_key_path: Path, signature_path: Path | None = None) -> Path:
    bundle_path = bundle_path.expanduser().resolve()
    if not bundle_path.is_file():
        raise SigningError(f"No existe el bundle: {bundle_path}")
    key = load_private_key(private_key_path)
    signature = key.sign(bundle_path.read_bytes())
    target = (
        signature_path.expanduser() if signature_path else bundle_path.with_name(bundle_path.name + SIGNATURE_SUFFIX)
    )
    target.resolve().parent.mkdir(parents=True, exist_ok=True)
    target.write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
    return target.resolve()


def verify_bundle(
    bundle_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> None:
    bundle_path = bundle_path.expanduser().resolve()
    signature_path = signature_path.expanduser().resolve()
    if not bundle_path.is_file():
        raise SigningError(f"No existe el bundle: {bundle_path}")
    if not signature_path.is_file():
        raise SigningError(f"No existe la firma: {signature_path}")
    key = load_public_key(public_key_path)
    try:
        signature = base64.b64decode(signature_path.read_text(encoding="ascii").strip(), validate=True)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SigningError("La firma no es base64 válido") from exc
    try:
        key.verify(signature, bundle_path.read_bytes())
    except InvalidSignature as exc:
        raise SigningError("La firma no corresponde al bundle") from exc


def public_key_fingerprint(public_key_path: Path) -> str:
    key = load_public_key(public_key_path)
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()
