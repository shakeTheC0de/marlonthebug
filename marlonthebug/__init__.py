"""MarlonTheBug — Offensive Security Auditing & Exploitation Platform."""

__version__ = "1.0.0"
__author__ = "MarlonTheBug Team"
__description__ = "Offensive Security Auditing & Exploitation Platform"

from marlonthebug.utils.logging import setup_logging

setup_logging()

__all__ = [
    "__version__",
    "__author__",
    "__description__",
]
