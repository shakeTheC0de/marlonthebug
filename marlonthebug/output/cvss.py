"""CVSS 3.1 calculator — parses vector strings and computes scores."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class CVSS31:
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"
    A: str = "N"

    _WEIGHTS: ClassVar[dict[str, dict[str, float]]] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "PR_CHANGED": {"N": 0.85, "L": 0.68, "H": 0.50},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }

    @classmethod
    def from_vector(cls, vector: str) -> CVSS31:
        instance = cls()
        if not vector.startswith("CVSS:3.1/"):
            return instance
        parts = vector.replace("CVSS:3.1/", "").split("/")
        for part in parts:
            if ":" not in part:
                continue
            key, value = part.split(":", 1)
            if hasattr(instance, key):
                setattr(instance, key, value)
        return instance

    def to_vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    def base_score(self) -> float:
        iss = 1 - ((1 - self._WEIGHTS["C"][self.C]) *
                   (1 - self._WEIGHTS["I"][self.I]) *
                   (1 - self._WEIGHTS["A"][self.A]))

        if self.S == "U":
            impact = self._WEIGHTS["S_CHANGED"] if False else 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        pr_key = "PR_CHANGED" if self.S == "C" else "PR"
        exploitability = (
            8.22
            * self._WEIGHTS["AV"][self.AV]
            * self._WEIGHTS["AC"][self.AC]
            * self._WEIGHTS[pr_key][self.PR]
            * self._WEIGHTS["UI"][self.UI]
        )

        if impact <= 0:
            return 0.0

        if self.S == "U":
            score = impact + exploitability
        else:
            score = 1.08 * (impact + exploitability)

        return float(math.ceil(min(score, 10.0) * 10) / 10)

    def severity(self) -> str:
        score = self.base_score()
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "info"

    @staticmethod
    def quick_score(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
        return CVSS31(AV=av, AC=ac, PR=pr, UI=ui, S=s, C=c, I=i, A=a).base_score()

    @staticmethod
    def from_severity(severity: str) -> float:
        mapping = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0,
        }
        return mapping.get(severity.lower(), 0.0)
