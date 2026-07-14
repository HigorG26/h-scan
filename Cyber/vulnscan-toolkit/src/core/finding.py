"""
Modelo de dado central: Finding.

Todo módulo de varredura, independentemente da ferramenta que ele invoca
por trás (sqlmap, ZAP, nikto, etc.), deve normalizar seu resultado para
este formato. Isso é o que permite que o motor de relatórios seja
totalmente desacoplado dos módulos de scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Crítica"
    HIGH = "Alta"
    MEDIUM = "Média"
    LOW = "Baixa"
    INFO = "Informativa"


@dataclass
class Finding:
    module: str                 # ex: "sqli", "xss", "xxe"
    title: str                  # ex: "SQL Injection em parâmetro 'id'"
    description: str
    severity: Severity
    cvss_vector: str | None = None   # ex: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    cvss_score: float | None = None
    endpoint: str | None = None
    parameter: str | None = None
    evidence: str | None = None      # payload/request/response relevante
    recommendation: str | None = None
    references: list[str] = field(default_factory=list)
    tool_source: str | None = None   # ex: "sqlmap", "zap", "nikto"

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d
