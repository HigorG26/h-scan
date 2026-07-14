"""
XxeModule - detecção de XML External Entity via templates do Nuclei.

XXE não tem uma ferramenta "clássica" dedicada como sqlmap tem para SQLi;
a abordagem consolidada na comunidade é usar o Nuclei com templates da
categoria `xxe` (mantidos pela ProjectDiscovery/comunidade), que testam
endpoints que aceitam XML com payloads de entidade externa e out-of-band
callback (via interactsh) para confirmar exploração.

Saída: nuclei -jsonl, um objeto JSON por linha.
"""

from __future__ import annotations

import json

from core.finding import Finding, Severity
from modules.base import BaseScanModule

CVSS_XXE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_SCORE_XXE = 7.5

NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class XxeModule(BaseScanModule):
    name = "xxe"

    def run(self) -> list[Finding]:
        out_jsonl = self.work_dir / "nuclei-xxe.jsonl"
        cmd = [
            "nuclei",
            "-u", self.target,
            "-tags", "xxe",
            "-jsonl",
            "-o", str(out_jsonl),
            "-silent",
        ]
        self._run_cli(cmd, timeout=self.settings.get("xxe_timeout", 900))

        if not out_jsonl.exists():
            return []

        findings: list[Finding] = []
        for line in out_jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            severity = NUCLEI_SEVERITY_MAP.get((info.get("severity") or "").lower(), Severity.MEDIUM)

            findings.append(
                Finding(
                    module=self.name,
                    title=info.get("name", "XXE - XML External Entity"),
                    description=info.get("description", ""),
                    severity=severity,
                    cvss_vector=CVSS_XXE,
                    cvss_score=CVSS_SCORE_XXE,
                    endpoint=item.get("matched-at", self.target),
                    evidence=item.get("extracted-results") or item.get("curl-command"),
                    recommendation=(
                        "Desabilitar resolução de entidades externas e DTDs no parser XML "
                        "(ex: disable-external-entities), preferir parsers seguros por padrão "
                        "(defusedxml) e validar/whitelist de tipos de conteúdo aceitos."
                    ),
                    references=info.get("reference") or [],
                    tool_source="nuclei",
                )
            )
        return findings
