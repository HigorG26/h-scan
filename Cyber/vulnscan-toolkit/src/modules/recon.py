"""
ReconModule - varredura leve de reconhecimento (Nikto).

Roda antes dos módulos mais invasivos para levantar informações gerais do
servidor (headers, arquivos expostos, configurações inseguras). Usa o
Nikto via CLI e faz parsing da saída em -Format json.
"""

from __future__ import annotations

import json

from core.finding import Finding, Severity
from modules.base import BaseScanModule


class ReconModule(BaseScanModule):
    name = "recon"

    def run(self) -> list[Finding]:
        out_json = self.work_dir / "nikto.json"
        cmd = [
            "nikto",
            "-h", self.target,
            "-Format", "json",
            "-output", str(out_json),
        ]
        self._run_cli(cmd, timeout=self.settings.get("recon_timeout", 600))

        if not out_json.exists():
            return []

        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for item in data.get("vulnerabilities", []):
            findings.append(
                Finding(
                    module=self.name,
                    title=item.get("msg", "Achado do Nikto")[:120],
                    description=item.get("msg", ""),
                    severity=Severity.LOW,
                    endpoint=item.get("url", self.target),
                    evidence=item.get("id"),
                    recommendation="Revisar configuração do servidor / remover exposição desnecessária.",
                    tool_source="nikto",
                )
            )
        return findings
