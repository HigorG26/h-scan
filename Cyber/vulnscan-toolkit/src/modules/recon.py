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

        # O -Format json do Nikto retorna uma LISTA de resultados por host
        # escaneado (não um único dict), cada um com sua própria chave
        # "vulnerabilities". Normaliza para sempre iterar uma lista de hosts.
        host_results = data if isinstance(data, list) else [data]

        findings: list[Finding] = []
        for host_result in host_results:
            for item in host_result.get("vulnerabilities", []):
                findings.append(
                    Finding(
                        module=self.name,
                        title=item.get("msg", "Achado do Nikto")[:120],
                        description=item.get("msg", ""),
                        severity=Severity.LOW,
                        endpoint=item.get("url", self.target),
                        evidence=str(item.get("id", "")),
                        recommendation="Revisar configuração do servidor / remover exposição desnecessária.",
                        references=[item["references"]] if item.get("references") else [],
                        tool_source="nikto",
                    )
                )
        return findings
