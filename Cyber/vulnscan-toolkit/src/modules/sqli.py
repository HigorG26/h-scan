"""
SqliModule - detecção de SQL Injection via sqlmap.

Invoca o sqlmap em modo --batch (não-interativo) contra o alvo e faz o
parsing do relatório JSON que o próprio sqlmap pode gerar
(--output-dir + leitura do log/target.txt), normalizando os parâmetros
vulneráveis encontrados em Findings com CVSS estimado.

Nota de projeto: a versão inicial faz parsing do log texto do sqlmap
(mais estável entre versões). Uma evolução (Sprint 3) é usar a REST API
do sqlmap (sqlmapapi.py) para obter JSON estruturado nativamente.
"""

from __future__ import annotations

import re

from core.finding import Finding, Severity
from modules.base import BaseScanModule

CVSS_SQLI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_SCORE_SQLI = 9.8


class SqliModule(BaseScanModule):
    name = "sqli"

    def run(self) -> list[Finding]:
        cmd = [
            "sqlmap",
            "-u", self.target,
            "--batch",
            "--random-agent",
            "--level", str(self.settings.get("sqli_level", 2)),
            "--risk", str(self.settings.get("sqli_risk", 1)),
            "--output-dir", str(self.work_dir),
        ]
        result = self._run_cli(cmd, timeout=self.settings.get("sqli_timeout", 1800))
        return self._parse_output(result.stdout)

    def _parse_output(self, stdout: str) -> list[Finding]:
        findings: list[Finding] = []

        # sqlmap imprime algo como: "Parameter: id (GET)" seguido do tipo de injeção
        param_blocks = re.findall(
            r"Parameter:\s*(\S+)\s*\((\w+)\)(.*?)(?=Parameter:|\Z)",
            stdout,
            re.DOTALL,
        )

        for param, method, block in param_blocks:
            findings.append(
                Finding(
                    module=self.name,
                    title=f"SQL Injection no parâmetro '{param}' ({method})",
                    description=block.strip()[:800] or "Parâmetro identificado como injetável pelo sqlmap.",
                    severity=Severity.CRITICAL,
                    cvss_vector=CVSS_SQLI,
                    cvss_score=CVSS_SCORE_SQLI,
                    endpoint=self.target,
                    parameter=param,
                    evidence=block.strip()[:2000],
                    recommendation=(
                        "Utilizar prepared statements/queries parametrizadas, aplicar "
                        "validação e allowlist de entrada, e restringir privilégios do "
                        "usuário de banco de dados usado pela aplicação."
                    ),
                    tool_source="sqlmap",
                )
            )

        return findings
