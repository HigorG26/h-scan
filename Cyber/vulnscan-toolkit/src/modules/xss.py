"""
XssModule - detecção de Cross-Site Scripting via OWASP ZAP (baseline scan).

Usa a imagem/binário do OWASP ZAP em modo "baseline" (zap-baseline.py),
que sobe o ZAP, faz spider passivo + varredura ativa leve, e retorna um
relatório em JSON. Este módulo filtra apenas os alertas relacionados a
XSS (Reflected, Stored, DOM) e normaliza em Findings.

Pré-requisito no container: pacote `zaproxy` (ou binário zap.sh) instalado
e no PATH, ou uso do wrapper `zap-baseline.py` incluído nas imagens
oficiais do ZAP.
"""

from __future__ import annotations

import json

from core.finding import Finding, Severity
from modules.base import BaseScanModule

XSS_KEYWORDS = ("cross site scripting", "xss")

ZAP_RISK_TO_SEVERITY = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}

CVSS_XSS_REFLECTED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CVSS_SCORE_XSS_REFLECTED = 6.1


class XssModule(BaseScanModule):
    name = "xss"

    def run(self) -> list[Finding]:
        out_json = self.work_dir / "zap-report.json"
        cmd = [
            "zap-baseline.py",
            "-t", self.target,
            "-J", str(out_json),
            "-m", str(self.settings.get("zap_spider_minutes", 2)),
        ]
        # zap-baseline.py retorna código != 0 quando encontra alertas; não tratar como erro fatal
        self._run_cli(cmd, timeout=self.settings.get("xss_timeout", 1200))

        if not out_json.exists():
            return []

        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                name = (alert.get("name") or "").lower()
                if not any(k in name for k in XSS_KEYWORDS):
                    continue

                risk = alert.get("riskdesc", "").split(" ")[0]
                severity = ZAP_RISK_TO_SEVERITY.get(risk, Severity.MEDIUM)

                for instance in alert.get("instances", [{}]):
                    findings.append(
                        Finding(
                            module=self.name,
                            title=alert.get("name", "Cross-Site Scripting"),
                            description=alert.get("desc", ""),
                            severity=severity,
                            cvss_vector=CVSS_XSS_REFLECTED,
                            cvss_score=CVSS_SCORE_XSS_REFLECTED,
                            endpoint=instance.get("uri", self.target),
                            parameter=instance.get("param"),
                            evidence=instance.get("evidence"),
                            recommendation=alert.get(
                                "solution",
                                "Aplicar output encoding contextual e Content-Security-Policy.",
                            ),
                            references=[r for r in (alert.get("reference") or "").split("\n") if r],
                            tool_source="owasp-zap",
                        )
                    )
        return findings
