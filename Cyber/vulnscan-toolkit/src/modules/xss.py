"""
XssModule - detecção de Cross-Site Scripting via OWASP ZAP (baseline scan).

Desde a v2.15 do ZAP, o script zap-baseline.py deixou de ser distribuído no
pacote desktop (.tar.gz) e só existe dentro da imagem oficial do ZAP
(ghcr.io/zaproxy/zaproxy:stable). Reempacotar isso manualmente dentro da
nossa própria imagem é frágil e quebra a cada release do ZAP.

Por isso este módulo usa Docker-outside-of-Docker (DooD): dispara a imagem
oficial do ZAP como um container-irmão (via socket do Docker montado em
/var/run/docker.sock), na mesma rede Docker do alvo, e le o relatório JSON
resultante de volta através do bind mount compartilhado de ./reports.

Pré-requisitos para este módulo funcionar (ver README):
  - o container do vulnscan-toolkit precisa rodar com
    -v /var/run/docker.sock:/var/run/docker.sock
  - a variável de ambiente HOST_REPORTS_DIR deve apontar para o caminho,
    no HOST (não dentro do container), do diretório bind-mountado em
    /app/reports - necessário porque volumes do `docker run` disparado
    daqui de dentro são resolvidos pelo daemon do Docker do host, não
    pelo sistema de arquivos deste container.
  - a rede passada em settings["docker_network"] deve ser a mesma rede
    Docker onde o alvo está acessível (ex: vulnscan-net).
"""

from __future__ import annotations

import json
import os

from core.finding import Finding, Severity
from modules.base import BaseScanModule

REPORTS_MOUNT_CONTAINER = "/app/reports"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

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

    def _host_work_dir(self) -> str | None:
        """
        Traduz self.work_dir (caminho DENTRO deste container, ex:
        /app/reports/<run_id>/xss) para o caminho equivalente no HOST,
        usando HOST_REPORTS_DIR como base. Necessário para que o container-
        irmão do ZAP (criado pelo daemon do Docker do host) monte o volume
        certo.
        """
        host_reports_dir = os.environ.get("HOST_REPORTS_DIR")
        if not host_reports_dir:
            return None

        work_dir_str = str(self.work_dir)
        if work_dir_str.startswith(REPORTS_MOUNT_CONTAINER):
            relative = work_dir_str[len(REPORTS_MOUNT_CONTAINER):].lstrip("/")
        else:
            relative = self.work_dir.name

        return f"{host_reports_dir.rstrip('/')}/{relative}"

    def run(self) -> list[Finding]:
        out_json = self.work_dir / "zap-report.json"

        host_work_dir = self._host_work_dir()
        if not host_work_dir:
            log_msg = (
                "HOST_REPORTS_DIR não definida - não é possível montar o volume "
                "para o container-irmão do ZAP (Docker-outside-of-Docker). "
                "Rode o vulnscan-toolkit com: -e HOST_REPORTS_DIR=\"$(pwd)/reports\" "
                "-v /var/run/docker.sock:/var/run/docker.sock"
            )
            (self.work_dir / "stderr.log").write_text(log_msg, encoding="utf-8")
            return []

        network = self.settings.get("docker_network", "vulnscan-net")
        cmd = [
            "docker", "run", "--rm",
            "--network", network,
            "-v", f"{host_work_dir}:/zap/wrk:rw",
            ZAP_IMAGE,
            "zap-baseline.py",
            "-t", self.target,
            "-J", "zap-report.json",
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
