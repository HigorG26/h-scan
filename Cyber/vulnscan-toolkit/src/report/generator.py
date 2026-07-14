"""
ReportGenerator - motor de relatórios.

Fluxo:
  1. Recebe a lista de Findings (já normalizados pelos módulos).
  2. Calcula estatísticas agregadas (contagem por severidade, CVSS médio,
     top módulos) para o Sumário Executivo.
  3. Renderiza um template Jinja2 (report/templates/report.html.j2) com:
       - Sumário Executivo
       - Nível de Criticidade (badges CVSS/Severidade)
       - Detalhes Técnicos (endpoint, parâmetro, payload/evidência)
       - Recomendações de Mitigação
  4. Exporta em HTML (sempre) e, se solicitado, converte para PDF via
     WeasyPrint (não depende de wkhtmltopdf externo, mais fácil de
     conteinerizar).
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.finding import Finding, Severity

log = logging.getLogger("vulnscan.report")

TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class ReportGenerator:
    def __init__(self, target: str, run_id: str, findings: list[Finding], out_dir: Path):
        self.target = target
        self.run_id = run_id
        self.findings = findings
        self.out_dir = out_dir

    def _build_summary(self) -> dict:
        counts = Counter(f.severity for f in self.findings)
        scored = [f.cvss_score for f in self.findings if f.cvss_score is not None]
        avg_cvss = round(sum(scored) / len(scored), 1) if scored else None

        return {
            "total_findings": len(self.findings),
            "by_severity": {sev.value: counts.get(sev, 0) for sev in SEVERITY_ORDER},
            "avg_cvss": avg_cvss,
            "modules_run": sorted({f.module for f in self.findings}),
        }

    def _sorted_findings(self) -> list[Finding]:
        rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
        return sorted(self.findings, key=lambda f: rank.get(f.severity, 99))

    def generate(self, fmt: str = "both") -> list[Path]:
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        template = env.get_template("report.html.j2")

        html = template.render(
            target=self.target,
            run_id=self.run_id,
            generated_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
            summary=self._build_summary(),
            findings=self._sorted_findings(),
        )

        html_path = self.out_dir / "relatorio.html"
        html_path.write_text(html, encoding="utf-8")

        generated_paths = [html_path]

        if fmt in ("pdf", "both"):
            pdf_path = self.out_dir / "relatorio.pdf"
            try:
                from weasyprint import HTML  # import tardio: dependência pesada, só carrega se precisar

                HTML(string=html, base_url=str(self.out_dir)).write_pdf(str(pdf_path))
                generated_paths.append(pdf_path)
            except Exception as exc:
                log.error("Falha ao gerar PDF via WeasyPrint: %s. Relatório HTML ainda disponível.", exc)

        return generated_paths
