"""
VulnScan Toolkit - Orquestrador de varredura de vulnerabilidades web
======================================================================

Ponto de entrada (CLI) da ferramenta. Responsável por:
  1. Ler os argumentos de linha de comando (alvo, módulos, perfil de scan).
  2. Validar o escopo (garantir que o alvo é autorizado / está em allowlist).
  3. Disparar o orquestrador, que executa os módulos de varredura selecionados.
  4. Consolidar os achados e acionar o motor de relatórios (HTML/PDF).

Uso básico:
    python main.py --target https://app-teste.local --profile full --out ./reports

IMPORTANTE (uso ético/legal):
    Esta ferramenta deve ser executada SOMENTE contra ativos para os quais
    você possui autorização explícita por escrito (pentest autorizado,
    ambiente de laboratório próprio, ou programa de bug bounty com escopo
    definido). O arquivo scope.yaml funciona como trava de segurança:
    o scan é abortado se o alvo não estiver na allowlist.
"""

from __future__ import annotations

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime

from core.orchestrator import ScanOrchestrator
from core.scope_guard import ScopeGuard
from config.settings import load_settings
from report.generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vulnscan.main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnscan-toolkit",
        description="Orquestrador modular de varredura de vulnerabilidades web (SQLi, XSS, XXE, etc).",
    )
    parser.add_argument("--target", required=True, help="URL base do alvo (ex: https://app-teste.local)")
    parser.add_argument(
        "--profile",
        choices=["quick", "full", "custom"],
        default="quick",
        help="Perfil de varredura: quick (rápido), full (completo), custom (definido em modules.yaml)",
    )
    parser.add_argument(
        "--modules",
        nargs="*",
        default=None,
        help="Lista explícita de módulos a rodar (sobrepõe o profile). Ex: --modules sqli xss xxe",
    )
    parser.add_argument(
        "--out",
        default="/app/reports",
        help="Diretório de saída dos relatórios (padrão: /app/reports, que é o volume montado pelo docker-compose)",
    )
    parser.add_argument(
        "--format",
        choices=["html", "pdf", "both"],
        default="both",
        help="Formato do relatório final",
    )
    parser.add_argument(
        "--scope-file",
        default="/app/config/scope.yaml",
        help="Arquivo com a allowlist de alvos autorizados (padrão: /app/config/scope.yaml, volume montado)",
    )
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirmação explícita de que você possui autorização para testar o alvo",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.i_have_authorization:
        log.error(
            "Execução abortada: use --i-have-authorization para confirmar que você "
            "possui autorização formal para testar o alvo informado."
        )
        return 1

    settings = load_settings()

    # 1. Trava de escopo: nunca varrer algo fora da allowlist
    guard = ScopeGuard(scope_file=args.scope_file)
    if not guard.is_authorized(args.target):
        log.error("Alvo '%s' não está na allowlist (%s). Abortando.", args.target, args.scope_file)
        return 1

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("Iniciando varredura [run_id=%s] alvo=%s perfil=%s", run_id, args.target, args.profile)

    # 2. Orquestração dos módulos de scan
    orchestrator = ScanOrchestrator(
        target=args.target,
        profile=args.profile,
        modules_override=args.modules,
        settings=settings,
        run_dir=out_dir,
    )
    findings = orchestrator.run()

    # 3. Geração do relatório consolidado
    report = ReportGenerator(
        target=args.target,
        run_id=run_id,
        findings=findings,
        out_dir=out_dir,
    )
    paths = report.generate(fmt=args.format)

    log.info("Varredura concluída. Relatórios gerados:")
    for p in paths:
        log.info("  -> %s", p)

    return 0


if __name__ == "__main__":
    sys.exit(main())
