"""
BaseScanModule - contrato que todo módulo de varredura deve implementar.

Cada módulo real (SqliModule, XssModule, XxeModule, ...) tipicamente:
  1. Monta o comando CLI da ferramenta subjacente (sqlmap, zap-cli, nikto...).
  2. Executa via subprocess, salvando stdout/stderr/JSON em self.work_dir.
  3. Faz o parsing da saída (texto ou JSON) para extrair vulnerabilidades.
  4. Normaliza cada vulnerabilidade em um objeto Finding.
"""

from __future__ import annotations

import subprocess
import logging
from abc import ABC, abstractmethod
from pathlib import Path

from core.finding import Finding

log = logging.getLogger("vulnscan.modules")


class BaseScanModule(ABC):
    name: str = "base"

    def __init__(self, target: str, settings: dict, work_dir: Path):
        self.target = target
        self.settings = settings
        self.work_dir = work_dir

    @abstractmethod
    def run(self) -> list[Finding]:
        """Executa a varredura e retorna uma lista de Findings normalizados."""
        raise NotImplementedError

    def _run_cli(self, cmd: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
        """
        Helper para invocar uma ferramenta externa via CLI dentro do container.
        Salva stdout/stderr em arquivos para auditoria/depuração.
        """
        log.debug("Executando: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        (self.work_dir / "stdout.log").write_text(result.stdout or "", encoding="utf-8")
        (self.work_dir / "stderr.log").write_text(result.stderr or "", encoding="utf-8")

        if result.returncode != 0:
            log.warning("Comando '%s' retornou código %d (ver stderr.log)", cmd[0], result.returncode)

        return result
