"""
ScanOrchestrator - núcleo do sistema.

Responsável por:
  - Resolver quais módulos rodar (a partir do profile ou de --modules).
  - Executar cada módulo (sequencial no MVP; paralelo/async na v2).
  - Agregar todos os Findings retornados em uma lista única.
  - Persistir a saída bruta (stdout/JSON) de cada ferramenta em run_dir,
    para rastreabilidade/auditoria.

Módulos são plugins: qualquer classe em src/modules que herde de
BaseScanModule e se registre em MODULE_REGISTRY é automaticamente
disponibilizada via --modules.
"""

from __future__ import annotations

import logging
from pathlib import Path

from modules.registry import MODULE_REGISTRY, resolve_profile
from core.finding import Finding

log = logging.getLogger("vulnscan.orchestrator")


class ScanOrchestrator:
    def __init__(
        self,
        target: str,
        profile: str,
        modules_override: list[str] | None,
        settings: dict,
        run_dir: Path,
    ):
        self.target = target
        self.profile = profile
        self.modules_override = modules_override
        self.settings = settings
        self.run_dir = run_dir

    def _resolve_modules(self) -> list[str]:
        if self.modules_override:
            return self.modules_override
        return resolve_profile(self.profile)

    def run(self) -> list[Finding]:
        module_names = self._resolve_modules()
        log.info("Módulos selecionados: %s", ", ".join(module_names))

        all_findings: list[Finding] = []
        for name in module_names:
            module_cls = MODULE_REGISTRY.get(name)
            if module_cls is None:
                log.warning("Módulo desconhecido: %s (ignorado)", name)
                continue

            log.info("→ Executando módulo '%s'...", name)
            module_dir = self.run_dir / name
            module_dir.mkdir(parents=True, exist_ok=True)

            try:
                module = module_cls(target=self.target, settings=self.settings, work_dir=module_dir)
                findings = module.run()
                log.info("  '%s' concluído: %d achado(s)", name, len(findings))
                all_findings.extend(findings)
            except Exception as exc:  # módulo com falha não deve derrubar o scan inteiro
                log.exception("Erro no módulo '%s': %s", name, exc)

        return all_findings
