"""
ScopeGuard - trava de segurança/legalidade.

Antes de qualquer módulo ser executado, o alvo precisa bater com uma entrada
da allowlist definida em config/scope.yaml. Isso evita o uso indevido da
ferramenta contra alvos não autorizados (requisito de qualquer ferramenta
ofensiva usada em ambiente corporativo).
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from urllib.parse import urlparse

import yaml

log = logging.getLogger("vulnscan.scope_guard")


class ScopeGuard:
    def __init__(self, scope_file: str | Path):
        self.scope_file = Path(scope_file)
        self.allowed_patterns: list[str] = self._load()

    def _load(self) -> list[str]:
        if not self.scope_file.exists():
            log.warning("Arquivo de escopo não encontrado: %s (nenhum alvo autorizado)", self.scope_file)
            return []
        data = yaml.safe_load(self.scope_file.read_text(encoding="utf-8")) or {}
        return data.get("allowed_hosts", [])

    def is_authorized(self, target_url: str) -> bool:
        host = urlparse(target_url).hostname or ""
        for pattern in self.allowed_patterns:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False
