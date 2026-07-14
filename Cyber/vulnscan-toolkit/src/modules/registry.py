"""
Registro de módulos + resolução de profiles.

Adicionar um novo módulo = criar a classe em src/modules/<nome>.py e
registrá-la aqui. Nada mais no orquestrador precisa mudar.
"""

from __future__ import annotations

from modules.sqli import SqliModule
from modules.xss import XssModule
from modules.xxe import XxeModule
from modules.recon import ReconModule

MODULE_REGISTRY = {
    "recon": ReconModule,
    "sqli": SqliModule,
    "xss": XssModule,
    "xxe": XxeModule,
}

# Profiles pré-definidos (usados quando --modules não é passado)
PROFILES = {
    "quick": ["recon", "xss"],
    "full": ["recon", "sqli", "xss", "xxe"],
}


def resolve_profile(profile: str) -> list[str]:
    if profile == "custom":
        # No modo custom, espera-se que --modules tenha sido usado.
        # Se não foi, cai para 'quick' como fallback seguro.
        return PROFILES["quick"]
    return PROFILES.get(profile, PROFILES["quick"])
