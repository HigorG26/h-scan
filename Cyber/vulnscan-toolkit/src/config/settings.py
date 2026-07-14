"""
Carregamento de configurações da ferramenta (config/settings.yaml + .env).

Mantém timeouts, níveis de agressividade (sqli_level/risk), e outros
parâmetros ajustáveis sem precisar mexer no código dos módulos.
"""

from __future__ import annotations

from pathlib import Path

import yaml

DEFAULTS = {
    "sqli_level": 2,
    "sqli_risk": 1,
    "sqli_timeout": 1800,
    "xss_timeout": 1200,
    "xxe_timeout": 900,
    "recon_timeout": 600,
    "zap_spider_minutes": 2,
    "report_company_name": "CIESC",
    "report_author": "Higor Silva",
}

SETTINGS_FILE = Path("./config/settings.yaml")


def load_settings() -> dict:
    settings = DEFAULTS.copy()
    if SETTINGS_FILE.exists():
        user_cfg = yaml.safe_load(SETTINGS_FILE.read_text(encoding="utf-8")) or {}
        settings.update(user_cfg)
    return settings
