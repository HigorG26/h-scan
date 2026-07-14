# VulnScan Toolkit

Orquestrador modular de varredura de vulnerabilidades web, conteinerizado, que integra ferramentas open-source consolidadas (sqlmap, OWASP ZAP, Nikto, Nuclei) e consolida os resultados em um relatório profissional (HTML/PDF) com sumário executivo, criticidade CVSS, detalhes técnicos e recomendações de mitigação.

> **Uso ético:** execute apenas contra alvos autorizados. A ferramenta possui uma trava de escopo (`config/scope.yaml`) que bloqueia varreduras contra hosts fora da allowlist, e exige a flag `--i-have-authorization`.

## 1. Arquitetura e Stack

**Linguagem:** Python 3.11+ — ecossistema maduro para orquestração de subprocessos, parsing e geração de relatórios, além de ser a linguagem nativa da maioria das ferramentas ofensivas (sqlmap, ZAP scripts, nuclei tem bindings/CLI fácil de invocar).

**Bibliotecas principais:**

| Biblioteca | Uso |
|---|---|
| `PyYAML` | Configuração (scope.yaml, settings.yaml, modules.yaml) |
| `Jinja2` | Templating do relatório HTML |
| `WeasyPrint` | Conversão HTML → PDF sem dependência externa de binário (wkhtmltopdf) |
| `requests` | Chamadas HTTP auxiliares (ex: ZAP API, webhooks) |
| `argparse` | CLI (evolui para `Typer`/`Click` se a CLI crescer) |
| `subprocess` (stdlib) | Invocação das ferramentas externas |
| `dataclasses`/`enum` (stdlib) | Modelo normalizado `Finding` |

**Containerização:** Dockerfile único baseado em `debian:bookworm-slim`, instalando sqlmap, Nikto (via apt), Nuclei (via `go install`) e OWASP ZAP baseline (binário oficial). Isso isola completamente as dependências do host — não conflita com as ferramentas já instaladas no Kali. `docker-compose.yml` facilita build/run e persiste `./reports` como volume.

**Por que essa arquitetura:** o núcleo (orquestrador + modelo `Finding` + motor de relatório) é 100% desacoplado das ferramentas externas. Cada módulo é um adaptador fino que traduz a saída de uma ferramenta (texto, JSON, JSONL) para o formato `Finding`. Trocar ou adicionar uma ferramenta não exige tocar no orquestrador nem no relatório.

## 2. Módulos de Varredura

| Módulo | Vulnerabilidade | Ferramenta OSS integrada | Forma de integração |
|---|---|---|---|
| `recon` | Levantamento geral / misconfig | Nikto | CLI, saída `-Format json` |
| `sqli` | SQL Injection | sqlmap | CLI `--batch`, parsing de stdout (evolução: API REST do sqlmap) |
| `xss` | Cross-Site Scripting (Reflected/Stored/DOM) | OWASP ZAP (baseline scan) | CLI `zap-baseline.py -J`, parsing do JSON de alertas |
| `xxe` | XML External Entity | Nuclei (templates tag `xxe`) | CLI `-jsonl`, parsing linha a linha |

Todos herdam de `BaseScanModule` (`src/modules/base.py`) e retornam `list[Finding]`. Novo módulo = nova classe + registro em `src/modules/registry.py`. Profiles (`quick`, `full`, `custom`) definem quais módulos rodam por padrão; `--modules` permite escolha explícita.

## 3. Motor de Relatórios

- `core/finding.py`: modelo normalizado (`Finding` + enum `Severity`) — contrato único entre módulos e relatório.
- `report/generator.py`: agrega estatísticas (contagem por severidade, CVSS médio, módulos executados), ordena achados por criticidade, renderiza `report/templates/report.html.j2` via Jinja2.
- Template HTML contém as 4 seções pedidas: Sumário Executivo, Nível de Criticidade (cards visuais por severidade), Detalhes Técnicos (endpoint, parâmetro, payload/evidência, CVSS) e Recomendações de Mitigação (por achado + seção geral).
- Exportação dupla: HTML sempre gerado; PDF via WeasyPrint (renderiza o mesmo HTML/CSS, sem precisar de binário externo tipo wkhtmltopdf).

## 4. Roadmap de Desenvolvimento (Sprints)

**Sprint 0 — Núcleo (pronto para começar agora)**
Estrutura de diretórios, `main.py`, `ScopeGuard`, `Finding`, `ScanOrchestrator`, `ReportGenerator` com template básico. *Critério de teste: rodar `--profile quick` contra um alvo de laboratório e obter um relatório HTML, mesmo que sem achados reais ainda (mock).*

**Sprint 1 — Módulo Recon + Relatório funcional**
Integrar Nikto de ponta a ponta, validar parsing real, refinar template (badges, tabela). *Teste: scan contra DVWA/juice-shop local gera relatório com achados de recon.*

**Sprint 2 — Módulo SQLi (sqlmap)**
Integração completa, parsing robusto (migrar para leitura de `--output-dir` estruturado em vez de regex em stdout). *Teste: DVWA com SQLi conhecida é detectada e aparece como Crítica no relatório.*

**Sprint 3 — Módulo XSS (OWASP ZAP)**
Subir ZAP em modo baseline dentro do container, parsing de alertas, mapeamento de risco ZAP → CVSS. *Teste: OWASP Juice Shop detecta XSS refletido.*

**Sprint 4 — Módulo XXE (Nuclei)**
Integração com templates `xxe`, tratamento de falso-positivo/timeout. *Teste: endpoint vulnerável a XXE (ex: WebGoat) é sinalizado.*

**Sprint 5 — Hardening e Usabilidade**
Paralelização dos módulos (asyncio/threading), progress bar, logs estruturados (JSON), tratamento de erros por módulo sem derrubar o scan, testes unitários (`pytest`) para parsers.

**Sprint 6 — Relatório "nível empresa" + Apresentação**
Refinar CSS do relatório (logo, cores da marca), adicionar gráfico de distribuição de severidade (ex: matplotlib embutido como imagem), exportar também um resumo em Markdown para stakeholders não técnicos, preparar demo para o projeto de inovação.

## Estrutura de Diretórios

```
vulnscan-toolkit/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── config/
│   ├── scope.yaml          # allowlist de alvos autorizados
│   ├── settings.yaml       # timeouts e parâmetros ajustáveis
│   └── modules.yaml        # (futuro) definição de profile "custom"
├── reports/                # saída dos scans (1 subpasta por run_id)
├── wordlists/              # payloads/dicionários customizados
├── tests/                  # testes unitários (pytest)
├── docs/                   # documentação técnica adicional
└── src/
    ├── main.py              # CLI / entrypoint
    ├── core/
    │   ├── finding.py        # modelo normalizado de achado
    │   ├── scope_guard.py    # trava de autorização de alvo
    │   └── orchestrator.py   # executa os módulos selecionados
    ├── modules/
    │   ├── base.py           # classe abstrata BaseScanModule
    │   ├── registry.py       # registro de módulos + profiles
    │   ├── recon.py          # Nikto
    │   ├── sqli.py           # sqlmap
    │   ├── xss.py            # OWASP ZAP baseline
    │   └── xxe.py            # Nuclei (tag xxe)
    ├── report/
    │   ├── generator.py      # motor de relatórios
    │   └── templates/
    │       └── report.html.j2
    └── config/
        └── settings.py       # loader de config
```

## Como rodar (MVP)

```bash
docker compose build

docker compose run --rm vulnscan \
  --target https://app-teste.local \
  --profile full \
  --format both \
  --i-have-authorization
```

Relatórios finais em `./reports/<run_id>/relatorio.html` e `relatorio.pdf`.
