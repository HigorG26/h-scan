# VulnScan Toolkit - imagem conteinerizada
# Base Debian slim: instala as ferramentas ofensivas via apt/pip/go, isolando
# tudo do host (evita conflito de libs com o Kali/ambiente local).

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/go/bin:${PATH}"

# --- Dependências de sistema + libs do WeasyPrint (renderização PDF) ---
# Nota: o pacote "nikto" foi removido dos repositórios do Debian (bookworm em diante),
# por isso é instalado via git clone logo abaixo, junto com perl (sua única dependência real).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        perl sqlmap \
        golang-go git curl wget ca-certificates \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev \
        shared-mime-info fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# --- Nikto via git clone (não está mais nos repositórios apt do Debian) ---
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# --- Nuclei (ProjectDiscovery) via go install ---
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates || true

# --- OWASP ZAP baseline script (zap-baseline.py) ---
# Resolve dinamicamente a URL do asset "*_Linux.tar.gz" do release mais recente via
# GitHub API (evita fixar um número de versão, que quebra a cada novo release do ZAP).
# Se a API falhar (ex: rate limit sem autenticação), cai para uma versão conhecida como fallback.
RUN mkdir -p /opt/zap && \
    ZAP_FALLBACK_URL="https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz" && \
    ZAP_URL=$(curl -fsSL -A "Mozilla/5.0" https://api.github.com/repos/zaproxy/zaproxy/releases/latest \
        | grep -o '"browser_download_url":[[:space:]]*"[^"]*_Linux\.tar\.gz"' \
        | head -n1 | sed -E 's/.*"(https[^"]+)"/\1/'); \
    if [ -z "$ZAP_URL" ]; then ZAP_URL="$ZAP_FALLBACK_URL"; fi && \
    echo "Baixando ZAP de: ${ZAP_URL}" && \
    curl -fsSL -o /tmp/zap.tar.gz "${ZAP_URL}" && \
    tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 && \
    rm /tmp/zap.tar.gz && \
    ln -s /opt/zap/zap-baseline.py /usr/local/bin/zap-baseline.py && \
    chmod +x /usr/local/bin/zap-baseline.py

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY src/ ./src
COPY config/ ./config

WORKDIR /app/src

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
