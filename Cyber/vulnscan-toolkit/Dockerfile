# VulnScan Toolkit - imagem conteinerizada
# Base Debian slim: instala as ferramentas ofensivas via apt/pip/go, isolando
# tudo do host (evita conflito de libs com o Kali/ambiente local).

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/go/bin:${PATH}"

# --- Dependências de sistema + libs do WeasyPrint (renderização PDF) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nikto sqlmap \
        golang-go git curl wget ca-certificates \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev \
        shared-mime-info fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# --- Nuclei (ProjectDiscovery) via go install ---
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates || true

# --- OWASP ZAP baseline script (zap-baseline.py) ---
# Baixa o pacote "stable" do ZAP e expõe o wrapper de baseline scan
RUN mkdir -p /opt/zap && \
    curl -fsSL -o /tmp/zap.tar.gz \
        https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2.16.1_Linux.tar.gz && \
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
