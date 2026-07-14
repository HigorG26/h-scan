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

# --- Cliente Docker (CLI apenas, sem daemon) para Docker-outside-of-Docker ---
# Desde a v2.15, o zap-baseline.py deixou de ser distribuído no pacote desktop
# do ZAP (.tar.gz) - ele só existe dentro da imagem oficial do ZAP
# (ghcr.io/zaproxy/zaproxy:stable). Tentar reempacotar isso à mão é frágil e
# quebra a cada release. A forma correta e oficialmente documentada é rodar o
# baseline scan disparando a imagem oficial como um container-irmão, via socket
# do Docker montado (ver módulo xss.py e as instruções de execução no README).
RUN DEB_ARCH="$(dpkg --print-architecture)" && \
    case "$DEB_ARCH" in \
        amd64) DOCKER_ARCH="x86_64" ;; \
        arm64) DOCKER_ARCH="aarch64" ;; \
        armhf) DOCKER_ARCH="armhf" ;; \
        *) DOCKER_ARCH="x86_64" ;; \
    esac && \
    DOCKER_VER="29.6.1" && \
    curl -fsSL -o /tmp/docker.tgz \
        "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_VER}.tgz" && \
    tar -xzf /tmp/docker.tgz -C /tmp && \
    mv /tmp/docker/docker /usr/local/bin/docker && \
    chmod +x /usr/local/bin/docker && \
    rm -rf /tmp/docker.tgz /tmp/docker

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY src/ ./src
COPY config/ ./config

WORKDIR /app/src

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
