FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Actualizar e instalar tools de pentest
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    gobuster \
    enum4linux \
    smbclient \
    netcat-openbsd \
    curl \
    wget \
    python3 \
    python3-pip \
    nuclei \
    tmux \
    net-tools \
    iputils-ping \
    dnsutils \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Wordlists básicas
RUN apt-get update && apt-get install -y wordlists \
    && gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true \
    && apt-get clean

WORKDIR /workspace

CMD ["tail", "-f", "/dev/null"]
