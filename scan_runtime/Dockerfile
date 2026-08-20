FROM python:3.12-slim-bookworm

ARG TARGETARCH
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    tar \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY pinned_versions.json /tmp/pinned_versions.json
COPY pinned_download.py /tmp/pinned_download.py
COPY install_tools.sh /tmp/install_tools.sh
RUN chmod +x /tmp/install_tools.sh && /tmp/install_tools.sh "$TARGETARCH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && test -x /usr/local/bin/pd-httpx
COPY . .

RUN groupadd --gid 1000 scanner \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/scanner --shell /usr/sbin/nologin scanner \
    && mkdir -p /data /home/scanner/.config /home/scanner/.dit /home/scanner/nuclei-templates \
    && if [ -d /root/.config/nuclei ]; then cp -a /root/.config/nuclei /home/scanner/.config/nuclei; fi \
    && if [ -d /root/.dit ]; then cp -a /root/.dit/. /home/scanner/.dit/; fi \
    && chown -R scanner:scanner /home/scanner /data /app

USER 1000:1000
ENV HOME=/home/scanner
ENV XDG_CONFIG_HOME=/home/scanner/.config
ENV AGENT_DATA_DIR=/data

CMD ["python", "agent_main.py"]
