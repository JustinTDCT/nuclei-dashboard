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

CMD ["python", "agent_main.py"]
