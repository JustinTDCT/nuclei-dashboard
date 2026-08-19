from app.config import settings
from app.models import Agent


def agent_compose(agent: Agent, central_url: str, include_secret: bool = True) -> str:
    secret_line = ""
    if include_secret and agent.enrollment_secret:
        secret_line = f"      ENROLLMENT_SECRET: {agent.enrollment_secret}\n"
    return f"""# Site agent for {agent.name} ({agent.uuid})
# On the LAN host (outbound HTTPS to GitHub and {central_url}):
#   docker compose --env-file agent.env up -d --build
# Docker clones scan_runtime from the public repo and builds the image.
# Scanner tool versions are pinned in scan_runtime/pinned_versions.json at image build.
# After we push agent changes: docker compose up -d --build
# This image includes an independent heartbeat/control loop. Rebuild after
# control-plane changes; a container restart is not enough.
# Linux sites should keep network_mode: host so LAN subnets are reachable.
#
# TLS verification is on by default (TLS_VERIFY=1).
# Publicly trusted certificates: no extra files.
# Internal CA: copy the CA PEM to ./agent-certs/ca.pem next to this file, then set
#   TLS_CA_FILE=/certs/ca.pem
# in agent.env. The ./agent-certs directory is mounted into the container at /certs.
# Lab opt-out only: TLS_VERIFY=0

services:
  nuclei-agent:
    image: {settings.agent_image}
    pull_policy: build
    build:
      context: {settings.agent_git_context}
    command: ["python", "agent_main.py"]
    restart: unless-stopped
    network_mode: host
    environment:
      CENTRAL_URL: {central_url}
      AGENT_UUID: {agent.uuid}
{secret_line}      TLS_VERIFY: "${{TLS_VERIFY:-1}}"
      TLS_CA_FILE: ${{TLS_CA_FILE:-}}
      SCAN_DRY_RUN: "0"
    volumes:
      - agent-keys:/data
      - nuclei-templates:/root/nuclei-templates
      - ${{TLS_CA_HOST_DIR:-./agent-certs}}:/certs:ro

volumes:
  agent-keys:
  nuclei-templates:
"""


def agent_env(agent: Agent, central_url: str, include_secret: bool = True) -> str:
    lines = [
        f"CENTRAL_URL={central_url}",
        f"AGENT_UUID={agent.uuid}",
    ]
    if include_secret and agent.enrollment_secret:
        lines.append(f"ENROLLMENT_SECRET={agent.enrollment_secret}")
    lines.append(f"TLS_VERIFY={settings.agent_tls_verify}")
    lines.append("# Optional internal CA. Copy the PEM to ./agent-certs/ca.pem, then:")
    lines.append("# TLS_CA_FILE=/certs/ca.pem")
    return "\n".join(lines) + "\n"
