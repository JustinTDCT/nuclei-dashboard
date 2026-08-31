from app.agent_source import assert_immutable_agent_git_context, assert_immutable_agent_image
from app.config import settings
from app.models import Agent


def agent_compose(agent: Agent, central_url: str, include_secret: bool = True) -> str:
    git_context = assert_immutable_agent_git_context(settings.agent_git_context)
    image = assert_immutable_agent_image(settings.agent_image)
    secret_line = ""
    if include_secret and agent.enrollment_secret:
        secret_line = f"      ENROLLMENT_SECRET: {agent.enrollment_secret}\n"
    return f"""# Site agent for {agent.name} ({agent.uuid})
# On the LAN host (outbound HTTPS to GitHub and {central_url}):
#   docker compose --env-file agent.env up -d --build
# Docker clones scan_runtime from an immutable 40-character commit and builds the image.
# Scanner tool versions and SHA-256 checksums are pinned in scan_runtime/pinned_versions.json.
# After we push agent changes: bump AGENT_GIT_CONTEXT to that commit, then:
#   docker compose up -d --build
# This image includes an independent heartbeat/control loop. Rebuild after
# control-plane changes; a container restart is not enough.
#
# Privilege / networking:
# network_mode: host is required so site RFC1918 subnets are reachable.
# The process runs as uid 1000. Capabilities are dropped and only NET_RAW is
# added because Naabu SYN and host-discovery need raw sockets. Do not add
# privileged: true. The WAN scanner stays on the Docker bridge with the same
# user/capability set. security_opt no-new-privileges blocks further
# privilege escalation after start.
#
# TLS verification is on by default (TLS_VERIFY=1).
# Publicly trusted certificates: no extra files.
# Internal CA: copy the CA PEM to ./agent-certs/ca.pem next to this file, then set
#   TLS_CA_FILE=/certs/ca.pem
# in agent.env. The ./agent-certs directory is mounted into the container at /certs.
# Lab opt-out only: TLS_VERIFY=0

services:
  nuclei-agent:
    image: {image}
    pull_policy: build
    build:
      context: {git_context}
    command: ["python", "agent_main.py"]
    restart: unless-stopped
    network_mode: host
    user: "1000:1000"
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
    security_opt:
      - no-new-privileges:true
    environment:
      CENTRAL_URL: {central_url}
      AGENT_UUID: {agent.uuid}
{secret_line}      TLS_VERIFY: "${{TLS_VERIFY:-1}}"
      TLS_CA_FILE: ${{TLS_CA_FILE:-}}
      SCAN_DRY_RUN: "0"
      AGENT_DATA_DIR: /data
      HOME: /home/scanner
    volumes:
      - agent-keys:/data
      - nuclei-templates:/home/scanner/nuclei-templates
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
