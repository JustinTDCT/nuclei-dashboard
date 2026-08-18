from app.config import settings
from app.models import Agent


def agent_compose(agent: Agent, central_url: str, include_secret: bool = True) -> str:
    secret_line = ""
    if include_secret and agent.enrollment_secret:
        secret_line = f"      ENROLLMENT_SECRET: {agent.enrollment_secret}\n"
    return f"""# Site agent for {agent.name} ({agent.uuid})
# On the LAN host (outbound HTTPS to GitHub and {central_url}):
#   docker compose up -d --build
# Docker clones scan_runtime from the public repo and builds the image.
# After we push agent changes: docker compose up -d --build
# Linux sites should keep network_mode: host so LAN subnets are reachable.

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
{secret_line}      TLS_VERIFY: "{settings.agent_tls_verify}"
      SCAN_DRY_RUN: "0"
    volumes:
      - agent-keys:/data
      - nuclei-templates:/root/nuclei-templates

volumes:
  agent-keys:
  nuclei-templates:
"""


def agent_env(agent: Agent, central_url: str) -> str:
    lines = [
        f"CENTRAL_URL={central_url}",
        f"AGENT_UUID={agent.uuid}",
    ]
    if agent.enrollment_secret:
        lines.append(f"ENROLLMENT_SECRET={agent.enrollment_secret}")
    lines.append(f"TLS_VERIFY={settings.agent_tls_verify}")
    return "\n".join(lines) + "\n"
