from __future__ import annotations

from pathlib import Path

from app.compose_gen import agent_compose, agent_env
from app.config import Settings
from app.models import Agent

ROOT = Path(__file__).resolve().parents[2]


def test_settings_tls_verify_default_is_on():
    assert Settings.model_fields["agent_tls_verify"].default == "1"


def test_generated_agent_config_verifies_tls_by_default(monkeypatch):
    from app import compose_gen

    monkeypatch.setattr(compose_gen.settings, "agent_tls_verify", "1")
    agent = Agent(
        id=1,
        tenant_id=1,
        name="Edge",
        uuid="11111111-2222-3333-4444-555555555555",
        enrollment_secret="secret-value",
        status="pending_enrollment",
    )
    compose = agent_compose(agent, "https://dashboard.example.com:8118")
    env = agent_env(agent, "https://dashboard.example.com:8118")
    assert 'TLS_VERIFY: "1"' in compose
    assert "TLS_VERIFY=1" in env
    assert "ENROLLMENT_SECRET: secret-value" in compose
    assert "ENROLLMENT_SECRET=secret-value" in env


def test_generated_env_can_omit_enrollment_secret(monkeypatch):
    from app import compose_gen

    monkeypatch.setattr(compose_gen.settings, "agent_tls_verify", "1")
    agent = Agent(
        id=2,
        tenant_id=1,
        name="Edge",
        uuid="11111111-2222-3333-4444-555555555555",
        enrollment_secret="secret-value",
        status="pending_enrollment",
    )
    compose = agent_compose(agent, "https://dashboard.example.com:8118", include_secret=False)
    env = agent_env(agent, "https://dashboard.example.com:8118", include_secret=False)
    assert "ENROLLMENT_SECRET" not in compose
    assert "ENROLLMENT_SECRET" not in env


def test_compose_files_default_tls_verify_on():
    root_compose = (ROOT / "docker-compose.yml").read_text()
    agent_compose_file = (ROOT / "agent" / "docker-compose.yml").read_text()
    template = (ROOT / "agent" / "docker-compose.template.yml").read_text()
    example = (ROOT / ".env.example").read_text()
    assert "AGENT_TLS_VERIFY:-1" in root_compose
    assert "AGENT_TLS_VERIFY:-0" not in root_compose
    assert "TLS_VERIFY:-1" in agent_compose_file
    assert "TLS_VERIFY:-0" not in agent_compose_file
    assert 'TLS_VERIFY: "1"' in template
    assert 'TLS_VERIFY: "0"' not in template
    assert "AGENT_TLS_VERIFY=1" in example


def test_agent_client_tls_verify_default_and_opt_out(monkeypatch):
    import sys

    runtime = str(ROOT / "scan_runtime")
    if runtime not in sys.path:
        sys.path.insert(0, runtime)
    import api_client

    monkeypatch.delenv("TLS_VERIFY", raising=False)
    monkeypatch.delenv("TLS_CA_FILE", raising=False)
    assert api_client._tls_verify() is True

    monkeypatch.setenv("TLS_VERIFY", "0")
    assert api_client._tls_verify() is False

    monkeypatch.setenv("TLS_VERIFY", "1")
    assert api_client._tls_verify() is True

    monkeypatch.setenv("TLS_VERIFY", "/etc/ssl/internal-ca.pem")
    assert api_client._tls_verify() == "/etc/ssl/internal-ca.pem"

    monkeypatch.setenv("TLS_VERIFY", "1")
    monkeypatch.setenv("TLS_CA_FILE", "/tmp/ca.pem")
    assert api_client._tls_verify() == "/tmp/ca.pem"
