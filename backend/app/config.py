from pydantic_settings import BaseSettings, SettingsConfigDict

from app.agent_source import DEFAULT_AGENT_GIT_CONTEXT


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql://nuclei@localhost:5432/nuclei"
    secret_key: str = ""
    jwt_expire_hours: int = 12
    agent_jwt_expire_minutes: int = 720
    scanner_token: str = ""
    admin_username: str = "admin"
    admin_password: str = ""
    admin_email: str = "admin@localhost"
    public_url: str = "https://10.150.10.155:8118"
    agent_image: str = "nuclei-dashboard-agent:latest"
    agent_git_context: str = DEFAULT_AGENT_GIT_CONTEXT
    agent_tls_verify: str = "1"
    cors_origins: str = "http://localhost:5173,https://localhost:8118,https://10.150.10.155:8118"
    nvd_api_key: str = ""
    raw_artifact_dir: str = "/var/lib/nuclei-dashboard/raw-artifacts"
    raw_artifact_max_bytes: int = 268435456
    ingest_max_rows: int = 500
    ingest_max_bytes: int = 1048576
    settings_encryption_key: str = ""
    login_failure_limit: int = 5
    login_failure_window_seconds: int = 900
    login_lockout_seconds: int = 900
    login_ip_limit: int = 20
    login_ip_window_seconds: int = 300
    agent_challenge_ttl_seconds: int = 120
    agent_challenge_limit: int = 10
    agent_challenge_ip_limit: int = 30
    agent_challenge_window_seconds: int = 300
    scanner_kill_grace_seconds: int = 5
    scanner_cancel_grace_seconds: int = 90


settings = Settings()
