from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql://nuclei:changeme@localhost:5432/nuclei"
    secret_key: str = "dev-secret-change-me"
    jwt_expire_hours: int = 12
    agent_jwt_expire_minutes: int = 720
    scanner_token: str = "change-this-scanner-token"
    admin_username: str = "admin"
    admin_password: str = "changeme"
    admin_email: str = "admin@localhost"
    public_url: str = "https://10.150.10.155:8118"
    agent_image: str = "nuclei-dashboard-agent:latest"
    agent_tls_verify: str = "0"
    cors_origins: str = "http://localhost:5173,https://localhost:8118,https://10.150.10.155:8118"


settings = Settings()
