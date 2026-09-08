"""
Centralized application settings.

All configuration is read from environment variables (via .env in local/dev,
real environment variables in production). Nothing sensitive is ever
hard-coded here — see .env.example for the full list of expected variables.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    app_secret_key: str = "dev-only-not-secure-change-me"
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg2://soc_admin:soc_admin@localhost:5432/soc_workbench"

    redis_url: str = "redis://localhost:6379/0"

    jwt_secret_key: str = "dev-only-jwt-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    auth_single_user_mode: bool = True

    llm_provider: Literal["mock", "openai", "anthropic"] = "mock"
    llm_model: str = "mock-soc-analyst-v1"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    ti_use_live_providers: bool = False
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    ti_cache_ttl_seconds: int = 3600
    ti_rate_limit_per_minute: int = 4

    backend_webhook_token: str = "dev-only-webhook-token"

    # Off by default (mirrors ti_use_live_providers): every AI-initiated
    # external tool call (GitHub PR creation, secret-provider revocation) is
    # simulated by services.mcp_gateway unless this is explicitly enabled
    # AND a matching, enabled Integration + credential env var exist.
    external_tools_live_mode: bool = False

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
