"""Application configuration."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Development mode (bypasses OAuth)
    dev_mode: bool = True

    # Database
    database_url: str = "postgresql+asyncpg://cryptoserve:localdev@localhost:5432/cryptoserve"

    # GitHub OAuth
    github_client_id: str = ""
    github_client_secret: str = ""

    # Security
    cryptoserve_master_key: str = "dev-master-key-change-in-production"
    jwt_secret_key: str = "dev-jwt-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_days: int = 7

    # URLs
    frontend_url: str = "http://localhost:3003"
    backend_url: str = "http://localhost:8003"

    # Identity defaults
    default_identity_expiration_days: int = 90

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
