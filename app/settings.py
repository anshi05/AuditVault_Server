# app/settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
class Settings(BaseSettings):
    RPC_URL: str
    CONTRACT_ADDRESS: str
    CHAIN_ID: int = 31337
    ADMIN_PK: str
    SUBMITTER_PK: str
    INSPECTOR_PK: str | None = None

    PINATA_JWT: str | None = None
    PINATA_API_KEY: str | None = None
    PINATA_API_SECRET: str | None = None

    DATABASE_URL: str = "sqlite:///./data.db"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    AUTO_REVOKE_DAYS_BEFORE: int = 7

    ALLOW_ORIGINS: list[str] = ["*"]
    ALLOW_CREDENTIALS: bool = True
    ALLOW_METHODS: list[str] = ["*"]
    ALLOW_HEADERS: list[str] = ["*"]

    class Config:
        env_file = ".env"

settings = Settings()
