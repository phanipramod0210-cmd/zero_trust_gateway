"""POC-03 Zero-Trust Gateway — Config, Exceptions, Schemas, Main App, Routes"""

# ─── app/core/config.py ───────────────────────────────────────────────────────
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://zt_user:zt_pass@postgres:5432/zt_db"
    REDIS_URL: str = "redis://:zt_redis_pass@redis:6379/0"
    ANTHROPIC_API_KEY: str = ""
    LLM_MODEL: str = "claude-3-5-sonnet-20241022"
    LLM_PROXY_TIMEOUT: int = 45
    API_RATE_LIMIT: str = "30/minute"
    SESSION_TOKEN_TTL_SECONDS: int = 3600
    MAX_PROMPT_CHARS: int = 50_000
    ALLOWED_ORIGINS: list = ["*"]
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()
