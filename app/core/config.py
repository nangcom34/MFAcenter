from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    PROJECT_NAME: str = "DLD-MFAcenter Gateway"
    SECRET_KEY: str = Field(default="SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION_32_CHARS")
    ENCRYPTION_KEY: str = Field(default="32_BYTE_ENCRYPTION_KEY_FOR_TOTP")
    
    # Database Settings
    DATABASE_URL: str = Field(default="postgresql+asyncpg://postgres:postgres@db:5432/dld_mfa")
    
    # Redis Settings
    REDIS_URL: str = Field(default="redis://redis:6379/0")
    
    # Session Config
    SESSION_COOKIE_NAME: str = "dld_mfa_session"
    SESSION_TTL_SECONDS: int = 28800  # 8 Hours
    
    # Rate Limiting Config
    RATE_LIMIT_MAX_ATTEMPTS: int = 10
    RATE_LIMIT_WINDOW_SECONDS: int = 900  # 15 Minutes
    RATE_LIMIT_LOCKOUT_SECONDS: int = 300  # 5 Minutes
    
    # Domain Config
    MANAGEMENT_DOMAIN: str = "mfa.dld.go.th"
    
    class Config:
        env_file = ".env"

settings = Settings()