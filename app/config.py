from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://containerguard:containerguard@postgres:5432/containerguard"
    redis_url: str = "redis://redis:6379/0"
    api_key: str = "change-me-in-production"
    trivy_timeout_seconds: int = 300
    fail_on_severity: str = "CRITICAL"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
