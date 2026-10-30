import os
import secrets
from functools import cached_property
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Settings(BaseSettings):
    """Environment-driven application settings."""

    model_config = SettingsConfigDict(
        env_file=os.path.join(_BACKEND_DIR, ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    PROJECT_NAME: str = "SOC Agent (RAG + SOP Tools)"
    API_V1_STR: str = "/api/v1"
    VERSION: str = "1.0.0"

    # --- Security -----------------------------------------------------------
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # --- CORS ---------------------------------------------------------------
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # --- LLM provider -------------------------------------------------------
    LLM_PROVIDER: str = "auto"  # auto | openai | nim | none
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    NVIDIA_API_KEY: str = ""
    NIM_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NIM_MODEL: str = "meta/muse-glimmer-30b"
    LLM_TIMEOUT_SECONDS: float = 25.0

    # --- RAG / embeddings ---------------------------------------------------
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    EMBEDDING_CACHE_DIR: str = os.path.join(_BACKEND_DIR, "data", "huggingface")
    RETRIEVAL_TOP_K: int = 4

    # --- Database -----------------------------------------------------------
    DATABASE_URL: str = ""  # empty => SQLite at backend/data/soc.db

    # --- Storage paths ------------------------------------------------------
    BASE_DIR: str = _BACKEND_DIR
    DATA_DIR: str = os.path.join(BASE_DIR, "data")
    SOPS_DIR: str = os.path.join(DATA_DIR, "sops")
    FAISS_INDEX_FILE: str = os.path.join(DATA_DIR, "faiss.index")

    # --- Seed demo accounts -------------------------------------------------
    SEED_ADMIN_PASSWORD: str = "adminpassword123"
    SEED_ANALYST_PASSWORD: str = "socpassword123"

    # --- Threat Map & Geolocation -------------------------------------------
    GEOIP_DB_PATH: str = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")
    GEOIP_ASN_DB_PATH: str = os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb")
    ENABLE_ONLINE_GEOIP: bool = False
    DEMO_GEO_OVERRIDES_FILE: str = os.path.join(DATA_DIR, "demo_geo_overrides.json")
    DEFAULT_HOME_LAT: float = 37.7749
    DEFAULT_HOME_LON: float = -122.4194
    DEFAULT_HOME_LABEL: str = "SOC Operations Center (Primary HQ)"
    # --- Critical Alert Email Notifications (SMTP) ---------------------------
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "vamshipdas@gmail.com"
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "vamshipdas@gmail.com"
    ALERT_EMAIL_TO: str = "vamshipdas@gmail.com"
    ALERT_EMAIL_ENABLED: bool = True
    ALERT_MIN_SEVERITY: str = "high"
    ALERT_COOLDOWN_SECONDS: int = 300
    DASHBOARD_BASE_URL: str = "http://localhost:5173"

    @cached_property
    def effective_secret_key(self) -> str:
        if self.SECRET_KEY.strip():
            return self.SECRET_KEY
        return secrets.token_urlsafe(48)

    @cached_property
    def effective_database_url(self) -> str:
        if self.DATABASE_URL.strip():
            return self.DATABASE_URL
        return "sqlite:///" + os.path.join(self.DATA_DIR, "soc.db").replace("\\", "/")


settings = Settings()
os.makedirs(settings.DATA_DIR, exist_ok=True)
os.makedirs(settings.SOPS_DIR, exist_ok=True)
os.makedirs(settings.EMBEDDING_CACHE_DIR, exist_ok=True)
