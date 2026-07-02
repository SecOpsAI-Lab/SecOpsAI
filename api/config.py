import os
from functools import lru_cache

class Settings:
    API_KEY_HEADER: str = "X-API-Key"
    ALLOWED_API_KEYS: set = set(
        os.getenv("ALLOWED_API_KEYS", "dev-sensor-001,dev-sensor-002").split(",")
    )
    RATE_LIMIT_RPM: int = int(os.getenv("RATE_LIMIT_RPM", "100"))
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/ml/xgboost_detector.pkl")
    SCALER_PATH: str = os.getenv("SCALER_PATH", "models/scaler.pkl")
    FEATURE_NAMES_PATH: str = os.getenv("FEATURE_NAMES_PATH", "data/processed/feature_names.json")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LABEL_ONLY_OUTPUT: bool = True

    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "secopsai")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "secopsai_user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "your_password_here")
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))

@lru_cache()
def get_settings() -> Settings:
    return Settings()
