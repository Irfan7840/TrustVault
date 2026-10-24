import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration with secure defaults."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-dev-key-change-in-production-!")
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'trustvault.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload storage configuration
    UPLOAD_FOLDER = BASE_DIR / os.environ.get("UPLOAD_FOLDER", "storage/documents")
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB limit
    ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "png", "jpg", "jpeg", "csv", "md"}
    
    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # CSRF
    WTF_CSRF_ENABLED = os.environ.get("WTF_CSRF_ENABLED", "True").lower() in ("true", "1")
    WTF_CSRF_TIME_LIMIT = 3600


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False  # Allows simpler unit tests; CSRF specific tests will explicitly test CSRF
    UPLOAD_FOLDER = BASE_DIR / "tests" / "test_uploads"
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

    @classmethod
    def validate(cls):
        if not os.environ.get("SECRET_KEY") or os.environ.get("SECRET_KEY") == "fallback-dev-key-change-in-production-!":
            raise ValueError("SECRET_KEY must be securely defined in environment variables for production!")


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
