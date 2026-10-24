import os
from datetime import timedelta

from dotenv import load_dotenv
from sqlalchemy import URL

load_dotenv()


def env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")
    SECRET_KEY = os.getenv("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or URL.create(
        "mysql+pymysql", username=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 64 * 1024
    ALLOW_REGISTRATION = env_flag("ALLOW_REGISTRATION", False)

    JWT_SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

    # The JWT is stored in an HttpOnly cookie instead of localStorage.
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ACCESS_COOKIE_NAME = "sentinelx_access"
    JWT_ACCESS_COOKIE_PATH = "/api/"
    JWT_ACCESS_CSRF_COOKIE_NAME = "sentinelx_csrf"
    JWT_ACCESS_CSRF_COOKIE_PATH = "/"
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_COOKIE_SECURE = env_flag("JWT_COOKIE_SECURE", False)
    JWT_SESSION_COOKIE = True

    RESET_TTL_SECONDS = int(os.getenv("RESET_TTL_SECONDS", "900"))
    PUBLIC_APP_URL = os.getenv("PUBLIC_APP_URL", "http://localhost:8088")
    MAIL_HOST = os.getenv("MAIL_HOST", "")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_FROM = os.getenv("MAIL_FROM", "")
    MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "SentinelX Security")
    MAIL_USE_TLS = env_flag("MAIL_USE_TLS", True)
    MAIL_USE_SSL = env_flag("MAIL_USE_SSL", False)
