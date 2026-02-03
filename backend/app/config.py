import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev")
    DATABASE_URL = os.getenv("DATABASE_URL", "")
    MAIL_TO = os.getenv("MAIL_TO", "admin@rutherglenfb.com.au")

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER)

    # comma-separated
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()] or "*"
    TOTP_ISSUER = os.getenv("TOTP_ISSUER", "Rutherglen Fire Brigade")
