import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from flask import current_app


def send_password_reset_link(recipient, link):
    config = current_app.config
    host = config.get("MAIL_HOST")
    sender = config.get("MAIL_FROM") or config.get("MAIL_USERNAME")
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = "Reset your SentinelX password"
    message["From"] = formataddr((config.get("MAIL_FROM_NAME"), sender))
    message["To"] = recipient
    message.set_content(
        f"Reset your password using this link:\n{link}\n\n"
        f"This link expires in {config.get('RESET_TTL_SECONDS', 900) // 60} minutes. "
        "If you did not request a password reset, ignore this email."
    )

    smtp_class = smtplib.SMTP_SSL if config.get("MAIL_USE_SSL") else smtplib.SMTP
    with smtp_class(host, config["MAIL_PORT"], timeout=10) as server:
        if config.get("MAIL_USE_TLS") and not config.get("MAIL_USE_SSL"):
            server.starttls(context=ssl.create_default_context())
        if config.get("MAIL_USERNAME"):
            server.login(config["MAIL_USERNAME"], config.get("MAIL_PASSWORD", ""))
        server.send_message(message)
