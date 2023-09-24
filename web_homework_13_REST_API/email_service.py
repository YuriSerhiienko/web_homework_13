from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
from decouple import config

conf = ConnectionConfig(
    MAIL_USERNAME=config("SMTP_USERNAME"),
    MAIL_PASSWORD=config("SMTP_PASSWORD"),
    MAIL_FROM=config("SMTP_USERNAME"),
    MAIL_PORT=int(config("SMTP_PORT")),
    MAIL_SERVER=config("SMTP_SERVER"),
    MAIL_FROM_NAME="Your Application Name",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)


async def send_verification_email(email: EmailStr, token: str):
    message = MessageSchema(
        subtype="plain",
        subject="Email Verification",
        recipients=[email],
        body=f"Your token: {token}",
    )
    fm = FastMail(conf)
    await fm.send_message(message)


async def send_reset_password_email(email: EmailStr, token: str):
    message = MessageSchema(
        subtype="plain",
        subject="Reset Password",
        recipients=[email],
        body=f"Your token: {token}",
    )
    fm = FastMail(conf)
    await fm.send_message(message)
