import os
import jwt

from fastapi import FastAPI, BackgroundTasks, UploadFile, File, Form
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig
from typing import List
from dotenv import load_dotenv
from models import User

load_dotenv('.env')


conf = ConnectionConfig(
    MAIL_USERNAME = os.environ['EMAIL'],
    MAIL_PASSWORD = os.environ['PASSWORD'],
    MAIL_FROM= os.environ['EMAIL'],
    MAIL_PORT = 587,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_TLS = True,
    MAIL_SSL = False,
    USE_CREDENTIALS=True
)


async def send_email(email: List, subject: str, html):
    print(email)
    print(html)
    message = MessageSchema(
        subject="Verify your account",
        recipients=email,  # List of recipients, as many as you can pass 
        body=html,
        subtype="html"
        )

    fm = FastMail(conf)
    await fm.send_message(message)  