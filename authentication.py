import os
import jwt
import json
import base64
import hmac
from fastapi import HTTPException, status

from passlib.context import CryptContext
from dotenv import load_dotenv
from models import User

load_dotenv('.env')

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def get_hashed_password(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def verify_token(token: str):
    try:
        payload = jwt.decode(token, os.environ['SECRET_KEY'], algorithms="HS256")
        user = await User.get(id=payload['id'])
    except jwt.exceptions.DecodeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token, please request a new one"
        ,headers={"WWW-Authenticate": "Bearer"})

    return user


async def token_generator(email: str, password: str):
    user = await User.get(email=email)

    if user and verify_password(password, user.password):
        data = {
            'id': user.id,
            'username': user.name,
        }

        token = jwt.encode(data, os.environ['SECRET_KEY'], algorithm="HS256")

        return token
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials, please try again")


def create_signed_token(key, data):
    """
    Create a complete JWT token. Exclusively uses sha256
    HMAC.
    >>> token = jwt.create_signed_token(b'secret',
    ... {
    ...   'value': 'a value',
    ...   'other': 'This is some other value',
    ...   'verified': True
    ... })
    >>> len(token)
    185
    """
    header = json.dumps({'typ': 'JWT', 'alg': 'HS256'}).encode('utf-8')
    henc = base64.urlsafe_b64encode(header).decode().strip('=')

    payload = json.dumps(data).encode('utf-8')
    penc = base64.urlsafe_b64encode(payload).decode().strip('=')

    hdata = henc + '.' + penc

    d = hmac.new(key, hdata.encode('utf-8'), 'sha256')
    dig = d.digest()
    denc = base64.urlsafe_b64encode(dig).decode().strip('=')

    token = hdata + '.' + denc
    return token


def verify_signed_token(key, token):
    """
    Decodes the payload in the token and returns a tuple
    whose first value is a boolean indicating whether the
    signature on this token was valid, followed by the
    decoded payload.
    >>> token = 'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJIUzI1NiJ9.eyJ2YWx1ZSI6ICJhIHZhbHVlIn0._3VgFmk3sRll_-von0EIC7ty32tcBEeZMc94Qr8htn8'
    >>> jwt.verify_signed_token(b'secret', token)
    (True, {'value': 'a value'})
    """
    (header, payload, sig) = token.split('.')
    hdata = header + '.' + payload

    d = hmac.new(key, hdata.encode('utf-8'), 'sha256')
    dig = d.digest()
    denc = base64.urlsafe_b64encode(dig).decode().strip('=')

    verified = hmac.compare_digest(sig, denc)
    payload += '=' * (-len(payload) % 4)
    payload_data = json.loads(base64.urlsafe_b64decode(payload).decode())
    return (verified, payload_data)


def init_blacklist_file():
    open('blacklist_db.txt', 'a').close()
    return True


def add_blacklist_token(token):
    with open('blacklist_db.txt', 'a') as file:
        file.write(f'{token},')
    return True


def is_token_blacklisted(token):
    with open('blacklist_db.txt') as file:
        content = file.read()
        array = content[:-1].split(',')
        for value in array:
            if value == token:
                return True

    return False


