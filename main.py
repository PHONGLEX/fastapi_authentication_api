import os
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
import jwt
import secrets

from fastapi import FastAPI, HTTPException, status, Request, Depends
from tortoise.contrib.fastapi import register_tortoise
from authentication import add_blacklist_token, create_signed_token, get_hashed_password, is_token_blacklisted, token_generator, verify_signed_token, verify_token, init_blacklist_file
from email_helper import send_email
from models import *
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer


app = FastAPI()
load_dotenv('.env')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')

@app.on_event("startup")
async def startup_event():
    init_blacklist_file()


register_tortoise(
    app,
    db_url=os.environ['DATABASE_URL'],
    modules={"models": ["models"]},
    generate_schemas=True,
    add_exception_handlers=True
)


CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='Could not validate credentials',
    headers={'WWW-Authenticate': 'Bearer'},
)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    if is_token_blacklisted(token):
        raise CREDENTIALS_EXCEPTION
    try:
        user = await verify_token(token)
        return user
    except jwt.PyJWTError:
        raise CREDENTIALS_EXCEPTION


async def get_current_user_token(token: str = Depends(oauth2_scheme)):
    _ = await get_current_user(token)
    return token


@app.get('/')
async def greeting(user: User=Depends(get_current_user)):
    return {"message": "Hello World"}


@app.post('/register')
async def register(user: user_pydanticRegister, request: Request):
    user_info = user.dict(exclude_unset=True)
    user_info['password'] = get_hashed_password(user_info['password'])
    user_obj = await User.create(**user_info)
    new_user = await user_pydantic.from_tortoise_orm(user_obj)

    domain = request.client.host

    payload = {
        "id": user_obj.id,
    }

    token = jwt.encode(payload, os.environ['SECRET_KEY'], algorithm="HS256")

    link = f"http://{domain}:8000/email-verify/?token={token}"

    html = f"""
        Hi {user.name}, 
        Please use the link below to verify your account {link}
    """
    await send_email([new_user.email], "Verify your account", html)

    return {
        "message": "We've sent you an email to verify your account"
    }


@app.get('/email-verify')
async def email_verify(token: str):
    user = await verify_token(token)

    if user and not user.is_verified:
        user.is_verified = True
        await user.save()

        return {"message": "Successfully activation"}

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token, please request a new one")


@app.post('/login')
async def login(request_form: OAuth2PasswordRequestForm=Depends()):
    tokens = await token_generator(request_form.username, request_form.password)

    return {
        "access_token": tokens
    }
    
    
@app.post('/reset-password')
async def reset_password(email: str, request: Request):
    user = await User.get(email=email)

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email, please provide the correct email")

    domain = request.client.host
    data = {
        "id": user.id
    }
    token = secrets.token_hex()
    uidb64 = create_signed_token(token.encode('utf-8'), data)
    link = f"http://{domain}:8000/reset-password-confirm/{uidb64}/{token}"

    html = f"""
        Hi {user.name}, 
        Please use the link below to reset your password {link}
    """

    await send_email([user.email], "Reset your password", html)
    return {
        "message": "We've sent you an email to reset your password"
    }

    
@app.post('/reset-password-confirm/{uidb64}/{token}')
async def check_password_reset_token(uidb64: str, token: str):
    (verified, payload) = verify_signed_token(token.encode('utf-8'), uidb64)

    if verified:
        return {"success": True, "token": token, "uidb64": uidb64}

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, )


@app.post('/set-new-password')
async def set_new_password(data: ResetPasswordRequest):
    data = data.dict()
    (verified, payload) = verify_signed_token(data['token'].encode('utf-8'), data['uidb64'])
    
    if verified:
        user = await User.get(id=payload['id'])
        user.password = get_hashed_password(data['password'])
        await user.save()
        return {"message": "Changed password successfully"}

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token is invalid, please try again"
    ,headers={"WWW-Authenticate": "Bearer"})


@app.post('/logout', status_code=status.HTTP_204_NO_CONTENT)
async def logout(token: str = Depends(get_current_user_token)):
    if add_blacklist_token(token):
        return {'result': True}
    raise CREDENTIALS_EXCEPTION