from tortoise import Model, fields
from tortoise.contrib.pydantic import pydantic_model_creator
from pydantic import BaseModel
from datetime import datetime


class User(Model):
    id = fields.IntField(pk=True, index=True)
    name = fields.CharField(max_length=50, null=False, unique=True)
    email = fields.CharField(max_length=50, null=False, unique=True)
    password = fields.CharField(max_length=255, null=False)
    is_verified = fields.BooleanField(default=False)
    is_active = fields.BooleanField(default=True)
    is_staff = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(default=datetime.utcnow)


user_pydantic = pydantic_model_creator(User, name="User", exclude=("is_verified",))
user_pydanticLogin = pydantic_model_creator(User, name="UserLogin", exclude_readonly=True, exclude=("name", "is_verified", "is_active", "is_staff", "created_at"))
user_pydanticRegister = pydantic_model_creator(User, name="UserRegister", exclude_readonly=True, exclude=("is_verified", "is_active", "is_staff", "created_at"))
user_pydanticOut = pydantic_model_creator(User, name="UserOut", exclude=("password","id", "is_verified", "is_active", "is_staff", "created_at",))


class ResetPasswordRequest(BaseModel):
    uidb64: str
    token: str
    password: str