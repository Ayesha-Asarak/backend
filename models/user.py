from pydantic import BaseModel, EmailStr
from typing import Optional
class Signup(BaseModel):
    name: str
    email: EmailStr
    password: str
    # role:str
    
class Login(BaseModel):
    name: str
    password: str
    # role:str
    
class EmailCheck(BaseModel):
    email: EmailStr

class PasswordChange(BaseModel):
    email: EmailStr
    # old_password: str
    new_password: str

# Other models like OtpCheck if needed
class OtpCheck(BaseModel):
    otp: str
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str
    

# class ForgotSerie(BaseModel):
#     email: EmailStr
#     series: str