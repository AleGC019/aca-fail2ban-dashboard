from pydantic import BaseModel, EmailStr

class UserIn(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserDB(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str

class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
