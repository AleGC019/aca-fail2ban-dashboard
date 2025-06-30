from pydantic import BaseModel, EmailStr
from typing import List, Optional
from enum import Enum

class UserRole(str, Enum):
    USER = "USER"
    ADMIN = "ADMIN"

class UserIn(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserDB(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str
    roles: List[UserRole] = [UserRole.USER]

class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    roles: List[UserRole]

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    roles: Optional[List[UserRole]] = None

class PaginatedUsers(BaseModel):
    users: List[UserOut]
    totalCount: int
    totalPages: int
    currentPage: int
    pageSize: int
    hasNextPage: bool
    hasPreviousPage: bool

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class AssignAdminRequest(BaseModel):
    user_id: str
