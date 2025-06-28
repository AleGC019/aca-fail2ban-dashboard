from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from data.user_repository import get_user_by_email, create_user
from dotenv import load_dotenv
import os

# Cargar variables del archivo .env
load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")  # Para OAuth2 password flow
bearer_scheme = HTTPBearer()  # Para Bearer token en Swagger
secret = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret, algorithm=algorithm)

async def register_user(email: str, password: str):
    if await get_user_by_email(email):
        raise Exception("User already exists")
    hashed = hash_password(password)
    await create_user({"email": email, "hashed_password": hashed})

async def authenticate_user(email: str, password: str):
    user = await get_user_by_email(email)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """
    Función para obtener el usuario actual desde el token JWT Bearer
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decodificar el token JWT
        payload = jwt.decode(credentials.credentials, secret, algorithms=[algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # Buscar el usuario en la base de datos
    user = await get_user_by_email(email)
    if user is None:
        raise credentials_exception
    
    return user

# Función alternativa para OAuth2PasswordBearer (si la necesitas)
async def get_current_user_oauth2(token: str = Depends(oauth2_scheme)):
    """
    Función alternativa para obtener el usuario usando OAuth2PasswordBearer
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await get_user_by_email(email)
    if user is None:
        raise credentials_exception
    
    return user