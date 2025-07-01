from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from data.user_repository import get_user_by_email, get_user_by_username, get_user_by_username_or_email, create_user, check_users_exist
from dotenv import load_dotenv
import os

# Cargar variables del archivo .env
load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ACCESS_TOKEN_EXPIRE_MINUTES = 10080
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

async def register_user(username: str, email: str, password: str):
    # Verificar si el usuario ya existe por email
    if await get_user_by_email(email):
        raise Exception("Ya existe un usuario con este email")
    
    # Verificar si el usuario ya existe por username
    if await get_user_by_username(username):
        raise Exception("Ya existe un usuario con este nombre de usuario")
    
    hashed = hash_password(password)
    user_data = {
        "username": username,
        "email": email, 
        "hashed_password": hashed,
        "roles": ["USER"]  # Rol por defecto
    }
    await create_user(user_data)

async def users_exist():
    """
    Verifica si existe al menos un usuario en la base de datos
    """
    return await check_users_exist()

async def authenticate_user(username_or_email: str, password: str):
    user = await get_user_by_username_or_email(username_or_email)
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
    
    # Buscar el usuario en la base de datos por email (ya que el token contiene el email)
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

def require_role(required_role: str):
    """
    Decorador para requerir un rol específico
    """
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_roles = current_user.get("roles", [])
        if required_role not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Se requiere el rol {required_role} para acceder a este recurso"
            )
        return current_user
    return role_checker

async def require_admin(current_user: dict = Depends(get_current_user)):
    """
    Función específica para requerir rol de administrador
    """
    user_roles = current_user.get("roles", [])
    if "ADMIN" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere el rol ADMIN para acceder a este recurso"
        )
    return current_user