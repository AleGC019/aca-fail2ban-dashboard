from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from services.auth import authenticate_user, create_access_token, register_user, get_current_user
from data.user_model import UserIn, Token, LoginRequest

router = APIRouter()

@router.post("/register", status_code=201)
async def register(user: UserIn):
    try:
        await register_user(user.username, user.email, user.password)
        return {"message": "Usuario creado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}

@router.post("/login-custom", response_model=Token)
async def login_custom(login_data: LoginRequest):
    """
    Login alternativo que acepta JSON con username_or_email y password
    """
    user = await authenticate_user(login_data.username_or_email, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/whoami")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Endpoint para obtener información del usuario autenticado
    """
    return {
        "username": current_user["username"],
        "email": current_user["email"], 
        "message": "Token válido"
    }
