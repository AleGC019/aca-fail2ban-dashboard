from fastapi import APIRouter, Depends, HTTPException
from services.auth import authenticate_user, create_access_token, register_user, get_current_user, users_exist
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
async def login_custom(login_data: LoginRequest):
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

@router.get("/users-exist")
async def check_if_users_exist():
    """
    Verifica si existe al menos un usuario en la base de datos.
    Útil para saber si se debe mostrar la pantalla de configuración inicial.
    """
    exist = await users_exist()
    return {"users_exist": exist}
