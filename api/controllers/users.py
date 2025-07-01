from fastapi import APIRouter, Depends, HTTPException, Query
from services.auth import get_current_user, require_admin
from data.user_repository import (
    get_user_by_id, 
    get_users_paginated, 
    delete_user, 
    add_role_to_user,
    update_user
)
from data.user_model import UserOut, PaginatedUsers, UserUpdate

router = APIRouter()

@router.get("/{user_id}", response_model=UserOut)
async def get_user_by_id_endpoint(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Obtiene un usuario por su ID.
    Requiere autenticación.
    """
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return UserOut(
        id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        roles=user.get("roles", ["USER"])
    )

@router.get("/", response_model=PaginatedUsers)
async def get_users_paginated_endpoint(
    page: int = Query(1, ge=1, description="Número de página (mínimo 1)"),
    page_size: int = Query(10, ge=1, le=100, description="Tamaño de página (1-100)"),
    current_user: dict = Depends(get_current_user)
):
    """
    Obtiene usuarios de forma paginada.
    Requiere autenticación.
    """
    result = await get_users_paginated(page, page_size)
    
    users_out = []
    for user in result["users"]:
        users_out.append(UserOut(
            id=str(user["_id"]),
            username=user["username"],
            email=user["email"],
            roles=user.get("roles", ["USER"])
        ))
    
    return PaginatedUsers(
        users=users_out,
        totalCount=result["totalCount"],
        totalPages=result["totalPages"],
        currentPage=result["currentPage"],
        pageSize=result["pageSize"],
        hasNextPage=result["hasNextPage"],
        hasPreviousPage=result["hasPreviousPage"]
    )

@router.delete("/{user_id}")
async def delete_user_endpoint(
    user_id: str,
    current_user: dict = Depends(require_admin)
):
    """
    Elimina un usuario por su ID.
    Solo accesible para usuarios con rol ADMIN.
    """
    # Verificar que el usuario existe
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # No permitir que un admin se elimine a sí mismo
    if str(user["_id"]) == str(current_user["_id"]):
        raise HTTPException(
            status_code=400, 
            detail="No puedes eliminar tu propia cuenta"
        )
    
    success = await delete_user(user_id)
    if not success:
        raise HTTPException(
            status_code=500, 
            detail="Error al eliminar el usuario"
        )
    
    return {"message": "Usuario eliminado exitosamente"}

@router.post("/{user_id}/assign-admin")
async def assign_admin_role(
    user_id: str,
    current_user: dict = Depends(require_admin)
):
    """
    Asigna el rol de ADMIN a un usuario.
    Solo accesible para usuarios con rol ADMIN.
    """
    # Verificar que el usuario existe
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Verificar si ya tiene el rol de ADMIN
    user_roles = user.get("roles", [])
    if "ADMIN" in user_roles:
        raise HTTPException(
            status_code=400, 
            detail="El usuario ya tiene el rol de ADMIN"
        )
    
    success = await add_role_to_user(user_id, "ADMIN")
    if not success:
        raise HTTPException(
            status_code=500, 
            detail="Error al asignar el rol de ADMIN"
        )
    
    return {
        "message": f"Rol de ADMIN asignado exitosamente al usuario {user['username']}"
    }

@router.put("/{user_id}", response_model=UserOut)
async def update_user_endpoint(
    user_id: str,
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Actualiza un usuario.
    Los usuarios pueden actualizar su propia información.
    Los ADMIN pueden actualizar cualquier usuario.
    """
    # Verificar que el usuario existe
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Verificar permisos: solo el propio usuario o un ADMIN pueden actualizar
    is_self = str(user["_id"]) == str(current_user["_id"])
    is_admin = "ADMIN" in current_user.get("roles", [])
    
    if not (is_self or is_admin):
        raise HTTPException(
            status_code=403, 
            detail="No tienes permisos para actualizar este usuario"
        )
    
    # Solo los ADMIN pueden cambiar roles
    if user_update.roles is not None and not is_admin:
        raise HTTPException(
            status_code=403, 
            detail="Solo los administradores pueden cambiar roles"
        )
    
    # Preparar datos de actualización
    update_data = {}
    if user_update.username is not None:
        update_data["username"] = user_update.username
    if user_update.email is not None:
        update_data["email"] = user_update.email
    if user_update.roles is not None:
        update_data["roles"] = user_update.roles
    
    if not update_data:
        raise HTTPException(
            status_code=400, 
            detail="No se proporcionaron datos para actualizar"
        )
    
    success = await update_user(user_id, update_data)
    if not success:
        raise HTTPException(
            status_code=500, 
            detail="Error al actualizar el usuario"
        )
    
    # Obtener el usuario actualizado
    updated_user = await get_user_by_id(user_id)
    return UserOut(
        id=str(updated_user["_id"]),
        username=updated_user["username"],
        email=updated_user["email"],
        roles=updated_user.get("roles", ["USER"])
    )

@router.get("/admin/stats")
async def get_user_stats(
    current_user: dict = Depends(require_admin)
):
    """
    Obtiene estadísticas de usuarios.
    Solo accesible para usuarios con rol ADMIN.
    """
    # Obtener todos los usuarios para calcular estadísticas
    all_users = await get_users_paginated(1, 1000)  # Asumiendo que no hay más de 1000 usuarios
    
    total_users = all_users["totalCount"]
    admin_count = 0
    user_count = 0
    
    for user in all_users["users"]:
        roles = user.get("roles", [])
        if "ADMIN" in roles:
            admin_count += 1
        else:
            user_count += 1
    
    return {
        "totalUsers": total_users,
        "adminUsers": admin_count,
        "regularUsers": user_count
    }
