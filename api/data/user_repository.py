from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from typing import List, Optional
import os
import math

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client["mydatabase"]
users_collection = db["users"]

async def get_user_by_email(email: str):
    return await users_collection.find_one({"email": email})

async def get_user_by_username(username: str):
    return await users_collection.find_one({"username": username})

async def get_user_by_id(user_id: str):
    """
    Busca un usuario por su ID de MongoDB
    """
    try:
        return await users_collection.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None

async def get_user_by_username_or_email(username_or_email: str):
    """
    Busca un usuario por username o email
    """
    return await users_collection.find_one({
        "$or": [
            {"username": username_or_email},
            {"email": username_or_email}
        ]
    })

async def get_users_paginated(page: int = 1, page_size: int = 10):
    """
    Obtiene usuarios de forma paginada
    """
    skip = (page - 1) * page_size
    
    # Contar total de usuarios
    total_count = await users_collection.count_documents({})
    
    # Obtener usuarios paginados
    cursor = users_collection.find({}).skip(skip).limit(page_size)
    users = await cursor.to_list(length=page_size)
    
    # Calcular metadatos de paginación
    total_pages = math.ceil(total_count / page_size)
    has_next_page = page < total_pages
    has_previous_page = page > 1
    
    return {
        "users": users,
        "totalCount": total_count,
        "totalPages": total_pages,
        "currentPage": page,
        "pageSize": page_size,
        "hasNextPage": has_next_page,
        "hasPreviousPage": has_previous_page
    }

async def check_users_exist():
    """
    Verifica si existe al menos un usuario en la base de datos
    """
    user = await users_collection.find_one({})
    return user is not None

async def create_user(user: dict):
    await users_collection.insert_one(user)

async def update_user(user_id: str, update_data: dict):
    """
    Actualiza un usuario por su ID
    """
    try:
        result = await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        return result.modified_count > 0
    except Exception:
        return False

async def delete_user(user_id: str):
    """
    Elimina un usuario por su ID
    """
    try:
        result = await users_collection.delete_one({"_id": ObjectId(user_id)})
        return result.deleted_count > 0
    except Exception:
        return False

async def add_role_to_user(user_id: str, role: str):
    """
    Agrega un rol a un usuario
    """
    try:
        result = await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$addToSet": {"roles": role}}
        )
        return result.modified_count > 0
    except Exception:
        return False
