from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client["mydatabase"]
users_collection = db["users"]

async def get_user_by_email(email: str):
    return await users_collection.find_one({"email": email})

async def get_user_by_username(username: str):
    return await users_collection.find_one({"username": username})

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

async def check_users_exist():
    """
    Verifica si existe al menos un usuario en la base de datos
    """
    user = await users_collection.find_one({})
    return user is not None

async def create_user(user: dict):
    await users_collection.insert_one(user)
