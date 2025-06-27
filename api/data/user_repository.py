from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client["mydatabase"]
users_collection = db["users"]

async def get_user_by_email(email: str):
    return await users_collection.find_one({"email": email})

async def create_user(user: dict):
    await users_collection.insert_one(user)
