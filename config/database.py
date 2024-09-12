from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
from urllib.parse import quote_plus
import os

username = quote_plus('anojan')
password = quote_plus('lRD4gCIqbRq1Jdvv')
cluster = 'cluster0.mhaksto.mongodb.net'
uri = f"mongodb+srv://anojan:lRD4gCIqbRq1Jdvv@cluster0.qwvo6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = AsyncIOMotorClient(uri, server_api=ServerApi('1'))

db = client["SKMETALS"]  # Replace with your database name
collection_name = db["User"]
fogotPassword = db["user_otp"]

async def main():
    try:
        await client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
    except Exception as e:
        print(e)

# Since the asyncio event loop is already running, we should call main() with await
import asyncio

asyncio.get_event_loop().create_task(main())
