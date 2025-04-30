import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

_mongo_uri = os.environ.get("MONGO_URI")
client = MongoClient(_mongo_uri) if _mongo_uri else MongoClient()

def get_db():

    return client['project5_db']  

def get_user_collection():

    db = get_db()
    return db['userInfo']