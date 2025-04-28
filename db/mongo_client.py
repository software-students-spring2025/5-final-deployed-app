import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

client = os.environ.get("MONGO_URI")

def get_db():

    return client['project5_db']  

def get_user_collection():

    db = get_db()
    return db['userInfo']  