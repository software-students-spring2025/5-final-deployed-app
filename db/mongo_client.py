from pymongo import MongoClient

MONGO_URI = "mongodb+srv://lgl1876523678:1017@cluster0.k8xwe.mongodb.net/?retryWrites=true&w=majority"


client = MongoClient(MONGO_URI)

def get_db():

    return client['project5_db']  

def get_user_collection():

    db = get_db()
    return db['userInfo']  