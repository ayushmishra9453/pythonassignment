# database.py
from pymongo import MongoClient
client = MongoClient("mongodb://127.0.0.1:27017/assignment")
db = client.user_database
users_collection = db.users
ids_collection = db.ids