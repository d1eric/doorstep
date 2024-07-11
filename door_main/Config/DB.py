from pymongo import MongoClient

connection_string = "mongodb+srv://ericogundero:D4TIfaecFaoix96s@cluster0.41nfjyx.mongodb.net/"

client = MongoClient(connection_string)

mydb = client["MyDB"]

user_collection = mydb["Users"]

from motor import motor_asyncio

# connection_string = "mongodb+srv://david:david1234@cluster0.tcdmyxt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# client = motor_asyncio.AsyncIOMotorClient(connection_string)

# db = client["MyDB"]

conn = mydb["Users"]