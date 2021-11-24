import pymongo
from bson.objectid import ObjectId
from flask import request

db_main = pymongo.MongoClient('mongodb+srv://police-department:1234567890@police-department-jezpl.mongodb.net/test?retryWrites=true&w=majority')
db = db_main["users"]
db = db["users"]
settings = db_main['settings']
settings = settings['settings']
applic = db_main['applications']
applic = applic['applications']

id = ObjectId('5ede913021cf2c25c3f5f912')
applic.update_one({'_id': id},
                  {"$set": {'check': None, 'level': 'end', 'status': 'Closed'}})


