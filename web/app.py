from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy
import tensorflow as tf
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.IRG
users = db["Users"]

def UserExist(username):
    return users.find({"Username":username}).count() != 0

def returnState(status, comments):
    return jsonify({
        "status": status,
        "msg": comments
    })

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            return returnState(301, "Invalid Username")

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # store username and password into database
        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 4
        })

        return returnState(200, "You successfully signed up to the API")


def verifyPw(username, password):
    hashed_pw = users.find({
        "Username":username
    })[0]["Password"]

    return bcrypt.checkpw(password.encode('utf-8'), hashed_pw)


def countTokens(username):
    return users.find({
        "Username": username
    })[0]["Tokens"]


def verifyCredentials(username, password):
    if not UserExist(username):
        return returnState(301, "Invalid Username/Password"), True

    correct_pw = verifyPw(username, password)
    if not correct_pw:
        return returnState(302, "Invalid Username/Password"), True

    return None, False


class Classify(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        url = postedData["url"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return retJson

        #Verify user has enough tokens
        num_tokens = countTokens(username)
        if num_tokens <= 0:
            return returnState(303, "Not Enough Tokens!")

        r = requests.get(url)
        retJson = {}
        with open('temp.jpg', 'wb') as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            ret = proc.communicate()[0]
            proc.wait()
            with open("text.txt") as f:
                retJson = json.load(f)

        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": num_tokens-1
            }
        })

        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_amount = postedData["amount"]

        if not UserExist(username):
            return returnState(301,"Invalid Username/Password")

        #Create admin if it doesn't exist
        if not UserExist("Admin"):
            admin_pw = "abc123"
            hashed_pw = bcrypt.hashpw(admin_pw.encode('utf-8'), bcrypt.gensalt())
            users.insert({
                "Username": "Admin",
                "Password": hashed_pw
            })

        if not verifyPw("Admin", password):
            return returnState(304, "Invalid Admin Username/Password")

        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": refill_amount
            }
        })

        return returnState(200,"Refilled successfully")

api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__=="__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
