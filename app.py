from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import bcrypt

app = Flask(__name__)

# MongoDB Config
app.config["MONGO_URI"] = "mongodb://localhost:27017/DHTS_Login"
mongo = PyMongo(app)
users_collection = mongo.db.users  # Collection to store user data

# Helper function to hash the password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Helper function to verify hashed password
def verify_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Internal registration endpoint (only admin or system can use this)
@app.route('/register', methods=['POST'])
def register_user():
    if request.json:  # Ensure request body contains JSON
        username = request.json.get('username')
        password = request.json.get('password')

        # Check if user already exists
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            return jsonify({"message": "User already exists!"}), 400

        # Hash the password and store in the database
        hashed_password = hash_password(password)

        # Insert user into MongoDB
        user_id = users_collection.insert_one({
            "username": username,
            "password": hashed_password
        }).inserted_id

        return jsonify({"message": "User created!", "user_id": str(user_id)}), 201

    return jsonify({"message": "Invalid input!"}), 400

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    if request.json:
        username = request.json.get('username')
        password = request.json.get('password')

        # Fetch user from database
        user = users_collection.find_one({"username": username})

        if user and verify_password(user['password'], password):
            return jsonify({"message": "Login successful!"}), 200
        else:
            return jsonify({"message": "Invalid username or password!"}), 401

    return jsonify({"message": "Invalid input!"}), 400

if __name__ == '__main__':
    app.run(debug=True)
