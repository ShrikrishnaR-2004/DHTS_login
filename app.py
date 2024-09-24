from flask import Flask, request, jsonify
from pymongo import MongoClient
import bcrypt
import hashlib

app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['DHTS_Login']
users_collection = db['Login']

# SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Registration
@app.route('/internal/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the user already exists
    if users_collection.find_one({'username': username}):
        return jsonify({'error': 'User already exists'}), 400

    # Hash the password
    hashed_password = hash_password(password)

    # Insert user data into MongoDB
    users_collection.insert_one({
        'username': username,
        'password': hashed_password
    })

    return jsonify({'message': 'User registered successfully'}), 201

# Login
@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Retrieve data
    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    # Verify the password
    hashed_password = hash_password(password)
    if user['password'] == hashed_password:
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

if __name__ == '__main__':
    app.run(debug=True)
