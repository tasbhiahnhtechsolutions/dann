from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Initialize the database if it doesn't exist
with app.app_context():
    if not os.path.exists('users.db'):
        db.create_all()

def is_valid_email(email):
    # Simple regex for email validation
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

# Route for registering a new user with constraints
@app.route('/register', methods=['POST'])
def register():
    # Try to get data from JSON first, fall back to form data if JSON is unavailable
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Check if all fields are provided
    if not username or not password or not email:
        return jsonify({"error": "Username, password, and email are required"}), 400

    # Validate username length
    if len(username) < 5:
        return jsonify({"error": "Username must be at least 5 characters long"}), 400

    # Validate email format
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    # Password constraints (e.g., min 8 chars, one uppercase, one number)
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        return jsonify({"error": "Password must be at least 8 characters long, with at least one uppercase letter and one number"}), 400

    # Check if username or email already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400

    # Hash the password for security
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


# Route for user login with constraints
@app.route('/login', methods=['POST'])
def login():
    # Try to get data from JSON first, fall back to form data if JSON is unavailable
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')

    # Check if both fields are provided
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Retrieve the user by username
    user = User.query.filter_by(username=username).first()

    # Check if user exists and verify password
    if user and check_password_hash(user.password, password):
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

if __name__ == '__main__':
    app.run(port=6000, debug=True)
