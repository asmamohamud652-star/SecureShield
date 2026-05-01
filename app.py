from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import sqlite3
import datetime
import logging
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config["SECRET_KEY"] = "super-secret-key-change-this"

blacklisted_tokens = set()

logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)


def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = None

            auth_header = request.headers.get("Authorization")

            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

            if not token:
                return jsonify({"message": "Token is missing"}), 401

            if token in blacklisted_tokens:
                return jsonify({"message": "Token has been revoked"}), 401

            try:
                data = jwt.decode(
                    token,
                    app.config["SECRET_KEY"],
                    algorithms=["HS256"]
                )

                username = data["username"]
                role = data["role"]

            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token has expired"}), 401

            except jwt.InvalidTokenError:
                return jsonify({"message": "Invalid token"}), 401

            if allowed_roles and role not in allowed_roles:
                attempted_action = request.path
                logging.warning(
                    f"403 Forbidden - User '{username}' with role '{role}' attempted '{attempted_action}'"
                )
                return jsonify({"message": "403 Forbidden: Access denied"}), 403

            return f(username, role, *args, **kwargs)

        return wrapper
    return decorator


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "User")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if role not in ["User", "Admin"]:
        return jsonify({"message": "Role must be User or Admin"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, role)
        )

        conn.commit()
        conn.close()

        return jsonify({"message": "User registered successfully"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 409


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    conn.close()

    if not user:
        return jsonify({"message": "Invalid username or password"}), 401

    user_id, db_username, hashed_password, role = user

    if not bcrypt.check_password_hash(hashed_password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    token = jwt.encode(
        {
            "username": db_username,
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        },
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "token": token,
        "role": role
    }), 200


@app.route("/profile", methods=["GET"])
@token_required(allowed_roles=["User", "Admin"])
def profile(username, role):
    return jsonify({
        "message": "Profile access granted",
        "username": username,
        "role": role
    }), 200


@app.route("/user/<int:user_id>", methods=["DELETE"])
@token_required(allowed_roles=["Admin"])
def delete_user(username, role, user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()

    deleted = cursor.rowcount
    conn.close()

    if deleted == 0:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "message": f"User with id {user_id} deleted successfully",
        "deleted_by": username
    }), 200


@app.route("/logout", methods=["POST"])
@token_required(allowed_roles=["User", "Admin"])
def logout(username, role):
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1]

    blacklisted_tokens.add(token)

    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == "__main__":
    app.run(debug=True)
    