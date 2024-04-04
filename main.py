from flask import Flask
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import argon2
from argon2 import PasswordHasher
import time

#Get encryption key from environment variable
def get_encryption_key():
    key = os.environ.get("NOT_MY_KEY")

    if key is None:
        #Generate a new key if it doesn't exist
        key = os.urandom(32)
        key_str = base64.urlsafe_b64encode(key).decode('utf-8')

        #Making the key a string variable
        os.environ["NOT_MY_KEY"] = key_str

    #Making the key into bytes
    return base64.urlsafe_b64decode(os.environ["NOT_MY_KEY"])

#Encrypt private key and store in the database
def encrypt_private_key(key, expiration_time, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(b'\0'*16), backend=default_backend())
    cipher_text = cipher.encryptor().update(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

    insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn.execute(insert_sql, (cipher_text, int(expiration_time.timestamp())))
    conn.commit()

def generate_secure_password():
    return str(uuid.uuid4())

#Rate limiter class to limit the requests to 10
class RateLimiter:
    def __init__(self, max_requests, per_seconds):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.request_times = {}
    def allow_request(self, ip):
        current_time = time.time()
        if ip not in self.request_times:
            self.request_times[ip] = [current_time]
            return True
        else:
            self.request_times[ip] = [t for t in self.request_times[ip] if current_time - t < self.per_seconds]
            if len(self.request_times[ip]) < self.max_requests:
                self.request_times[ip].append(current_time)
                return True
            else:
                return False

rate_limiter = RateLimiter(max_requests=10, per_seconds=1)

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            self.log_auth_request()

            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            if not rate_limiter.allow_request(self.log_auth_request()):
                self.send_response(429, "Too Many Requests")
                self.end_headers()
                return
            
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                headers["kid"] = "goodKID"
                token_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

        elif parsed_path.path == "/register":
            self.handle_registration()

        else:
            self.send_response(405)
            self.end_headers()

    def handle_registration(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        user_data = json.loads(post_data.decode('utf-8'))

        secure_password = generate_secure_password()
        hashed_password = ph.hash(secure_password)

        self.save_user(user_data['username'], hashed_password, user_data.get('email'))

        response_data = {"password": secure_password}
        self.send_response(201)  # Created
        self.end_headers()
        self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

    def save_user(self, username, hashed_password, email=None):
        conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                      (username, hashed_password, email))
        conn.commit()

    def log_auth_request(self):
        request_ip = self.client_address[0]
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        user_id = self.get_user_id()

        conn.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                      (request_ip, timestamp, user_id))
        conn.commit()

    def get_user_id(self):
        return 1


#Creates the SQLite database file
database_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(database_file)

#Define the table schema for storing private keys
create_table_keys_sql = """
CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

#Define the table schema for storing users
create_table_users_sql = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

#Define the table schema for logging authentication requests
create_table_auth_logs_sql = """
CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""

#SQL to create tables
conn.execute(create_table_keys_sql)
conn.execute(create_table_users_sql)
conn.execute(create_table_auth_logs_sql)
conn.commit()

#Update the existing store_private_key function call
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
encrypt_private_key(private_key, expiration_time, get_encryption_key())

expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expiration_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
encrypt_private_key(expired_key, expiration_time, get_encryption_key())

app = Flask(__name__)
limiter = Limiter(app)
ph = PasswordHasher()

@app.route('/example')
def example_route():
    return 'Hello, this is an example route!'

app.config['DEBUG'] = True

webServer = HTTPServer(("localhost", 8080), MyServer)
try:
    webServer.serve_forever()
except KeyboardInterrupt:
    pass

webServer.server_close()
