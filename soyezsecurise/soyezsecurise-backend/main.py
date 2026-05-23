import hmac
import hashlib
from itertools import count
import os
from fastapi import FastAPI
import redis
import base64
from pydantic import BaseModel, StringConstraints
from typing import Annotated
import pyotp
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import psycopg2
from fastapi import Request
import uuid
from fastapi.middleware.cors import CORSMiddleware
import time
import qrcode
import io
from psycopg2.extras import RealDictCursor
from check_block import(
    check,
    blocker
)
from logger import (
    login_logger,
    db_logger,
    sys_logger,
    otp_logger,
    Log_event
)



#---------------------------------------------------setup--------------------------------------------------#
DATABASE_URL = os.getenv("DATABASE_URL")


conn = psycopg2.connect(
    DATABASE_URL,
    cursor_factory=RealDictCursor
)
REDIS_URL = os.getenv("REDIS_URL")

nonce_db = redis.Redis.from_url(REDIS_URL,decode_responses=True)
ratelimitin = redis.Redis.from_url(REDIS_URL,decode_responses=True)
temp_blocked = redis.Redis.from_url(REDIS_URL,decode_responses=True)
cursor = conn.cursor()
app = FastAPI()
#--------------------------------------------strict input classes--------------------------------------------------#

# =========================
# Strict input parameters 
# =========================

OTPType = Annotated[
    str,
    StringConstraints(
        min_length=0,
        max_length=6,
        pattern=r"^[0-9]"
    )
]

EmailType = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=90,
        pattern=r"^[a-zA-Z0-9@._]+$"
    )
]

UsernameType = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=32,
        pattern=r"^[a-zA-Z0-9@._]+$"
    )
]

Hex64Type = Annotated[
    str,
    StringConstraints(
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]+$"
    )
]



PasswordNameType = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9.@_]+$"
    )
]

Base64Type = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=10000,
        pattern=r"^[A-Za-z0-9+/=]+$"
    )
]

Requets_ID = Annotated[
    str,
    StringConstraints(
        min_length=32,
        max_length=32,
        pattern=r"^[A-Za-z0-9+/=]+$"
    )
]

# =========================
# Request Models
# =========================

class UsernameRequest(BaseModel):
    username: UsernameType


class NewUserRequest(BaseModel):
    username: UsernameType
    hash: Hex64Type
    email: EmailType
    salt: Annotated[
        str,
        StringConstraints(
            min_length=64,
            max_length=64,
            pattern=r"^[a-fA-F0-9]+$"
        )
    ]


class StoredPasswordRequest(BaseModel):
    signature: Hex64Type
    username: UsernameType
    password_name: PasswordNameType 
    usernametbs: UsernameType
    enc_data: Base64Type
    request_id: Requets_ID 


class GetEncryptedRequest(BaseModel):
    signature: Hex64Type
    username: UsernameType
    password_name: PasswordNameType
    usernameS: PasswordNameType
    request_id: Requets_ID


class GetBackupRequest(BaseModel):
    signature: Hex64Type
    username: UsernameType
    otp: OTPType
    request_id: Requets_ID
class ListPasswordRequest(BaseModel):
    signature: Hex64Type
    username: UsernameType
    request_id: Requets_ID

class GetOTPRequest(BaseModel):
    signature: Hex64Type
    username: UsernameType
    request_id: Requets_ID


class DeletePasswordRequest2(BaseModel):
    signature: Hex64Type
    username: UsernameType
    password_name: PasswordNameType
    usernameS: PasswordNameType
    request_id: Requets_ID

#----------------------------------------------functions--------------------------------------------------#

# =========================
# decrypting
# =========================

def decrypt(enc_secret, key, tag, nonce):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(enc_secret, tag)
    return plaintext

# =========================
# verifying otp
# =========================

def otp_generation_and_verfication(username, user_otp):
    cursor.execute(
        """
    SELECT id FROM users WHERE username = %s;""",
        (username,),)
    userid = cursor.fetchone()[0]
    cursor.execute("""
    SELECT secret,salt FROM twofa WHERE userid = %s;
""", (userid,),
)
    row = cursor.fetchone()
    enc_secret = row[0]
    enc_secret = base64.b64decode(enc_secret)
    salt = row[1]
    salt = base64.b64decode(salt)
    cursor.execute("""
    SELECT hash FROM users WHERE id = %s;
""", (userid,),
)
    base_key = bytes.fromhex(cursor.fetchone()[0])
    key1 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'otpsecretencryption',
)
    key = key1.derive(base_key)
    nonce = salt[:12]
    tag = salt[12:]
    secret = decrypt(enc_secret, key, tag, nonce)
    secret = secret.decode().strip()
    totp = pyotp.TOTP(secret)
    if totp.verify(str(user_otp)):
        
        return "VALID"
    else:
        return "INVALID"

    
# =========================
# time_equilizer
# =========================

def time_equilizer(started_time):
    time_taken = time.time() - started_time
    target = 0.30
    required = target - time_taken
    if required > 0:
        time.sleep(required)



# =========================
# ip
# =========================

def get_client_ip(request: Request):
    trusted_proxies = ["127.0.0.1", "localhost"]
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.client.host
    return ip


# =========================
# encrypting otp secret
# =========================

def encrypter(data, un):
    nonce_gen = os.urandom(12)
    cursor.execute("""
        SELECT hash FROM users WHERE id = %s;""",
        (un,),
    )
    hash_key = cursor.fetchone()[0]
    key1 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'otpsecretencryption',
    )
    key = key1.derive(bytes.fromhex(hash_key))
    nonce = nonce_gen
    encrypted_data = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = encrypted_data.encrypt_and_digest(data.encode())
    salt_payload = nonce + tag 
    salt_payload = base64.b64encode(salt_payload).decode()
    secret = ciphertext
    secret = base64.b64encode(ciphertext).decode()
    sys_logger.info(f"Secret was Encrpyted for user -{un}-")
    return {
        "secret" : secret,
        "salt_payload" : salt_payload
    }

# =========================
# New IP alerting
# =========================

# def IP_check(userid, ip):
#     cursor.execute("""
#         SELECT ip FROM iptracking WHERE userid = %s;
# """, (userid,))
#     old_ip = cursor.fetchone()[0]
#     if ip == old_ip:
#         return {"No ERROR" : "--"}
#     else:
#         return {"ERROR" : "You have Logged in from another device or ip"}


# =========================
# Middleware
# =========================


app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]


)

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';"
    
    return response


#--------------------------------------------APIs--------------------------------------------------#

# =========================
# otp enabling
# =========================

@app.post("/enableotp")
async def enable_otp(data: UsernameRequest, request: Request):
    start = time.time()
    request_id = uuid.uuid4().hex
    ip = get_client_ip(request)
    if check(ip) == "IP BLOCKED":
        return {"ERROR" : "You have been blocked for violating policies, Try again later"}
    username = data.username
    count = ratelimitin.incr(f"rlpost:{username}")
    cursor.execute(
        """
    SELECT * FROM users WHERE username = %s""",
        (username,),
    )
    if username == "' 1=1--":
        Log_event(login_logger, "/enableotp", "CRITICAL", "Bypassed pydantic", f"{username}", f"{ip}", f"{request_id}")
        return {"ERROR" : "Thats not gonna work bruh"}
    
    result = cursor.fetchone()
    if not result:
        Log_event(login_logger, "/enableotp", "WARNING", "Invalid username entered", f"{username}", f"{ip}", f"{request_id}")
        nonce = os.urandom(32).hex()
        salt = os.urandom(32).hex()
        time_equilizer(start)
        return {"nonce" : nonce,
                "salt" : salt,
                "request_id" : request_id}
    else:
        if ratelimitin.exists(f"rlpost:{username}"):
            if int(ratelimitin.get(f"rlpost:{username}")) >= 10:
                temp_blocked.set(f"blocked:{username}", "1")
                temp_blocked.expire(f"blocked:{username}", 3600)
                ratelimitin.delete(f"rlpost:{username}")
                Log_event(login_logger, "/enableotp", "WARNING", "Rapid requests detected", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "Too many requests, try again in an hour"}
            else:
                pass
        else:
            ratelimitin.set(f"rlpost:{username}", "0")
        
        if temp_blocked.exists(f"blocked:{username}"):
            Log_event(login_logger, "/enableotp", "CRITICAL", "User blocked", f"{username}", f"{ip}", f"{request_id}")
            return {"ERROR": "You are temporarily blocked, try again in an hour"}
        nonce = os.urandom(32).hex()
        Log_event(sys_logger, "/enableotp", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        userid = cursor.fetchone()[0]
        cursor.execute(
    "SELECT 1 FROM twofa WHERE userid = %s",
    (userid,)
) 
        ifexists = cursor.fetchone()
        if ifexists:
            return {"ERROR" : "otp Already enabled"}
        key = f"{username}:otp"

        nonce_db.hset(
        key,
         mapping={
            "value": nonce,
            },
        )
        Log_event(sys_logger, "/enableotp", "INFO", "Temporary nonce stored", f"{username}", f"{ip}", f"{request_id}")
        Log_event(sys_logger, "/enableotp", "INFO", "temperory Nonce Stored", f"{username}", f"{ip}", f"{request_id}")
        nonce_db.expire(key, 300)
        ratelimitin.incr(f"rlpost:{username}")
        if count == 1:
            ratelimitin.expire(f"rlpost:{username}", 3600)
        cursor.execute(
    "SELECT salt FROM salt WHERE userid = %s",
    (userid,)
)
        salt = cursor.fetchone()[0]
        Log_event(sys_logger, "/enableotp", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        time_equilizer(start)
        return {
            "nonce": nonce,
            "request_id" : request_id
            }

@app.post("/enable_otp2")
async def enable_otp2(data: GetOTPRequest, request: Request):
    try:
        signature = data.signature
        un = data.username
        request_id = data.request_id
        ip = get_client_ip(request)
        if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
        signature_bytes = bytes.fromhex(signature)
        data = nonce_db.hgetall(f"{un}:otp")

        if not data:
            blocker(ip, request_id)
            return {"ERROR": f"Session expired"}
        cursor.execute(
        """
        SELECT * FROM users WHERE username = %s""",
        (un,),
        )
        result = cursor.fetchone()
        if not result:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        row = cursor.fetchone()
        user_id = row[0]
        cursor.execute(
            """
        SELECT hash FROM users WHERE id = %s""",
            (user_id,),
        )
        hash = cursor.fetchone()[0]

        server_signature = hmac.new(
            bytes.fromhex(hash), bytes.fromhex(data["value"]), hashlib.sha256
        ).digest()
        Log_event(sys_logger, "/enable_otp2", "INFO", "Server signature generated", f"{un}", f"{ip}", f"{request_id}")
        if not hmac.compare_digest(signature_bytes, server_signature):
            ratelimitin.incr(f"rlpost:{un}")
            Log_event(login_logger, "/enable_otp2", "WARNING", "Invalid signature", f"{un}", f"{ip}", f"{request_id}")
            blocker(ip, request_id)
            return {"ERROR": f"Username or password is wrong"}
        Log_event(login_logger, "/enable_otp2", "INFO", "Valid signature", f"{un}", f"{ip}", f"{request_id}")
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
        name=un,
        issuer_name="Ayano V2"
        )
        img = qrcode.make(uri)
        enabled = True
        encrypt = encrypter(secret, user_id)
        enc_secret = encrypt["secret"]
        salt = encrypt["salt_payload"]
        cursor.execute(
        """
        INSERT INTO twofa(userid, enabled, secret, salt) VALUES (%s,%s,%s,%s)
""",(user_id, enabled, enc_secret, salt) )
        Log_event(otp_logger, "/enable_otp2", "INFO", "OTP enabled", f"{un}", f"{ip}", f"{request_id}")
        conn.commit()
        img = qrcode.make(uri)
        buffer = io.BytesIO()
        img.save(
        buffer,
        format="PNG"
        )
        img_b64 = base64.b64encode(
            buffer.getvalue()
        ).decode()

        return {"secret_code": secret,
                "qr" : img_b64}

    except Exception as e:
        Log_event(sys_logger, "/enableotp2", "ERROR", f"""{str(e)}""", f"{un}", f"{ip}", f"{request_id}")
        sys_logger.error(f"error: -{str(e)}- at otp-enabling")
        return {"ERROR": "Something Went Wrong"}
    

# =========================
# new user creation
# =========================


@app.post("/newuser")
async def new_user(data: NewUserRequest, request: Request):
    try:
        un = data.username
        hp = data.hash
        salt = data.salt
        email = data.email
        ip = get_client_ip(request)
        if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
        request_id = uuid.uuid4().hex
        cursor.execute(
            """
            SELECT * FROM users WHERE username = %s;""",
            (un,),
        )
        result = cursor.fetchone()

        if result:
            Log_event(login_logger, "/newuser", "WARNING", "Duplicate username registration attempt", f"{un}", f"{ip}", f"{request_id}")
            return {"ERROR": "Invalid username"}

        else:
            clean_un = un

            cursor.execute(
                """
            INSERT INTO users (username, hash)
        VALUES (%s, %s);
        """,
                (clean_un, hp),
            )

            cursor.execute("SELECT id FROM users WHERE username = %s;", (clean_un,))
            row = cursor.fetchone()[0]
            user_id = row
            cursor.execute(
                """
            INSERT INTO emails (userid, email)
        VALUES (%s, %s);
        """,
                (user_id, email),
            )
            Log_event(db_logger, "/newuser", "INFO", "User hash stored", f"{un}", f"{ip}", f"{request_id}")
            cursor.execute("""
            INSERT INTO iptracking (userid, ip) VALUES(%s, %s);
""", (user_id, ip))
            Log_event(db_logger, "/newuser", "INFO", "IP stored", f"{un}", f"{ip}", f"{request_id}")
            cursor.execute(
                """
            INSERT INTO salt (userid, salt)
            VALUES(%s, %s);
            """,
                (user_id, salt),
            )
            Log_event(db_logger, "/newuser", "INFO", "Salt stored", f"{un}", f"{ip}", f"{request_id}")
            conn.commit()
            Log_event(login_logger, "/newuser", "INFO", "New user created", f"{un}", f"{ip}", f"{request_id}")
            return {"message": "User created successfully", "username": clean_un}
    except Exception as e:
        Log_event(sys_logger, "/newuser", "ERROR", f"""{str(e)}""", f"{un}", f"{ip}", f"{request_id}")
        print(f"str(e)")
        return {"ERROR" : "Something Went Wrong"}

# =========================
# storing password
# =========================

# To store the password.
@app.post("/storepassword")
async def store_password(data: UsernameRequest, request: Request):
    start = time.time()
    username = data.username
    request_id = uuid.uuid4().hex
    ip = get_client_ip(request)
    if check(ip) == "IP BLOCKED":
        return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
    cursor.execute(
        """
    SELECT * FROM users WHERE username = %s""",
        (username,),
    )
    result = cursor.fetchone()
    if not result:
        Log_event(login_logger, "/storepassword", "WARNING", "Invalid username entered", f"{username}", f"{ip}", f"{request_id}")
        nonce = os.urandom(32).hex()
        salt = os.urandom(32).hex()
        time_equilizer(start)
        return {"nonce" : nonce,
                "salt" : salt,
                "request_id" : request_id}
    else:
        if ratelimitin.exists(f"rlpost:{username}"):
            if int(ratelimitin.get(f"rlpost:{username}")) >= 10:
                temp_blocked.set(f"blocked:{username}", "1")
                temp_blocked.expire(f"blocked:{username}", 3600)
                ratelimitin.delete(f"rlpost:{username}")
                Log_event(login_logger, "/storepassword", "WARNING", "Rapid requests detected", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "Too many requests"}
            else:
                pass
        else:
            ratelimitin.set(f"rlpost:{username}", "0")
        if temp_blocked.exists(f"blocked:{username}"):
            Log_event(login_logger, "/storepassword", "CRITICAL", "User blocked", f"{username}", f"{ip}", f"{request_id}")
            return {"ERROR": "You are temporarily blocked, try again after some time"}
        nonce = os.urandom(32).hex()
        Log_event(sys_logger, "/storepassword", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        key = f"post:{username}"
        nonce_db.hset(
            key,
            mapping={
                "value": nonce,
            },
        )
        Log_event(sys_logger, "/storepassword", "INFO", "Temporary nonce stored", f"{username}", f"{ip}", f"{request_id}")
        nonce_db.expire(f"post:{username}", 300)
        ratelimitin.incr(f"rlpost:{username}")
        if count == 1:
            ratelimitin.expire(f"rlpost:{username}", 3600)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        userid = cursor.fetchone()[0]
        cursor.execute(
    "SELECT salt FROM salt WHERE userid = %s",
    (userid,)
)
        salt = cursor.fetchone()[0]
        time_equilizer(start)
        return {
            "nonce": nonce,
            "salt" : salt,
            "request_id" : request_id
            }


@app.post("/storepassword2")
async def store_password2(data: StoredPasswordRequest, request: Request):
    try:
        signature = data.signature
        un = data.username
        password_name = data.password_name
        usernametobestored = data.usernametbs
        enc_data = data.enc_data
        ip = get_client_ip(request)
        if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
        request_id = data.request_id
        signature_bytes = bytes.fromhex(signature)
        data = nonce_db.hgetall(f"post:{un}")
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        row = cursor.fetchone()
        if row is None:
            return {"ERROR": f"Username or password is wrong"}
        user_id = row
        if not data:
            blocker(ip, request_id)
            return {"ERROR": "Session expired"}
        cursor.execute(
        """
        SELECT * FROM users WHERE username = %s""",
        (un,),
        )
        result = cursor.fetchone()
        if not result:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute(
            """
        SELECT hash FROM users WHERE id = %s""",
            (user_id,),
        )
        hash = cursor.fetchone()[0]
        server_signature = hmac.new(
            bytes.fromhex(hash), bytes.fromhex(data["value"]), hashlib.sha256
        ).digest()
        Log_event(sys_logger, "/storepassword2", "INFO", "Server signature generated", f"{un}", f"{ip}", f"{request_id}")
        if not hmac.compare_digest(signature_bytes, server_signature):
            ratelimitin.incr(f"rlpost:{un}")
            Log_event(login_logger, "/storepassword2", "WARNING", "Invalid signature", f"{un}", f"{ip}", f"{request_id}")
            blocker(ip, request_id)
            return {
                "ERROR": f"Username or password is wrong"
            }
        Log_event(login_logger, "/storepassword2", "INFO", "Valid signature", f"{un}", f"{ip}", f"{request_id}")
        
        sys_logger.info(f"base64 encrypted transmitted data was decrypted form base64 at store-password")
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        row = cursor.fetchone()
        if row is None:
            return {"ERROR": f"Username or password is wrong"}
        user_id = row[0]
        cursor.execute(
            "SELECT accountusername FROM stored where userid = %s", (user_id,))
        raw_names = cursor.fetchall()
        names = []
        for name in raw_names:
            names.append(name[0])
        if password_name in names:
            return {"ERROR" : "You have Already stored a password with this name"}
        cursor.execute(
            "INSERT INTO stored (userid,accountusername ,encdata ,servicename) VALUES (%s,  %s, %s, %s)",
            (user_id, usernametobestored ,enc_data ,password_name),
        )
        Log_event(db_logger, "/storepassword2", "INFO", "Password stored", f"{un}", f"{ip}", f"{request_id}")
        conn.commit()
        nonce_db.delete(f"post:{un}")
        ratelimitin.delete(f"rlpost:{un}")
        return {"message": "Password stored successfully"}

    except Exception as e:
        sys_logger.error(f"Error: -{str(e)} occured at store-password")
        return {
            "ERROR": "Something went wrong",
        }



# =========================
# retreving password
# =========================


@app.post("/getenc")
async def get_enc(data: UsernameRequest, request: Request):
    start = time.time()
    username = data.username
    ip = get_client_ip(request)
    if check(ip) == "IP BLOCKED":
        return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
    request_id = uuid.uuid4().hex
    cursor.execute(
        """
    SELECT * FROM users WHERE username = %s""",
        (username,),
    )
    result = cursor.fetchone()
    if not result:
        Log_event(login_logger, "/getenc", "WARNING", "Invalid username entered", f"{username}", f"{ip}", f"{request_id}")
        time_equilizer(start)
        nonce = os.urandom(32).hex()
        salt = os.urandom(32).hex()
        time_equilizer(start)
        return {"nonce" : nonce,
                "salt" : salt,
                "request_id" : request_id}
    else:
        if check(ip) == "IP BLOCKED":
            return "IP BLOCKED, Check after some time"
        if ratelimitin.exists(f"rlpost:{username}"):
            if int(ratelimitin.get(f"rlpost:{username}")) >= 10:
                temp_blocked.set(f"blocked:{username}", "1")
                temp_blocked.expire(f"blocked:{username}", 3600)
                ratelimitin.delete(f"rlpost:{username}")
                Log_event(login_logger, "/getenc", "WARNING", "Rapid requests detected", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "Too many requests, try again in an hour"}
            else:
                pass
            if temp_blocked.exists(f"blocked:{username}"):
                Log_event(login_logger, "/getenc", "CRITICAL", "User blocked", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "You are temporarily blocked, try again after some time"}
            else:
                pass
        else:
            ratelimitin.set(f"rlpost:{username}", "0")
        nonce = os.urandom(32)
        Log_event(sys_logger, "/getenc", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        key = f"get:{username}"
        nonce_db.hset(
            key,
            mapping={
                "value": nonce.hex(),
            },
        )
        Log_event(sys_logger, "/getenc", "INFO", "Temporary nonce stored", f"{username}", f"{ip}", f"{request_id}")
        nonce_db.expire(f"get:{username}", 300)
        sys_logger.info(f"Nonce was generated for user -{username}- at getting-encrpyted-data")
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        userid = cursor.fetchone()[0]
        cursor.execute(
    "SELECT salt FROM salt WHERE userid = %s",
    (userid,)
)
        salt = cursor.fetchone()[0]
        time_equilizer(start)
        return {
            "nonce": nonce.hex(),
            "salt" : salt,
            "request_id" : request_id
            }


@app.post("/getenc2")
async def get_enc2(data: GetEncryptedRequest, request: Request):
    try:
        signature = data.signature
        un = data.username
        password_name = data.password_name
        unS = data.usernameS
        ip = get_client_ip(request)
        if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
        request_id = data.request_id
        signature_bytes = bytes.fromhex(signature)
        data = nonce_db.hgetall(f"get:{un}")

        if not data:
            blocker(ip, request_id)
            return {"ERROR": "Session expired"}
        cursor.execute(
        """
        SELECT * FROM users WHERE username = %s""",
        (un,),
        )
        result = cursor.fetchone()
        if not result:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute(
            """
        SELECT hash FROM users WHERE username = %s""",
            (un,),
        )
        hash = cursor.fetchone()[0]

        server_signature = hmac.new(
            bytes.fromhex(hash), bytes.fromhex(data["value"]), hashlib.sha256
        ).digest()
        Log_event(sys_logger, "/getenc2", "INFO", "Server signature generated", f"{un}", f"{ip}", f"{request_id}")
        if not hmac.compare_digest(signature_bytes, server_signature):
            ratelimitin.incr(f"rlpost:{un}")
            Log_event(login_logger, "/getenc2", "WARNING", "Invalid signature", f"{un}", f"{ip}", f"{request_id}")
            blocker(ip, request_id)
            print(server_signature, signature_bytes)
            return {"ERROR": f"Username or password is wrong"}
        Log_event(login_logger, "/getenc2", "INFO", "Valid signature", f"{un}", f"{ip}", f"{request_id}")
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        row = cursor.fetchone()
        user_id = row
        if row is None:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute(
            """
            SELECT encdata FROM stored WHERE userid = %s AND servicename = %s AND accountusername=%s""",
            (user_id, password_name, unS),
        )
        enc = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT accountusername FROM stored WHERE userid = %s AND servicename = %s""",
            (user_id, password_name),
        )
        username_A = cursor.fetchone()[0]
        nonce_db.delete(f"get:{un}")
        nonce_db.delete(f"post:{un}")
        Log_event(db_logger, "/getenc2", "INFO", "Password retrieved", f"{un}", f"{ip}", f"{request_id}")
        sys_logger.info(f"Encrypted data of User -{un}- was encrypted uaing base64 before transmision at getting-encrpyted-data")
        return {"encdata": enc,
                "username_A": username_A}
    except Exception as e:
        Log_event(db_logger, "/getenc2", "WARNING", "Failed password retrieval", f"{un}", f"{ip}", f"{request_id}")
        sys_logger.error(f"Error: -{str(e)} occured at ")
        return {"ERROR":  f"Something Went Wrong"}

# =========================
# retriving backup
# =========================
@app.post("/login")
async def login(data: UsernameRequest, request: Request):
    start = time.time()
    username = data.username
    ip = get_client_ip(request)
    if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have been blocked for violating policies, Try again later"}
    request_id = uuid.uuid4().hex
    cursor.execute(
        """
    SELECT * FROM users WHERE username = %s""",
        (username,),
    )
    result = cursor.fetchone()
    if not result:
        Log_event(login_logger, "/login", "WARNING", "Invalid username entered", f"{username}", f"{ip}", f"{request_id}")
        time_equilizer(start)
        nonce = os.urandom(32).hex()
        salt = os.urandom(32).hex()
        time_equilizer(start)
        return {"nonce" : nonce,
                "salt" : salt,
                "request_id" : request_id}
    else:
        if check(ip) == "IP BLOCKED":
            return "IP BLOCKED, Check after some time"
        if ratelimitin.exists(f"rlpost:{username}"):
            if int(ratelimitin.get(f"rlpost:{username}")) >= 10:
                temp_blocked.set(f"blocked:{username}", "1")
                temp_blocked.expire(f"blocked:{username}", 3600)
                ratelimitin.delete(f"rlpost:{username}")
                Log_event(login_logger, "/login", "WARNING", "Rapid requests detected", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "Too many requests, try again in an hour"}            
            else:
                pass
        else:
            ratelimitin.set(f"rlpost:{username}", "0")
        nonce = os.urandom(32)
        Log_event(sys_logger, "/login", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        key = f"login:{username}"
        nonce_db.hset(
            key,
            mapping={
                "value": nonce.hex(),
            },
        )
        Log_event(sys_logger, "/login", "INFO", "Temporary nonce stored", f"{username}", f"{ip}", f"{request_id}")
        nonce_db.expire(f"login:{username}", 300)
        sys_logger.info(f"Nonce was generated for user -{username}- at get-backup")
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        userid = cursor.fetchone()[0]
        cursor.execute(
    "SELECT salt FROM salt WHERE userid = %s",
    (userid,)
)
        salt = cursor.fetchone()[0]
        time_equilizer(start)
        return {
            "nonce": nonce.hex(),
            "salt": salt,
            "request_id": request_id
                }


@app.post("/login2")
async def login2(data: GetBackupRequest, request: Request):
    try:
        signature = data.signature
        un = data.username
        user_otp = data.otp
        ip = get_client_ip(request)
        check(ip)
        request_id = data.request_id
        if check(ip) == "IP BLOCKED":
            return "IP BLOCKED, Check after some time"
        signature_bytes = bytes.fromhex(signature)
        data = nonce_db.hgetall(f"login:{un}")

        if not data:
            blocker(ip, request_id)
            return {"ERROR": "Username or password is wrong"}
        cursor.execute(
        """
        SELECT * FROM users WHERE username = %s""",
        (un,),
        )
        result = cursor.fetchone()
        if not result:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute(
            """
        SELECT hash FROM users WHERE username = %s""",
            (un,),)
        hash = cursor.fetchone()[0]
        server_signature = hmac.new(
           bytes.fromhex(hash), bytes.fromhex(data["value"]), hashlib.sha256
        ).digest()
        print(bytes.fromhex(data["value"]))
        print(hash.encode())
        print(server_signature)
        Log_event(sys_logger, "/login2", "INFO", "Server signature generated", f"{un}", f"{ip}", f"{request_id}")
        if not hmac.compare_digest(signature_bytes, server_signature):
            ratelimitin.incr(f"rlpost:{un}")
            Log_event(login_logger, "/login2", "WARNING", "Invalid signature", f"{un}", f"{ip}", f"{request_id}")
            blocker(ip, request_id)
            return {"ERROR": f"Username or password is wrong"}
        Log_event(login_logger, "/login2", "INFO", "Valid signature", f"{un}", f"{ip}", f"{request_id}")
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        user_id = cursor.fetchone()[0]
        cursor.execute("SELECT salt FROM salt WHERE userid = %s", (user_id,))
        nonce_db.delete(f"list:{un}")
        nonce_db.delete(f"post:{un}")
        cursor.execute("SELECT enabled FROM twofa WHERE userid = %s", (user_id,))
        otp_status = cursor.fetchone()

        if otp_status:
            status = otp_generation_and_verfication(un, user_otp)
            if status == "VALID":
                Log_event(otp_logger, "/login2", "INFO", "OTP verified", f"{un}", f"{ip}", f"{request_id}")
                pass
            else:
                blocker(ip, request_id)
                Log_event(otp_logger, "/login2", "WARNING", "Invalid OTP entered", f"{un}", f"{ip}", f"{request_id}")
                return {"ERROR" : "Wrong OTP"}
            cursor.execute("SELECT salt FROM salt WHERE userid = %s", (user_id,))
            
            db_logger.info(f"Backup Data was given of user {un}")
        return {"Status": "Valid"}
    except Exception as e:
        sys_logger.error(f"Error: -{str(e)} occured at get-backup")
        return {"ERROR": "Something went wrong"}


@app.post("/list")
async def list(data: UsernameRequest, request: Request):
    start = time.time()
    username = data.username
    ip = get_client_ip(request)
    if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
    request_id = uuid.uuid4().hex
    cursor.execute(
        """
    SELECT * FROM users WHERE username = %s""",
        (username,),
    )
    result = cursor.fetchone()
    if not result:
        Log_event(login_logger, "/list", "WARNING", "Invalid username entered", f"{username}", f"{ip}", f"{request_id}")
        time_equilizer(start)
        nonce = os.urandom(32).hex()
        salt = os.urandom(32).hex()
        time_equilizer(start)
        return {"nonce" : nonce,
                "salt" : salt,
                "request_id" : request_id}
    else:
        if check(ip) == "IP BLOCKED":
            return "IP BLOCKED, Check after some time"
        if ratelimitin.exists(f"rlpost:{username}"):
            if int(ratelimitin.get(f"rlpost:{username}")) >= 10:
                temp_blocked.set(f"blocked:{username}", "1")
                temp_blocked.expire(f"blocked:{username}", 3600)
                ratelimitin.delete(f"rlpost:{username}")
                Log_event(login_logger, "/list", "WARNING", "Rapid requests detected", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "Too many requests, try again in an hour"}            
            else:
                pass
        else:
            ratelimitin.set(f"rlpost:{username}", "0")
        nonce = os.urandom(32)
        Log_event(sys_logger, "/list", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        key = f"list:{username}"
        nonce_db.hset(
            key,
            mapping={
                "value": nonce.hex(),
            },
        )
        Log_event(sys_logger, "/list", "INFO", "Temporary nonce stored", f"{username}", f"{ip}", f"{request_id}")
        nonce_db.expire(f"list:{username}", 300)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        userid = cursor.fetchone()[0]
        cursor.execute(
    "SELECT salt FROM salt WHERE userid = %s",
    (userid,))
        salt = cursor.fetchone()[0]
        time_equilizer(start)
        return {
            "nonce": nonce.hex(),
            "salt": salt,
            "request_id": request_id 
                }

@app.post("/list2")
async def list2(data: ListPasswordRequest, request: Request):
    try:
        signature = data.signature
        un = data.username
        ip = get_client_ip(request)
        check(ip)
        request_id = data.request_id
        if check(ip) == "IP BLOCKED":
            return "IP BLOCKED, Check after some time"
        signature_bytes = bytes.fromhex(signature)
        data = nonce_db.hgetall(f"list:{un}")
        if not data:
            blocker(ip, request_id)
            return {"ERROR": "Session expired"}
        cursor.execute(
        """
        SELECT * FROM users WHERE username = %s""",
        (un,),
        )
        result = cursor.fetchone()
        if not result:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        userid = cursor.fetchone()[0]
        cursor.execute(
            """
        SELECT hash FROM users WHERE id = %s;""",
            (userid,),
        )
        hash = cursor.fetchone()[0]
        data = nonce_db.hgetall(f"list:{un}")
        server_signature = hmac.new(
            bytes.fromhex(hash), bytes.fromhex(data["value"]), hashlib.sha256).digest()
        Log_event(sys_logger, "/list2", "INFO", "Server signature generated", f"{un}", f"{ip}", f"{request_id}")
        if not hmac.compare_digest(signature_bytes, server_signature):
            ratelimitin.incr(f"rlpost:{un}")
            Log_event(login_logger, "/list2", "WARNING", "Invalid signature", f"{un}", f"{ip}", f"{request_id}")
            blocker(ip, request_id)
            return {"ERROR": f"Username or password is wrong"}
        Log_event(login_logger, "/list2", "INFO", "Valid signature", f"{un}", f"{ip}", f"{request_id}")
        cursor.execute("""
        SELECT servicename, accountusername FROM stored WHERE userid=%s;
        """,
        (userid,),
        )
        rows = cursor.fetchall()
        passwords = []

        for service, username in rows:
            passwords.append({
                "service": service,
                "username": username
            })

        nonce_db.delete(f"list:{un}")
        return {
            "passwords": passwords
        }
    except Exception as e:
        Log_event(sys_logger, "/list2", "ERROR", f"""{str(e)}""", f"{un}", f"{ip}", f"{request_id}")
        return {"ERROR": "Something Went Wrong"}
    

@app.post("/delete")
async def delete_password(data: UsernameRequest, request: Request):
    start = time.time()
    username = data.username
    ip = get_client_ip(request)
    if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
    request_id = uuid.uuid4().hex
    cursor.execute(
        """
    SELECT * FROM users WHERE username = %s""",
        (username,),
    )
    result = cursor.fetchone()
    if not result:
        Log_event(login_logger, "/delete_password", "WARNING", "Invalid username entered", f"{username}", f"{ip}", f"{request_id}")
        time_equilizer(start)
        nonce = os.urandom(32).hex()
        salt = os.urandom(32).hex()
        time_equilizer(start)
        return {"nonce" : nonce,
                "salt" : salt,
                "request_id" : request_id}
    else:
        if check(ip) == "IP BLOCKED":
            return "IP BLOCKED, Check after some time"
        if ratelimitin.exists(f"rlpost:{username}"):
            if int(ratelimitin.get(f"rlpost:{username}")) >= 10:
                temp_blocked.set(f"blocked:{username}", "1")
                temp_blocked.expire(f"blocked:{username}", 3600)
                ratelimitin.delete(f"rlpost:{username}")
                Log_event(login_logger, "/delete_password", "WARNING", "Rapid requests detected", f"{username}", f"{ip}", f"{request_id}")
                return {"ERROR": "Too many requests, try again in an hour"}            
            else:
                pass
        else:
            ratelimitin.set(f"rlpost:{username}", "0")
        nonce = os.urandom(32)
        Log_event(sys_logger, "/delete_password", "INFO", "Nonce generated", f"{username}", f"{ip}", f"{request_id}")
        key = f"delete:{username}"
        nonce_db.hset(
            key,
            mapping={
                "value": nonce.hex(),
            },
        )
        Log_event(sys_logger, "/delete_password", "INFO", "Temporary nonce stored", f"{username}", f"{ip}", f"{request_id}")
        nonce_db.expire(f"delete:{username}", 300)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        userid = cursor.fetchone()[0]
        cursor.execute(
    "SELECT salt FROM salt WHERE userid = %s",
    (userid,))
        salt = cursor.fetchone()[0]
        time_equilizer(start)
        return {
            "nonce": nonce.hex(),
            "salt": salt,
            "request_id": request_id
            }
@app.post("/delete2")
async def delete_password2(data: DeletePasswordRequest2, request: Request):
    try:
        signature = data.signature
        un = data.username
        password_name = data.password_name
        unS = data.usernameS
        ip = get_client_ip(request)
        if check(ip) == "IP BLOCKED":
            return {"ERROR" : "You have benn blocked for violating policies, Try again later"}
        request_id = data.request_id
        signature_bytes = bytes.fromhex(signature)
        data = nonce_db.hgetall(f"delete:{un}")

        if not data:
            blocker(ip, request_id)
            return {"ERROR": "Session expired"}
        cursor.execute(
        """
        SELECT * FROM users WHERE username = %s""",
        (un,),
        )
        result = cursor.fetchone()
        if not result:
            return {"ERROR": f"Username or password is wrong"}
        cursor.execute(
            """
        SELECT hash FROM users WHERE username = %s""",
            (un,),)
        hash = cursor.fetchone()[0]
        server_signature = hmac.new(
           bytes.fromhex(hash), bytes.fromhex(data["value"]), hashlib.sha256).digest()
        Log_event(sys_logger, "/delete2", "INFO", "Server signature generated", f"{un}", f"{ip}", f"{request_id}")
        if not hmac.compare_digest(signature_bytes, server_signature):
            ratelimitin.incr(f"rlpost:{un}")
            Log_event(login_logger, "/delete2", "WARNING", "Invalid signature", f"{un}", f"{ip}", f"{request_id}")
            blocker(ip, request_id)
            return {"ERROR": f"Username or password is wrong"}
        Log_event(login_logger, "/delete2", "INFO", "Valid signature", f"{un}", f"{ip}", f"{request_id}")
        cursor.execute("SELECT id FROM users WHERE username = %s", (un,))
        row = cursor.fetchone()
        if row is None:
            return {"ERROR": f"Username or password is wrong"}
        user_id = row[0]
        cursor.execute(
            """
            DELETE FROM stored WHERE userid = %s AND servicename = %s AND accountusername=%s""",
            (user_id, password_name, unS),
        )
        Log_event(db_logger, "/delete2", "INFO", "Password deleted", f"{un}", f"{ip}", f"{request_id}")
        conn.commit()
        nonce_db.delete(f"delete:{un}")
        return {"message": "Password deleted successfully"}
    except Exception as e:
        Log_event(sys_logger, "/delete2", "ERROR", f"""{str(e)}""", f"{un}", f"{ip}", f"{request_id}")
        return {"ERROR": "Something Went Wrong"}
