from flask import Flask, request, jsonify
import base64
import json
import os
import time
import uuid
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

users = {}
sessions = {}

rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public = rsa_private.public_key()

public_pem = rsa_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")


def b64e(b):
    return base64.b64encode(b).decode("utf-8")


def b64d(s):
    return base64.b64decode(s.encode("utf-8"))


def hash_password(password, salt):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return dk.hex()


def derive_hmac_key(aes_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"messenger-hmac-key",
    )
    return hkdf.derive(aes_key)


def get_session():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    sid = auth.split(" ", 1)[1].strip()
    return sessions.get(sid)


@app.get("/")
def home():
    return jsonify({"ok": True, "message": "server running"})


@app.get("/public-key")
def public_key():
    return jsonify({"public_key_pem": public_pem})


@app.post("/register")
def register():
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if username in users:
        return jsonify({"error": "user already exists"}), 400

    salt = os.urandom(16)
    users[username] = {
        "salt_hex": salt.hex(),
        "pw_hash_hex": hash_password(password, salt),
    }
    return jsonify({"ok": True, "message": "registered"})


@app.post("/handshake")
def handshake():
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    enc_aes_key_b64 = str(data.get("enc_aes_key_b64", ""))

    if username not in users:
        return jsonify({"error": "invalid credentials"}), 401

    salt = bytes.fromhex(users[username]["salt_hex"])
    expected = users[username]["pw_hash_hex"]
    if hash_password(password, salt) != expected:
        return jsonify({"error": "invalid credentials"}), 401

    try:
        enc = b64d(enc_aes_key_b64)
        aes_key = rsa_private.decrypt(
            enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        return jsonify({"error": "failed to decrypt session key"}), 400

    if len(aes_key) != 32:
        return jsonify({"error": "AES key must be 32 bytes"}), 400

    sid = str(uuid.uuid4())
    sessions[sid] = {
        "username": username,
        "aes_key": aes_key,
        "hmac_key": derive_hmac_key(aes_key),
        "created_at": time.time(),
    }

    return jsonify({"ok": True, "session_id": sid})


@app.post("/message")
def message():
    sess = get_session()
    if not sess:
        return jsonify({"error": "missing or invalid session"}), 401

    data = request.get_json(force=True)
    nonce_b64 = str(data.get("nonce_b64", ""))
    ciphertext_b64 = str(data.get("ciphertext_b64", ""))
    timestamp = str(data.get("timestamp", ""))
    hmac_b64 = str(data.get("hmac_b64", ""))

    if not nonce_b64 or not ciphertext_b64 or not timestamp or not hmac_b64:
        return jsonify({"error": "missing fields"}), 400

    try:
        nonce = b64d(nonce_b64)
        ciphertext = b64d(ciphertext_b64)
        recv_mac = b64d(hmac_b64)
    except Exception:
        return jsonify({"error": "bad base64"}), 400

    try:
        ts = float(timestamp)
    except ValueError:
        return jsonify({"error": "bad timestamp"}), 400

    if abs(time.time() - ts) > 120:
        return jsonify({"error": "timestamp outside allowed window"}), 400

    mac_data = nonce + ciphertext + timestamp.encode("utf-8") + sess["username"].encode("utf-8")
    expected_mac = hmac.new(sess["hmac_key"], mac_data, hashlib.sha256).digest()

    if not hmac.compare_digest(recv_mac, expected_mac):
        return jsonify({"error": "HMAC failed, message was changed"}), 400

    try:
        aesgcm = AESGCM(sess["aes_key"])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        student_obj = json.loads(plaintext.decode("utf-8"))
    except Exception:
        return jsonify({"error": "decrypt or JSON parse failed"}), 400

    msg_text = str(student_obj.get("message", ""))

    anomaly_flag = False
    reasons = []

    if len(msg_text) > 400:
        anomaly_flag = True
        reasons.append("message too long")

    bad_words = ["attack", "exploit", "drop table", "malware"]
    lower = msg_text.lower()
    for w in bad_words:
        if w in lower:
            anomaly_flag = True
            reasons.append("suspicious word: " + w)

    return jsonify({
        "ok": True,
        "from": sess["username"],
        "student": student_obj,
        "anomaly_flag": anomaly_flag,
        "anomaly_reasons": reasons
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, ssl_context="adhoc")
