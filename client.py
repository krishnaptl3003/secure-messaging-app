import base64
import json
import os
import time
import hmac
import hashlib
from dataclasses import dataclass, asdict

import urllib3
import requests

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER = "https://127.0.0.1:5000"


def b64e(b):
    return base64.b64encode(b).decode("utf-8")


def b64d(s):
    return base64.b64decode(s.encode("utf-8"))


@dataclass
class Student:
    student_id: str
    name: str
    email: str
    major: str
    message: str
    timestamp: float


def derive_hmac_key(aes_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"messenger-hmac-key",
    )
    return hkdf.derive(aes_key)


def main():
    print("Secure Messaging Client")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    r = requests.post(
        SERVER + "/register",
        json={"username": username, "password": password},
        verify=False
    )
    if r.status_code == 200:
        print("Registered")
    else:
        try:
            print("Register:", r.json().get("error", "ok"))
        except Exception:
            print("Register:", r.text)

    pk = requests.get(SERVER + "/public-key", verify=False).json()["public_key_pem"]
    public_key = serialization.load_pem_public_key(pk.encode("utf-8"))

    aes_key = AESGCM.generate_key(bit_length=256)

    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    hs = requests.post(
        SERVER + "/handshake",
        json={
            "username": username,
            "password": password,
            "enc_aes_key_b64": b64e(enc_key),
        },
        verify=False
    )
    if hs.status_code != 200:
        print("Handshake failed:", hs.text)
        return

    session_id = hs.json()["session_id"]
    print("Session ready:", session_id)

    msg = input("Message: ").strip()

    student = Student(
        student_id="916687297",
        name="Krishna Patel",
        email="krishnaptl@gmail.com",
        major="Computer Science",
        message=msg,
        timestamp=time.time(),
    )

    student_json_bytes = json.dumps(asdict(student)).encode("utf-8")

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, student_json_bytes, None)

    hmac_key = derive_hmac_key(aes_key)
    ts_str = str(student.timestamp)

    mac_data = nonce + ciphertext + ts_str.encode("utf-8") + username.encode("utf-8")
    mac = hmac.new(hmac_key, mac_data, hashlib.sha256).digest()

    payload = {
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ciphertext),
        "timestamp": ts_str,
        "hmac_b64": b64e(mac),
    }

    headers = {"Authorization": "Bearer " + session_id}
    resp = requests.post(
        SERVER + "/message",
        json=payload,
        headers=headers,
        verify=False
    )

    print("Server status:", resp.status_code)
    try:
        print(json.dumps(resp.json(), indent=2))
    except Exception:
        print(resp.text)


if __name__ == "__main__":
    main()
