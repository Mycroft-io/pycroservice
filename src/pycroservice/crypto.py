import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def keyPassword():
    return str(uuid.uuid4()).encode("utf-8")


def fromPem(pem, password=None):
    return serialization.load_pem_private_key(pem, password=password)


def generate(key_size=8192, password=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if password is None:
        cryp = serialization.NoEncryption()
    else:
        cryp = serialization.BestAvailableEncryption(password=password)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=cryp,
    )


def pubKey(priv_key):
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def encodeJwt(payload, priv_key, issuer, expires_in=None):
    if expires_in is None:
        expires_in = 60 * 60
    iat = int(time.time())
    exp = int(iat + expires_in)
    return jwt.encode(
        {**payload, **{"iss": issuer, "iat": iat, "exp": exp}},
        priv_key,
        algorithm="RS256",
    )


def decodeJwt(token, pub_key, issuer):
    try:
        return jwt.decode(token, pub_key, issuer=issuer, algorithms=["RS256"])
    except jwt.PyJWTError:
        return None
