import os.path
import time
import uuid
from functools import lru_cache

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _fromStringOrFile(val, fn):
    if type(val) is bytes:
        return fn(val)
    if os.path.isfile(val):
        with open(val, "rb") as f:
            return fn(f.read())
    if type(val) is str:
        return fn(val.encode("utf-8"))


@lru_cache(maxsize=8)
def privateFromPem(pem, password=None):
    return _fromStringOrFile(
        pem, lambda v: serialization.load_pem_private_key(v, password=password)
    )


@lru_cache(maxsize=8)
def publicFromPem(pem):
    return _fromStringOrFile(pem, serialization.load_pem_public_key)


def publicFromPrivate(priv_key):
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def keyPassword():
    return str(uuid.uuid4()).encode("utf-8")


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
