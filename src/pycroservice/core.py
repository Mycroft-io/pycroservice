import re
from functools import wraps
from os import environ as ENV

import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS


def pycroservice(app_name, static_url_path=None):
    app = Flask(app_name, static_url_path=static_url_path)
    CORS(app)
    return app


def reqVal(request, key, default=None):
    res = request.values.get(key)
    if res is not None:
        return res

    if request.is_json:
        return request.json.get(key, default)

    return default


def decodeJwt(token):
    try:
        return jwt.decode(
            token,
            ENV["JWT_SECRET"],
            issuer=ENV["JWT_ISSUER"],
            algorithms=["HS512", "HS256"],
        )
    except jwt.PyJWTError:
        return None


def reqTok(request):
    token = request.headers.get("authorization")
    if token:
        token = re.sub("^Bearer ", "", token)
        return decodeJwt(token)


def loggedInHandler(
    required=None,
    ignore_password_change=False,
    ignore_mfa_check=False,
    token_check=None,
):
    if required is None:
        required = []

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = reqTok(request)

            if token is None:
                return jsonify({"status": "nope"}), 403

            if token_check is not None and not token_check(token):
                return (
                    jsonify({"status": "error", "message": "failed token check"}),
                    403,
                )

            if token["user"]["require_password_change"]:
                if not ignore_password_change:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "you must change your password",
                            }
                        ),
                        403,
                    )

            if token["user"]["mfa_enabled"] and not token.get("mfa_verified"):
                if not ignore_mfa_check:
                    return (
                        jsonify({"status": "error", "message": "verify your MFA"}),
                        403,
                    )

            for param in required:
                value = reqVal(request, param)
                if value is None:
                    return jsonify({"status": "nope"}), 400
                kwargs[param] = value

            return func(token, *args, **kwargs)

        return wrapper

    return decorator
