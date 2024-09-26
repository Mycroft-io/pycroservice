import re
from functools import wraps
from os import environ as ENV

import jwt
from flask import Blueprint, Flask, Response, jsonify, redirect, request
from flask_cors import CORS


def pycroservice(app_name, static_url_path=None, blueprints=None):
    if blueprints is None:
        blueprints = []
    app = Flask(app_name, static_url_path=static_url_path)
    for bloop in blueprints:
        if type(bloop) is Blueprint:
            app.register_blueprint(bloop)
        elif type(bloop) is tuple and len(bloop) == 2:
            app.register_blueprint(bloop[1], url_prefix=bloop[0])
        else:
            raise Exception(f"Invalid blueprint: {bloop}")
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


def makeRequireParamWrapper(param_name, new_param_name, transform_func):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if param_name not in kwargs:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": f"Missing required parameter: {param_name}",
                        }
                    ),
                    400,
                )
            transformed = transform_func(kwargs[param_name])
            kwargs.pop(param_name)
            kwargs[new_param_name] = transformed
            return func(*args, **kwargs)

        return wrapper

    return decorator


def makeRequireTokenWrapper(token_key, new_param_name, transform_func):
    """Note that this wrapper depends on the loggedInHandler wrapper
    or equivalent and assumes that token is passed as the first argument
    into the resulting wrapped function.
    This means that you have to call it like

        requireExample = makeRequireTokenWrapper(["foo", "bar"], "baz", bazFromBar)
        ...
        @loggedInHandler()
        @requireExample
        def mumble(token, baz):
          ...

    AND NOT

       ...
       @requireExample
       @loggedInHandler()
       def mumble(token, baz):
         ...

    The latter will give you errors about how it didn't get a `token` argument.
    """
    assert type(token_key) in {str, list}

    def decorator(func):
        @wraps(func)
        def wrapper(token, *args, **kwargs):
            if isinstance(token_key, str):
                keys = [token_key]
            elif isinstance(token_key, list):
                keys = token_key

            value = token
            for k in keys:
                value = value.get(k)
                if value is None:
                    return jsonify({"status": "nope"}), 400
            transformed = transform_func(value)
            kwargs[new_param_name] = transformed

            return func(token, *args, **kwargs)

        return wrapper

    return decorator
