import re
from functools import wraps
from os import environ as ENV

import jwt
from flask import Blueprint, Flask, Response, jsonify, redirect, request
from flask_cors import CORS

from . import rsa, util


def pycroservice(app_name, static_url_path=None, static_folder=None, blueprints=None):
    if blueprints is None:
        blueprints = []
    app = Flask(app_name, static_url_path=static_url_path, static_folder=static_folder)
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


def getPubKey():
    if "JWT_DECODE_KEY" in ENV:
        return rsa.publicFromPem(ENV["JWT_DECODE_KEY"])
    elif "JWT_SECRET" in ENV:
        return rsa.publicFromPrivate(rsa.privateFromPem(ENV["JWT_SECRET"]))
    raise Exception("pycroservice.core.decodeJwt: no-pubkey-provided")


def encodeJwt(payload, private_key=None, issuer=None, expires_in=None):
    if issuer is None:
        issuer = ENV["JWT_ISSUER"]
    if private_key is None:
        private_key = rsa.privateFromPem(ENV["JWT_SECRET"])
    return rsa.encodeJwt(payload, private_key, ENV["JWT_ISSUER"], expires_in=expires_in)


def decodeJwt(token, pub_key=None, issuer=None):
    if pub_key is None:
        pub_key = getPubKey()
    if issuer is None:
        issuer = ENV["JWT_ISSUER"]
    try:
        return jwt.decode(
            token, pub_key, issuer=issuer, algorithms=["RS256", "HS512", "HS256"]
        )
    except jwt.PyJWTError as e:
        print(f"ERROR: {e}")
        return None


def _reqTok(request):
    token = request.headers.get("authorization")
    if token:
        token = re.sub("^Bearer ", "", token)
        return decodeJwt(token)


def jsonError(message, status_code, details=None):
    res = {"status": "error", "message": message}
    if details is not None:
        res["details"] = details
    return jsonify(res), status_code


def hasScope(token, scope, org_id):
    return {"scope": scope, "org_id": org_id} in token["user"]["scopes"]


def _scope_check(token, scopes, params, allow_invited=False):
    if scopes is None:
        return True, None

    status_filter = {"deactivated"} if allow_invited else {"deactivated", "invited"}
    user_scopes = {
        f"{s['scope']}:org({s['org_id']})" if s["org_id"] else s["scope"]
        for s in token["user"]["scopes"] if s["status"] not in status_filter
    }

    if "godlike" in user_scopes:
        return True, None

    user_global_scopes = {
        s["scope"] for s in token["user"]["scopes"] if util.is_global_scope(s["scope"])
    }

    if user_global_scopes.intersection(scopes):
        return True, None

    if "org_id" in params:
        org_id = params["org_id"]
        if f"org_admin:org({org_id})" in user_scopes:
            return True, None
        if {f"{s}:org({org_id})" for s in scopes}.intersection(user_scopes):
            return True, None
        return False, "no org permissions"

    return False, "you're weird"


def loggedInHandler(
    required=None,
    optional=None,
    scopes=None,
    check=None,
    ignore_password_change=False,
    ignore_mfa_check=False,
    allow_invited=False,
):
    if required is None:
        required = []
    if optional is None:
        optional = []

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = _reqTok(request)

            if token is None:
                return jsonError("Token is missing", 401)

            for param in required:
                value = reqVal(request, param)
                if value is None:
                    return jsonError("No value found", 400)
                kwargs[param] = value

            scopes_passed, reason = _scope_check(
                token, scopes, kwargs, allow_invited=allow_invited
            )
            if not scopes_passed:
                return jsonError(reason, 403)

            if token["user"]["require_password_change"]:
                if not ignore_password_change:
                    return jsonError("you must change your password", 403)

            if token["user"]["mfa_enabled"] and not token.get("mfa_verified"):
                if not ignore_mfa_check:
                    return jsonError("you must verify your MFA", 403)

            for param in optional:
                value = reqVal(request, param)
                kwargs[param] = value

            if (check is not None) and (not check(token, kwargs)):
                return jsonError("check failed", 403, details={"check": check.__name__})

            return func(token, *args, **kwargs)

        return wrapper

    return decorator


def _assoc(val, keys, default=None):
    if isinstance(keys, str):
        ks = [keys]
    elif isinstance(keys, list):
        ks = keys

    value = val
    for k in ks:
        if k not in value:
            return default
        value = value[k]

    return value


def makeTokenOrParamWrapper(
    transform_func,
    new_param_name,
    from_params=None,
    from_token=None,
    required=False,
    prefer_token=False,
):
    """Note that this wrapper depends on the loggedInHandler wrapper
    or equivalent and assumes that token is passed as the first argument
    into the resulting wrapped function.
    This means that you have to call it like

        requireExample = makeTokenOrParamWrapper(bazFromBar, "baz", from_token=["foo", "bar"])
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
    assert from_token is None or (type(from_token) in {str, list})
    assert from_params is None or (type(from_params) is str)
    assert from_params or from_token

    def decorator(func):
        @wraps(func)
        def wrapper(token, *args, **kwargs):
            v_from_tok = None
            if from_token is not None:
                v_from_tok = _assoc(token, from_token)
            v_from_params = None
            if from_params is not None:
                v_from_params = kwargs.get(from_params)
            if prefer_token:
                v = v_from_tok or v_from_params
            else:
                v = v_from_params or v_from_tok
            if required and (v is None):
                return jsonError(f"failed to find `{new_param_name}`", 400)
            transformed = transform_func(v_from_tok or v_from_params)
            if (from_params is not None) and (from_params in kwargs):
                kwargs.pop(from_params)
            kwargs[new_param_name] = transformed
            return func(token, *args, **kwargs)

        return wrapper

    return decorator
