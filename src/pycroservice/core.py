import types
from functools import wraps
from os import environ as ENV

from flask import Blueprint, Flask, Response, jsonify, redirect, request
from flask_cors import CORS
from propelauth_flask import current_user, init_auth

from . import util

auth = init_auth(ENV["PROPELAUTH_URL"], ENV["PROPELAUTH_API_KEY"])


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


def jsonError(message, status_code, details=None):
    res = {"status": "error", "message": message}
    if details is not None:
        res["details"] = details
    return jsonify(res), status_code


def loggedInHandler(
    required=None,
    optional=None,
    scopes=None,
    check=None,
    ignore_password_change=False,
    ignore_mfa_check=False,
):
    if required is None:
        required = []
    if optional is None:
        optional = []

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for param in required:
                value = reqVal(request, param)
                if value is None:
                    return jsonError("No value found", 400)
                kwargs[param] = value

            if not current_user.exists():
                return jsonError("unauthenticated", 403)

            if "org_id" in kwargs:
                org_id = kwargs["org_id"]
                has_some_permissions = False
                for s in scopes:
                    if current_user.user.has_permission_in_org(org_id, s):
                        has_some_permissions = True
                if not has_some_permissions:
                    return jsonError("user lacks permissions", 403)
            else:
                ## TODO - it looks like `orgs/list` and `orgs/register` are the only
                ##        two handlers outside of auth that currently don't require an org_id
                ##        (and IIRC, it's because we wanted to be able to generate dev data)
                ##        If that's true, we can just remove this part of the  handler and
                ##        force org_id across the board.
                pass

            for param in optional:
                value = reqVal(request, param)
                kwargs[param] = value

            return func(current_user.user, *args, **kwargs)

        return wrapper

    return decorator


def makeUserOrParamWrapper(
    transform_func,
    new_param_name,
    from_params=None,
    from_user=None,
    required=False,
    prefer_user=False,
):
    """Note that this wrapper depends on the loggedInHandler wrapper
    or equivalent and assumes that user is passed as the first argument
    into the resulting wrapped function.
    This means that you have to call it like

        requireExample = makeUserOrParamWrapper(bazFromBar, "baz", from_user=lambda u: u.foo.bar)
        ...
        @loggedInHandler()
        @requireExample
        def mumble(user, baz):
          ...

    AND NOT

       ...
       @requireExample
       @loggedInHandler()
       def mumble(user, baz):
         ...

    The latter will give you errors about how it didn't get a `user` argument.
    """
    assert from_user is None or (type(from_user) is types.FunctionType)
    assert from_params is None or (type(from_params) is str)
    assert from_params or from_user

    def decorator(func):
        @wraps(func)
        def wrapper(user, *args, **kwargs):
            v_from_usr = None
            if from_user is not None:
                v_from_usr = from_user(user)
            v_from_params = None
            if from_params is not None:
                v_from_params = kwargs.get(from_params)
            if prefer_user:
                v = v_from_usr or v_from_params
            else:
                v = v_from_params or v_from_usr
            if required and (v is None):
                return jsonError(f"failed to find `{new_param_name}`", 400)
            transformed = transform_func(v_from_usr or v_from_params)
            if (from_params is not None) and (from_params in kwargs):
                kwargs.pop(from_params)
            kwargs[new_param_name] = transformed
            return func(user, *args, **kwargs)

        return wrapper

    return decorator
