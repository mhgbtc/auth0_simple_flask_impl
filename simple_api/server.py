from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, _request_ctx_stack
from flask_cors import cross_origin
from os import environ as env

from auth0_deps import (
    AuthError,
    requires_permission,
    requires_scope,
    validates_auth0_jwt_token
)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# This doesn't need authentication
@app.route("/api/public")
@cross_origin(headers=["Content-Type"])
def public():
    return jsonify({
        "msg": "public endpoint that does not require authentication"
    })


# This needs authentication
@app.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@validates_auth0_jwt_token
def private():
    return jsonify({
        "msg": "auth protected endpoint that requires authentication",
        "data": _request_ctx_stack.top.current_user
    })


# This needs authorization and a given scope
@app.route("/api/private-scoped")
@cross_origin(headers=["Content-Type", "Authorization"])
@validates_auth0_jwt_token
def private_scoped():
    if requires_scope("read:test"):
        return jsonify({
            "msg": "auth protected endpoint that requires authorization",
            "data": _request_ctx_stack.top.current_user
        })
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)


# This needs authorization and a given permission
@app.route("/api/private-permission")
@cross_origin(headers=["Content-Type", "Authorization"])
@validates_auth0_jwt_token
def private_permission():
    if requires_scope("read:test"):
        usrPayload = _request_ctx_stack.top.current_user
        # checking the permission claim in the JWT
        # will raise an auth error and abort the request if fails
        requires_permission("create:test", usrPayload)
        return jsonify({
            "msg": "auth protected endpoint that requires authorization",
            "data": _request_ctx_stack.top.current_user
        })
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)


if __name__ == "__main__":
    app.run()
