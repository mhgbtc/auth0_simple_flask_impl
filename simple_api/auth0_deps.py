from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
import json
from os import environ as env
from urllib.request import urlopen

AUTH0_ALGOS = ["RS256"]


# auth0 error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# helper function to format error response and append status code
def get_bearer_auth_token():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)
    parts = auth.split()
    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)
    token = parts[1]
    return token


def requires_permission(permission, payload):
    """Determines if the required permission is present
        in the Access Token (our payload)
    Args:
        permission (str): The permission required to access the resource
    """
    if "permissions" not in payload:
        raise AuthError({"code": "no_permissions",
                        "description": "no permissions key in access token"},
                        401)
    if permission not in payload["permissions"]:
        raise AuthError({"code": "no_req_permission",
                        "description": "you don't have the permission"
                         + " to perform this action"},
                        403)
    return True


# individual routes can be configured to look
# for a particular scope in the Access Token
# using this helper function
def requires_scope(required_scope):
    """Determines if the required scope is present in the Access Token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_bearer_auth_token()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False


# decorator
def validates_auth0_jwt_token(f):
    """Determines if the Access Token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_bearer_auth_token()
        # getting auth0 public key to be able to check the signature of our JWT
        jsonurl = urlopen(
            "https://"+env.get("AUTH0_DOMAIN")+"/.well-known/jwks.json"
        )
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=AUTH0_ALGOS,
                    audience=env.get("AUTH0_AUDIENCE"),
                    issuer="https://"+env.get("AUTH0_DOMAIN")+"/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({
                    "code": "invalid_claims",
                    "description":
                    "incorrect claims,"
                    + "please check the audience and issuer"
                }, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)
            # pushing the payload to the ctx stack will allow us
            # to get the decoded payload back in our controllers
            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"},
                        401)
    return decorated
