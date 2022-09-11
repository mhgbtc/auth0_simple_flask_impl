from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# auth0 init logic
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)


# when visitors to your app visit the /login route,
# they'll be redirected to Auth0 to begin the authentication flow
@app.route("/login")
def login():
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/authorize?audience=http://localhost&response_type=token&client_id="
        + env.get("AUTH0_CLIENT_ID")
        + "&redirect_uri=http://localhost/"
        # scopes define the specific actions applications can be allowed to do
        # on a user's behalf
        + "&scope=read:test"
    )


# this route handles signing a user out from your application,
# it will clear the user's session in your app,
# and briefly redirect to Auth0's logout endpoint
# to ensure their session is completely clear,
# before they are returned to your home route
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


# your home route will serve as a place to either
# render an authenticated user's details,
# or offer to allow visitors to sign in
@app.route("/")
def home():
    return render_template(
        "home.html"
    )


if __name__ == "__main__":
    app.run()
