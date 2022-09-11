# auth0 sample Flask impl

## What is this ?

Auth0 authentification flow illustrated with Flask. It consists of a client regular web app' + a backend API that verifies the JWTs issued while logging in from the client app' in order to protect some of its endpoints.

## How to run

You need to do a `docker compose up` inside both api and client folders. The API will be available on port 81 while the client app' will be available on port 80.
