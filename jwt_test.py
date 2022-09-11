from jwt import decode, encode

secret = 'learning'

# init the data
payload = {'school': 'udacity'}
algo = 'HS256'  # HMAC-SHA 256

# encode a JWT
encoded_jwt = encode(payload, secret)
print(encoded_jwt)

# decode a JWT
decoded_jwt = decode(
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"  # header
    + ".eyJwYXJrIjoidW5pb24gc3F1YXJlIn0"  # payload
    + ".N3EaAHsrJ9-ls82LT8JoFTNpDK3wcm5a79vYkSn8AFY",  # signature
    secret,
    algorithms=['HS256']
)
print(decoded_jwt)
