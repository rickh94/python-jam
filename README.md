# python_jam

[![Build Status](https://travis-ci.org/rickh94/python-jam.svg?branch=main)](https://travis-ci.org/rickh94/python-jam)

An asynchronous python implementation
of [Just Authenticate Me](https://justauthenticate.me)'s REST Api.

# Installation

Install normally from pypi.org:

`pip install python-jam`

It depends on [aiohttp](https://github.com/aio-libs/aiohttp), so if aiohttp is installed
with extras or speedups, those will be used automatically. It will also
use [ujson](https://github.com/ultrajson/ultrajson) for serialization if installed. (
Defaults to build-in json)

## Basic Usage

Create the JustAuthenticateMe object by supplying the AppId from you Just Authenticate
Me app, then call the corresponding functions as needed. The primary ones are in the
example below.

```python
from python_jam import (
    JustAuthenticateMe, JAMUnauthorized, JAMBadRequest,
    JAMNotVerified
)

jam = JustAuthenticateMe('APP_ID')

try:
    await jam.authenticate('user@example.com')
except JAMBadRequest as e:
    print("Something went wrong", e)

try:
    headers, claims = await jam.verify_token('user_id_token')
except JAMNotVerified:
    print("Unauthorized, invalid token")

try:
    new_token = await jam.refresh('user_refresh_token')
except JAMBadRequest as e:
    print("Refresh not allowed", e)
except JAMUnauthorized:
    print("invalid refresh token")
```

## Available Methods

These are the methods available on a JustAuthenticateMe instance. All Exception inherit
from `JustAuthenticateMeError`. This is also the exception raised by an unexpected
error. If the JustAuthenticateMe api returns a message with the error, that is passed
through as exception text.

- `jam.authenticate(email)` - Initialize authentication flow for a user given an email
  address. Returns `None` on success. Raises `JAMBadRequest` when a 400 bad request is
  received from justauthenticate.me (usually an invalid email) or `JAMNotFound` When a
  404 not found is received back from justauthenticate.me

- `jam.verify_token(id_token)` - Verify a JustAuthenticateMe token against jwks (loaded
  lazily). Call with parameter `id_token` (jwt) from JustAuthenticateMe.
  Returns `headers, claims`: headers and claims encoded in the user jwt. (passed through
  from [python-jwt](https://github.com/davedoesdev/python-jwt)) or
  raises `JAMNotVerified` if verification fails on a token.

- `jam.refresh(refresh_token)` - Refresh id tokens with refresh token. `refresh_token`:
  user's refreshToken from JustAuthenticateMe. Returns: new idToken (JWT) from
  JustAuthenticateMe. Raises `JAMBadRequest` when app doesn't allow refresh or request
  is malformed. Raises `JAMInvalid` when the refresh token was invalid. Raises
  `JAMNotFound` when the appId or refresh token was not found.

- `jam.delete_refresh_token(id_token, refresh_token)` - Delete a user's refresh token.
  (i.e. logout) Called with `id_token`: User's id token (JWT) from Just Authenticate Me,
  and `refresh_token`: The refresh token to delete. Returns `None` or
  raises `JAMUnauthorized` when the id_token is invalid or
  `JAMNotFound` when the refresh_token or app_id cannot be found

- `jam.delete_all_refresh_tokens(id_token)` - Delete all of a user's refresh tokens.
  (i.e. logout) Called with `id_token`: User's id token (JWT) from Just Authenticate Me.
  Returns `None` or raises `JAMUnauthorized` when the id_token is invalid.
