import aiohttp
import jwcrypto.jwk as jwk
import python_jwt as jwt
from jwcrypto.jws import InvalidJWSSignature
from urllib.parse import quote_plus

try:
    import ujson as json
except ImportError:
    import json


class JustAuthenticateMeError(BaseException):
    pass


class JAMBadRequest(JustAuthenticateMeError):
    pass


class JAMNotFound(JustAuthenticateMeError):
    pass


class JAMNotVerified(JustAuthenticateMeError):
    pass


class JAMUnauthorized(JustAuthenticateMeError):
    pass


class JustAuthenticateMe:
    def __init__(self, app_id):
        self.app_id = app_id
        self.base_url = f"https://api.justauthenticate.me/{self.app_id}/"
        self._jwk = None

    async def authenticate(self, email):
        """Initialize authentication flow for a user given an email address.

        :param email: email of the user
        :returns: None
        :raises JAMBadRequest: When a 400 bad request is received from
        justauthenticate.me
        :raises JAMNotFound: When a 404 not found is received back from
        justauthenticate.me
        """
        async with aiohttp.ClientSession(json_serialize=json.dumps) as session:
            async with session.post(
                self.base_url + "authenticate", json={"email": email}
            ) as response:
                if response.status == 200:
                    return
                data = await response.json()
                if response.status == 400:
                    raise JAMBadRequest(data["message"])
                if response.status == 404:
                    raise JAMNotFound(data["message"])
                raise JustAuthenticateMeError("Unknown Error")

    async def jwk(self):
        if self._jwk:
            return self._jwk
        async with aiohttp.ClientSession(json_serialize=json.dumps) as session:
            async with session.get(self.base_url + ".well-known/jwks.json") as response:
                data = await response.json()
                if response.status == 200:
                    key = data["keys"][0]
                    self._jwk = jwk.JWK(**key)
                    return self._jwk
                if response.status == 404:
                    raise JAMNotFound(data["message"])
                raise JustAuthenticateMeError("Unknown Error")

    async def verify_token(self, token):
        """Verify a JustAuthenticateMe token against jwks.
        :param token: idToken (jwt) from JustAuthenticateMe
        :returns headers, claims: headers and claims encoded in the user jwt
        :raises JAMNotVerified: if verification fails on a token
        """
        try:
            return jwt.verify_jwt(token, await self.jwk(), ["ES512"])
        except InvalidJWSSignature:
            raise JAMNotVerified()
        except Exception:
            raise JustAuthenticateMeError("Unknown Error")

    async def refresh(self, refresh_token: str):
        """Refresh id tokens with refresh token
        :param refresh_token: user's refreshToken from JustAuthenticateMe

        :returns: new idToken (JWT) from JustAuthenticateMe
        :raises JAMBadRequest: when app doesn't allow refresh or request is malformed.
        :raises JAMInvalid: refresh token was invalid
        :raises JAMNotFound: appId or refresh token was not found
        """
        async with aiohttp.ClientSession(json_serialize=json.dumps) as session:
            async with session.post(
                self.base_url + "refresh", json={"refreshToken": refresh_token}
            ) as response:
                data = await response.json()
                if response.status == 200:
                    return data["idToken"]
                if response.status == 400:
                    raise JAMBadRequest(data["message"])
                if response.status == 401:
                    raise JAMUnauthorized("Refresh token was invalid or expired")
                if response.status == 404:
                    raise JAMNotFound(data["message"])
                raise JustAuthenticateMeError("Unknown Error")

    async def delete_refresh_token(self, id_token: str, refresh_token: str):
        """Delete a user's refresh token.
        :param id_token: User's id token (JWT) from Just Authenticate Me
        :param refresh_token: The refresh token to delete
        :returns: None
        :raises JAMUnauthorized: when the id_token is invalid
        :raises JAMNotFound: when the refresh_token or app_id cannot be found
        """
        async with aiohttp.ClientSession() as session:
            async with session.delete(
                self.base_url + f"user/refresh/{quote_plus(refresh_token)}",
                headers={"Authorization": f"Bearer {id_token}"},
            ) as response:
                if response.status == 204:
                    return
                if response.status == 401:
                    raise JAMUnauthorized("ID token is invalid")
                if response.status == 404:
                    data = await response.json()
                    raise JAMNotFound(data["message"])
                raise JustAuthenticateMeError("Unknown Error")

    async def delete_all_refresh_tokens(self, id_token: str):
        """Delete all of a user's refresh tokens (log out everywhere).
        :param id_token: A users's id token (JWT) from Just Authenticate Me
        :returns: None
        :raises JAMUnauthorized: when the id token is invalid
        """
        async with aiohttp.ClientSession() as session:
            async with session.delete(
                self.base_url + "user/refresh",
                headers={"Authorization": f"Bearer {id_token}"}
            ) as response:
                if response.status == 204:
                    return
                if response.status == 401:
                    raise JAMUnauthorized("ID token is invalid")
                raise JustAuthenticateMeError("Unknown Error")
