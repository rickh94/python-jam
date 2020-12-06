import aiohttp
import jwcrypto.jwk as jwk
import python_jwt as jwt
from jwcrypto.jws import InvalidJWSSignature

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
                elif response.status == 404:
                    raise JAMNotFound(data["message"])
                else:
                    raise JustAuthenticateMeError(f"Unknown Error")

    async def jwk(self):
        if self._jwk:
            return self._jwk
        async with aiohttp.ClientSession(json_serialize=json.dumps) as session:
            async with session.get(self.base_url + ".well-known/jwks.json") as response:
                data = await response.json()
                if response.status == 200:
                    key = data['keys'][0]
                    self._jwk = jwk.JWK(**key)
                    return self._jwk
                elif response.status == 404:
                    raise JAMNotFound(data["message"])

    async def verify_token(self, token):
        print(self.jwk)
        try:
            return jwt.verify_jwt(token, await self.jwk(), ['ES512'])
        except InvalidJWSSignature:
            raise JAMNotVerified()
