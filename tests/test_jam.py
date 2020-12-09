import pytest
from aioresponses import aioresponses
from jwcrypto.jws import InvalidJWSSignature

from python_jam import (
    JustAuthenticateMe,
    JAMBadRequest,
    JAMNotFound,
    JustAuthenticateMeError,
    JAMNotVerified,
)


@pytest.fixture
def mock_aioresponse():
    with aioresponses() as m:
        yield m


@pytest.fixture
def jam():
    return JustAuthenticateMe("test-app-id")


def test_create_class():
    jam = JustAuthenticateMe("test-app-id")
    assert jam.app_id == "test-app-id"
    assert jam.base_url == "https://api.justauthenticate.me/test-app-id/"


@pytest.mark.asyncio
async def test_authenticate_success(mock_aioresponse, jam):
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate", status=200,
    )
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate", status=200,
    )

    await jam.authenticate("test@example.com")
    await jam.authenticate("test2@example.com")

    request_args = [
        item.kwargs["json"] for item in list(mock_aioresponse.requests.values())[0]
    ]
    assert {"email": "test@example.com"} in request_args
    assert {"email": "test2@example.com"} in request_args


@pytest.mark.asyncio
async def test_authenticate_bad_request(mock_aioresponse, jam):
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate",
        status=400,
        payload={"message": "invalid email"},
    )
    with pytest.raises(JAMBadRequest) as einfo:
        await jam.authenticate("failure")
    assert str(einfo.value) == "invalid email"


@pytest.mark.asyncio
async def test_authenticate_not_found(mock_aioresponse, jam):
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate",
        status=404,
        payload={"message": "App not found"},
    )
    with pytest.raises(JAMNotFound) as einfo:
        await jam.authenticate("test@example.com")
    assert str(einfo.value) == "App not found"


@pytest.mark.asyncio
async def test_authenticate_other_error(mock_aioresponse, jam):
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate",
        status=500,
        payload={"message": "Internal server error"},
    )
    with pytest.raises(JustAuthenticateMeError) as einfo:
        await jam.authenticate("test@example.com")

    assert str(einfo.value) == "Unknown Error"


@pytest.mark.asyncio
async def test_get_jwks(mock_aioresponse, jam, mocker):
    mock_aioresponse.get(
        "https://api.justauthenticate.me/test-app-id/.well-known/jwks.json",
        status=200,
        payload={"keys": [{"key_info": "info"}]},
    )
    mock_jwk = mocker.patch("jwcrypto.jwk.JWK", return_value="mock_jwk_return_value")
    jwk = await jam.jwk()

    assert jwk == "mock_jwk_return_value"
    assert jam._jwk == "mock_jwk_return_value"
    mock_jwk.assert_called_with(key_info="info")


@pytest.mark.asyncio
async def test_get_jwks_error(mock_aioresponse, jam, mocker):
    mock_aioresponse.get(
        "https://api.justauthenticate.me/test-app-id/.well-known/jwks.json",
        status=404,
        payload={"message": "app not found"},
    )
    mock_jwk = mocker.patch("jwcrypto.jwk.JWK", return_value="mock_jwk_return_value")
    with pytest.raises(JAMNotFound) as einfo:
        await jam.jwk()

    assert str(einfo.value) == "app not found"
    mock_jwk.assert_not_called()


@pytest.mark.asyncio
async def test_get_jwks_generic_error(mock_aioresponse, jam, mocker):
    mock_aioresponse.get(
        "https://api.justauthenticate.me/test-app-id/.well-known/jwks.json",
        status=500,
        payload={"message": "app not found"},
    )
    mock_jwk = mocker.patch("jwcrypto.jwk.JWK", return_value="mock_jwk_return_value")
    with pytest.raises(JustAuthenticateMeError) as einfo:
        await jam.jwk()

    assert str(einfo.value) == "Unknown Error"
    mock_jwk.assert_not_called()


@pytest.mark.asyncio
async def test_get_jwks_lazily(mock_aioresponse, jam):
    mock_aioresponse.get(
        "https://api.justauthenticate.me/test-app-id/.well-known/jwks.json",
        exception=Exception("Should not have been called"),
    )
    jam._jwk = "test_jwk"
    jwk = await jam.jwk()

    assert jwk == "test_jwk"


@pytest.mark.asyncio
async def test_verify_token(mocker, jam):
    mock_verify = mocker.patch(
        "python_jwt.verify_jwt", return_value=("headers", "claims")
    )
    jam._jwk = "fake_jwk"
    headers, claims = await jam.verify_token("test-token")

    assert headers == "headers"
    assert claims == "claims"
    mock_verify.assert_called_with("test-token", "fake_jwk", ["ES512"])


@pytest.mark.asyncio
async def test_verify_token_fails(monkeypatch, jam):
    jam._jwk = "fake_jwk"

    def _fail_verify(*args):
        raise InvalidJWSSignature()

    monkeypatch.setattr("python_jwt.verify_jwt", _fail_verify)

    with pytest.raises(JAMNotVerified):
        await jam.verify_token("invalid-token")


@pytest.mark.asyncio
async def test_verify_token_fails_unexpected(monkeypatch, jam):
    jam._jwk = "fake_jwk"

    def _fail_verify(*args):
        raise Exception("Something weird happened")

    monkeypatch.setattr("python_jwt.verify_jwt", _fail_verify)

    with pytest.raises(JustAuthenticateMeError) as einfo:
        await jam.verify_token("invalid-token")

    assert str(einfo.value) == "Unknown Error"
