import pytest
from aioresponses import aioresponses

from python_jam import (
    JustAuthenticateMe, JAMBadRequest, JAMNotFound,
    JustAuthenticateMeError,
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
    with pytest.raises(JAMBadRequest):
        await jam.authenticate("failure")


@pytest.mark.asyncio
async def test_authenticate_not_found(mock_aioresponse, jam):
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate",
        status=404,
        payload={"message": "App not found"},
    )
    with pytest.raises(JAMNotFound):
        await jam.authenticate("test@example.com")

@pytest.mark.asyncio
async def test_authenticate_other_error(mock_aioresponse, jam):
    mock_aioresponse.post(
        "https://api.justauthenticate.me/test-app-id/authenticate",
        status=500,
        payload={"message": "Internal server error"},
    )
    with pytest.raises(JustAuthenticateMeError):
        await jam.authenticate("test@example.com")
