import pytest
from aioresponses import aioresponses

from python_jam import JustAuthenticateMe


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

    request_args = [item.kwargs['json'] for item in list(mock_aioresponse.requests.values())[0]]
    assert {"email": "test@example.com"} in request_args
    assert {"email": "test2@example.com"} in request_args

