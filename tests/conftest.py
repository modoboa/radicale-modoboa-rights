"""Test fixtures."""

import pytest
import requests

from radicale import config

import radicale_modoboa_rights

ENDPOINT = "https://modoboa.test/api/v2/calendar-rights/"
TOKEN_ENDPOINT = "https://modoboa.test/api/o/token/"

BASE_RIGHTS_OPTIONS = {
    "type": "radicale_modoboa_rights",
    "modoboa_rights_endpoint": ENDPOINT,
    "modoboa_client_id": "radicale",
    "modoboa_client_secret": "secret",
}


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


def fail(error):
    if isinstance(error, Exception):
        raise error
    return error


class FakeApi:
    """Stand-in for the Modoboa token and rights endpoints."""

    def __init__(self):
        self.grants = {}
        # Calls to the rights endpoint
        self.calls = []
        self.error = None
        # Calls to the token endpoint
        self.token_calls = []
        self.token_error = None
        self.token_expires_in = 3600
        self.valid_tokens = set()

    def post(self, session, url, json=None, data=None, headers=None, auth=None, **kw):
        if url == TOKEN_ENDPOINT:
            return self.post_token(data, auth)
        authorization = (headers or {}).get("Authorization")
        self.calls.append({"url": url, "json": json, "authorization": authorization})
        if self.error is not None:
            return fail(self.error)
        if authorization not in {f"Bearer {token}" for token in self.valid_tokens}:
            return FakeResponse(status_code=401)
        return FakeResponse(data=self.grants.get(json["user"], {}))

    def post_token(self, data, auth):
        self.token_calls.append({"data": data, "auth": auth})
        if self.token_error is not None:
            return fail(self.token_error)
        token = f"token-{len(self.token_calls)}"
        self.valid_tokens.add(token)
        return FakeResponse(
            data={
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": self.token_expires_in,
            }
        )

    def revoke_tokens(self):
        self.valid_tokens.clear()

    def calls_for(self, user):
        return [call for call in self.calls if call["json"]["user"] == user]


class FakeTime:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


@pytest.fixture
def api(monkeypatch):
    fake = FakeApi()
    monkeypatch.setattr(
        requests.Session,
        "post",
        lambda session, url, **kwargs: fake.post(session, url, **kwargs),
    )
    return fake


@pytest.fixture
def clock(monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(radicale_modoboa_rights, "time", fake)
    return fake


def load_configuration(rights_options=None, extra=None):
    configuration = config.load()
    values = {"rights": {**BASE_RIGHTS_OPTIONS, **(rights_options or {})}}
    values.update(extra or {})
    configuration.update(values, "test", privileged=True)
    return configuration


@pytest.fixture
def make_rights():
    def _make_rights(**options):
        return radicale_modoboa_rights.Rights(load_configuration(options))

    return _make_rights
