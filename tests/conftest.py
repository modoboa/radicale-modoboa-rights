"""Test fixtures."""

import pytest
import requests

from radicale import config

import radicale_modoboa_rights

ENDPOINT = "https://modoboa.test/api/v2/calendar-rights/"

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


class FakeApi:
    """Stand-in for the Modoboa rights endpoint."""

    def __init__(self):
        self.grants = {}
        self.calls = []
        self.error = None

    def post(self, session, url, json=None, timeout=None, **kwargs):
        self.calls.append({"url": url, "json": json, "auth": session.auth})
        if self.error is not None:
            if isinstance(self.error, Exception):
                raise self.error
            return self.error
        return FakeResponse(data=self.grants.get(json["user"], {}))

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
