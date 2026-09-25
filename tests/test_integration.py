"""Integration tests: the plugin loaded by a real Radicale application."""

import base64
import sys
import wsgiref.util
from io import BytesIO

import pytest

from radicale import app

from conftest import load_configuration

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"
ALICE_CALENDAR = "/alice@example.com/Réunions équipe/"

EVENT = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Modoboa//Tests//EN
BEGIN:VEVENT
UID:{uid}
DTSTAMP:20260925T090000Z
DTSTART:20260925T100000Z
DTEND:20260925T110000Z
SUMMARY:Meeting
END:VEVENT
END:VCALENDAR
"""


@pytest.fixture
def application(api, tmp_path):
    configuration = load_configuration(
        extra={
            # Short delay on denied requests to keep tests fast
            "auth": {"type": "none", "delay": "0.001"},
            "storage": {
                "filesystem_folder": str(tmp_path),
                "_filesystem_fsync": "False",
            },
        }
    )
    return app.Application(configuration)


def request(application, method, path, login, data=None):
    """Send a request as login and return the status code."""
    environ = {
        "REQUEST_METHOD": method,
        # Already percent-decoded, as done by WSGI servers
        "PATH_INFO": path,
        "HTTP_AUTHORIZATION": "Basic "
        + base64.b64encode(f"{login}:password".encode()).decode(),
        "wsgi.errors": sys.stderr,
    }
    if data is not None:
        body = data.encode()
        environ["wsgi.input"] = BytesIO(body)
        environ["CONTENT_LENGTH"] = str(len(body))
    wsgiref.util.setup_testing_defaults(environ)
    status = None

    def start_response(status_, headers):
        nonlocal status
        status = int(status_.split()[0])

    list(application(environ, start_response))
    return status


def put_event(application, login, uid, calendar=ALICE_CALENDAR):
    return request(
        application, "PUT", f"{calendar}{uid}.ics", login, EVENT.format(uid=uid)
    )


@pytest.fixture
def alice_calendar(application):
    assert request(application, "MKCALENDAR", ALICE_CALENDAR, ALICE) == 201
    assert put_event(application, ALICE, "first") == 201


def test_owner_manages_his_calendar(application, alice_calendar):
    assert request(application, "GET", f"{ALICE_CALENDAR}first.ics", ALICE) == 200
    assert request(application, "DELETE", ALICE_CALENDAR, ALICE) == 200


def test_user_without_share_is_denied(application, api, alice_calendar):
    assert request(application, "GET", f"{ALICE_CALENDAR}first.ics", BOB) == 403
    assert put_event(application, BOB, "second") == 403


def test_read_only_share(application, api, alice_calendar):
    api.grants[BOB] = {"shares": {"alice@example.com/Réunions équipe": "r"}}
    assert request(application, "GET", f"{ALICE_CALENDAR}first.ics", BOB) == 200
    assert request(application, "PROPFIND", ALICE_CALENDAR, BOB) == 207
    assert put_event(application, BOB, "second") == 403
    assert request(application, "DELETE", f"{ALICE_CALENDAR}first.ics", BOB) == 403


def test_read_write_share(application, api, alice_calendar):
    api.grants[BOB] = {"shares": {"alice@example.com/Réunions équipe": "rwd"}}
    assert put_event(application, BOB, "second") == 201
    assert request(application, "DELETE", f"{ALICE_CALENDAR}first.ics", BOB) == 200
    # The calendar itself cannot be deleted by the grantee
    assert request(application, "DELETE", ALICE_CALENDAR, BOB) == 403
    assert request(application, "GET", f"{ALICE_CALENDAR}second.ics", ALICE) == 200


def test_grantee_cannot_create_calendars_in_owner_principal(
    application, api, alice_calendar
):
    api.grants[BOB] = {"shares": {"alice@example.com/Réunions équipe": "rwd"}}
    assert request(application, "MKCALENDAR", "/alice@example.com/Other/", BOB) == 403


def test_domain_shared_calendar(application, api):
    api.grants["admin"] = {"managed_domains": ["*"]}
    # The domain collection must exist before its first calendar
    assert request(application, "MKCOL", "/example.com/", "admin") == 201
    assert request(application, "MKCALENDAR", "/example.com/Team/", "admin") == 201
    assert put_event(application, CAROL, "team", "/example.com/Team/") == 201
    assert request(application, "DELETE", "/example.com/Team/", CAROL) == 403
    assert request(application, "MKCOL", "/example.com/Other/", CAROL) == 403
    assert (
        request(application, "GET", "/example.com/Team/team.ics", "dave@other.org")
        == 403
    )


def test_domain_collection_cannot_be_created_by_members(application, api):
    assert request(application, "MKCOL", "/example.com/", BOB) == 403
