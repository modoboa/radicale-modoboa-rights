"""Unit tests of the rights plugin."""

import pytest
import requests

from conftest import ENDPOINT, TOKEN_ENDPOINT, FakeResponse

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@other.org"
ALICE_CALENDAR = "/alice@example.com/Work/"


def test_anonymous_user_has_no_access(make_rights, api):
    rights = make_rights()
    assert rights.authorization("", "/") == ""
    assert rights.authorization("", ALICE_CALENDAR) == ""
    assert not api.calls


def test_root_is_readable(make_rights, api):
    rights = make_rights()
    assert rights.authorization(ALICE, "/") == "R"
    assert not api.calls


def test_owner_access_is_local(make_rights, api):
    rights = make_rights()
    assert rights.authorization(ALICE, "/alice@example.com/") == "RW"
    assert rights.authorization(ALICE, ALICE_CALENDAR) == "rw"
    assert not api.calls


def test_items_rely_on_parent_collection(make_rights, api):
    rights = make_rights()
    assert rights.authorization(ALICE, "/alice@example.com/Work/event.ics") == ""
    assert not api.calls


def test_domain_members_access_domain_calendars_locally(make_rights, api):
    rights = make_rights()
    assert rights.authorization(BOB, "/example.com/Team/") == "rwd"
    assert not api.calls


def test_domain_principal_is_not_granted_to_members(make_rights, api):
    rights = make_rights()
    assert rights.authorization(BOB, "/example.com/") == ""


def test_other_domain_members_have_no_access_to_domain_calendars(make_rights, api):
    rights = make_rights()
    assert rights.authorization(CAROL, "/example.com/Team/") == ""
    assert api.calls_for(CAROL)


def test_requests_sent_to_modoboa(make_rights, api):
    rights = make_rights()
    rights.authorization(BOB, ALICE_CALENDAR)
    assert api.token_calls == [
        {"data": {"grant_type": "client_credentials"}, "auth": ("radicale", "secret")}
    ]
    assert api.calls == [
        {"url": ENDPOINT, "json": {"user": BOB}, "authorization": "Bearer token-1"}
    ]


@pytest.mark.parametrize("permissions", ["r", "rwd"])
def test_shared_calendar(make_rights, api, permissions):
    api.grants[BOB] = {"shares": {"alice@example.com/Work": permissions}}
    rights = make_rights()
    assert rights.authorization(BOB, ALICE_CALENDAR) == permissions
    assert rights.authorization(BOB, "/alice@example.com/Private/") == ""
    assert rights.authorization(BOB, "/alice@example.com/") == ""


def test_shared_calendar_with_special_characters(make_rights, api):
    api.grants[BOB] = {"shares": {"alice@example.com/Réunions équipe": "r"}}
    rights = make_rights()
    assert rights.authorization(BOB, "/alice@example.com/Réunions équipe/") == "r"


def test_invalid_share_permissions_are_ignored(make_rights, api):
    api.grants[BOB] = {
        "shares": {
            "alice@example.com/Work": "RrWw",
            "alice@example.com/Home": "r",
        }
    }
    rights = make_rights()
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    assert rights.authorization(BOB, "/alice@example.com/Home/") == "r"


def test_superadmin(make_rights, api):
    api.grants["admin"] = {"admin_domains": ["*"], "managed_domains": ["*"]}
    rights = make_rights()
    assert rights.authorization("admin", "/alice@example.com/") == "R"
    assert rights.authorization("admin", ALICE_CALENDAR) == "rw"
    assert rights.authorization("admin", "/example.com/") == "RW"
    assert rights.authorization("admin", "/example.com/Team/") == "rw"
    assert rights.authorization("admin", "/admin/") == "RW"


def test_superadmin_without_calendars_administration(make_rights, api):
    api.grants["admin"] = {"managed_domains": ["*"]}
    rights = make_rights()
    assert rights.authorization("admin", "/alice@example.com/") == ""
    assert rights.authorization("admin", ALICE_CALENDAR) == ""
    assert rights.authorization("admin", "/example.com/Team/") == "rw"


def test_domain_admin(make_rights, api):
    api.grants[BOB] = {"admin_domains": ["example.com"]}
    rights = make_rights()
    assert rights.authorization(BOB, "/alice@example.com/") == "R"
    assert rights.authorization(BOB, ALICE_CALENDAR) == "rw"
    assert rights.authorization(BOB, "/carol@other.org/") == ""
    assert rights.authorization(BOB, "/carol@other.org/Work/") == ""
    assert rights.authorization(BOB, "/other.org/Team/") == ""


def test_domain_calendars_manager(make_rights, api):
    api.grants[CAROL] = {"managed_domains": ["example.com"]}
    rights = make_rights()
    assert rights.authorization(CAROL, "/example.com/") == "RW"
    assert rights.authorization(CAROL, "/example.com/Team/") == "rw"
    assert rights.authorization(CAROL, "/test.org/") == ""
    assert rights.authorization(CAROL, "/test.org/Team/") == ""
    # Managing shared calendars does not give access to user calendars
    assert rights.authorization(CAROL, ALICE_CALENDAR) == ""


def test_grants_are_cached(make_rights, api, clock):
    api.grants[BOB] = {"shares": {"alice@example.com/Work": "r"}}
    rights = make_rights()
    for _ in range(3):
        assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    assert len(api.calls) == 1


def test_grants_are_refreshed_after_cache_ttl(make_rights, api, clock):
    api.grants[BOB] = {"shares": {"alice@example.com/Work": "r"}}
    rights = make_rights(modoboa_rights_cache_ttl="60")
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    # Share revoked
    api.grants[BOB] = {}
    clock.now += 59
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    clock.now += 2
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""


def test_denied_access_refreshes_grants(make_rights, api, clock):
    rights = make_rights(modoboa_rights_refresh_interval="5")
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    assert len(api.calls) == 1
    # New share: not visible before the refresh interval...
    api.grants[BOB] = {"shares": {"alice@example.com/Work": "r"}}
    clock.now += 3
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    assert len(api.calls) == 1
    # ...but visible right after, without waiting for the cache TTL
    clock.now += 3
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    assert len(api.calls) == 2


def test_denied_accesses_do_not_flood_api(make_rights, api, clock):
    rights = make_rights()
    for index in range(20):
        rights.authorization(BOB, f"/alice@example.com/Calendar{index}/")
    assert len(api.calls) == 1


def test_grants_are_per_user(make_rights, api, clock):
    api.grants[BOB] = {"shares": {"alice@example.com/Work": "r"}}
    rights = make_rights()
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    assert rights.authorization(CAROL, ALICE_CALENDAR) == ""


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError("unreachable"),
        requests.Timeout("timeout"),
        FakeResponse(status_code=500),
        FakeResponse(status_code=401),
        FakeResponse(status_code=403),
        FakeResponse(status_code=404),
        FakeResponse(data=ValueError("not JSON")),
        FakeResponse(data=["not", "an", "object"]),
        FakeResponse(data={"admin_domains": "example.com"}),
        FakeResponse(data={"managed_domains": [1]}),
        FakeResponse(data={"shares": []}),
    ],
)
def test_api_failure_denies_access(make_rights, api, error):
    api.error = error
    rights = make_rights()
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    # Owner access does not depend on the API
    assert rights.authorization(BOB, "/bob@example.com/Work/") == "rw"


def test_stale_grants_are_used_when_api_is_down(make_rights, api, clock):
    api.grants[BOB] = {"shares": {"alice@example.com/Work": "r"}}
    rights = make_rights(
        modoboa_rights_cache_ttl="60",
        modoboa_rights_stale_max_age="3600",
        modoboa_rights_retry_delay="0",
    )
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    api.error = requests.ConnectionError("unreachable")
    clock.now += 120
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    clock.now += 3600
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""


def test_api_is_not_called_during_retry_delay(make_rights, api, clock):
    api.error = requests.ConnectionError("unreachable")
    rights = make_rights(modoboa_rights_retry_delay="10")
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    assert rights.authorization(CAROL, ALICE_CALENDAR) == ""
    assert len(api.calls) == 1
    api.error = None
    api.grants[CAROL] = {"shares": {"alice@example.com/Work": "r"}}
    clock.now += 11
    assert rights.authorization(CAROL, ALICE_CALENDAR) == "r"
    assert len(api.calls) == 2


def test_expired_entries_are_purged(make_rights, api, clock):
    rights = make_rights(
        modoboa_rights_cache_ttl="60", modoboa_rights_stale_max_age="3600"
    )
    rights.authorization(BOB, ALICE_CALENDAR)
    clock.now += 4000
    rights.authorization(CAROL, ALICE_CALENDAR)
    assert list(rights._cache) == [CAROL]


@pytest.mark.parametrize(
    "option",
    ["modoboa_rights_endpoint", "modoboa_client_id", "modoboa_client_secret"],
)
def test_required_options(make_rights, option):
    with pytest.raises(RuntimeError, match=option):
        make_rights(**{option: ""})


@pytest.mark.parametrize("value", ["abc", "-1"])
def test_invalid_number_option(make_rights, value):
    with pytest.raises(RuntimeError, match="modoboa_rights_cache_ttl"):
        make_rights(modoboa_rights_cache_ttl=value)


def test_access_token_is_reused(make_rights, api, clock):
    rights = make_rights()
    for user in [BOB, CAROL, "dave@example.com"]:
        rights.authorization(user, ALICE_CALENDAR)
    assert len(api.calls) == 3
    assert len(api.token_calls) == 1


def test_access_token_is_renewed_before_expiration(make_rights, api, clock):
    api.token_expires_in = 60
    rights = make_rights()
    rights.authorization(BOB, ALICE_CALENDAR)
    # Renewed 30 seconds before its expiration
    clock.now += 29
    rights.authorization(CAROL, ALICE_CALENDAR)
    assert len(api.token_calls) == 1
    clock.now += 2
    rights.authorization("dave@example.com", ALICE_CALENDAR)
    assert len(api.token_calls) == 2
    assert api.calls[-1]["authorization"] == "Bearer token-2"


def test_refused_access_token_is_renewed(make_rights, api, clock):
    api.grants[BOB] = {"shares": {"alice@example.com/Work": "r"}}
    rights = make_rights()
    rights.authorization(CAROL, ALICE_CALENDAR)
    api.revoke_tokens()
    assert rights.authorization(BOB, ALICE_CALENDAR) == "r"
    assert len(api.token_calls) == 2
    assert [call["authorization"] for call in api.calls_for(BOB)] == [
        "Bearer token-1",
        "Bearer token-2",
    ]


def test_access_token_is_renewed_only_once(make_rights, api):
    # e.g. the rights endpoint does not accept the application's tokens
    api.error = FakeResponse(status_code=401)
    rights = make_rights()
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    assert len(api.calls) == 2
    assert len(api.token_calls) == 2


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError("unreachable"),
        FakeResponse(status_code=401),
        FakeResponse(data=ValueError("not JSON")),
        FakeResponse(data={"token_type": "Bearer"}),
        FakeResponse(data={"access_token": ""}),
        FakeResponse(data={"access_token": "token", "expires_in": "soon"}),
        FakeResponse(data=["not", "an", "object"]),
    ],
)
def test_token_failure_denies_access(make_rights, api, error):
    api.token_error = error
    rights = make_rights(modoboa_rights_retry_delay="10")
    assert rights.authorization(BOB, ALICE_CALENDAR) == ""
    assert rights.authorization(CAROL, ALICE_CALENDAR) == ""
    assert not api.calls
    # No new attempt during the retry delay
    assert len(api.token_calls) == 1


def test_access_token_without_expiration(make_rights, api, clock):
    api.token_expires_in = None
    rights = make_rights()
    rights.authorization(BOB, ALICE_CALENDAR)
    clock.now += 200
    rights.authorization(CAROL, ALICE_CALENDAR)
    assert len(api.token_calls) == 1


def test_client_credentials_are_form_encoded(make_rights, api):
    rights = make_rights(modoboa_client_id="radi cale", modoboa_client_secret="a+b:c")
    rights.authorization(BOB, ALICE_CALENDAR)
    assert api.token_calls[0]["auth"] == ("radi+cale", "a%2Bb%3Ac")


def test_token_endpoint_option(make_rights, api):
    rights = make_rights(modoboa_token_endpoint="https://sso.test/token/")
    assert rights._token_endpoint == "https://sso.test/token/"
    rights = make_rights()
    assert rights._token_endpoint == TOKEN_ENDPOINT
