"""Rights plugin for Radicale backed by the Modoboa API."""

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import quote_plus, urljoin

import requests

from radicale import pathutils, rights
from radicale.log import logger

#: Permissions granted to a user on his own principal and calendars
OWNER_PRINCIPAL_PERMISSIONS = "RW"
OWNER_CALENDAR_PERMISSIONS = "rw"

#: Permissions granted to domain members on domain shared calendars.
#: 'd' forbids the deletion of the calendar itself.
DOMAIN_CALENDAR_PERMISSIONS = "rwd"

#: Permissions granted to administrators on user principals and calendars
ADMIN_PRINCIPAL_PERMISSIONS = "R"
ADMIN_CALENDAR_PERMISSIONS = "rw"

#: Permissions granted to managers of domain shared calendars. 'W' on
#: the domain collection allows to create it before its first calendar.
MANAGER_DOMAIN_PERMISSIONS = "RW"
MANAGER_CALENDAR_PERMISSIONS = "rw"

#: Matches any domain in admin_domains and managed_domains
ALL_DOMAINS = "*"

#: Permissions the Modoboa API is allowed to grant on a shared calendar
ALLOWED_SHARE_PERMISSIONS = frozenset("rwdDoOi")

#: Path of Modoboa's OAuth2 token endpoint
TOKEN_ENDPOINT_PATH = "/api/o/token/"

#: Access tokens are renewed this many seconds before they expire
TOKEN_EXPIRY_MARGIN = 30

#: Lifetime assumed for access tokens returned without expires_in
DEFAULT_TOKEN_LIFETIME = 300

#: Default values of optional settings
DEFAULTS = {
    "modoboa_rights_cache_ttl": 60,
    "modoboa_rights_refresh_interval": 5,
    "modoboa_rights_stale_max_age": 3600,
    "modoboa_rights_timeout": 2,
    "modoboa_rights_retry_delay": 10,
}


def get_domain(owner):
    """Return the domain part of a principal name."""
    return owner.rpartition("@")[2]


def is_domain_collection(owner):
    """Check if owner is a domain (shared calendars) and not a user."""
    return "@" not in owner


def get_domain_list(data, key):
    """Return the list of domains stored under key, raise ValueError if invalid."""
    domains = data.get(key, [])
    if not isinstance(domains, list) or not all(
        isinstance(domain, str) for domain in domains
    ):
        raise ValueError(f"'{key}' must be a list of strings")
    return frozenset(domains)


@dataclass(frozen=True)
class Grants:
    """Rights granted to a user on collections owned by someone else.

    admin_domains: domains whose user calendars the user administers
    managed_domains: domains whose shared calendars the user manages
    shares: user calendars shared with the user (path -> permissions)
    """

    admin_domains: frozenset = frozenset()
    managed_domains: frozenset = frozenset()
    shares: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, data):
        """Build grants from a Modoboa API response, raise ValueError if invalid."""
        if not isinstance(data, dict):
            raise ValueError("response must be a JSON object")
        admin_domains = get_domain_list(data, "admin_domains")
        managed_domains = get_domain_list(data, "managed_domains")
        shares = data.get("shares", {})
        if not isinstance(shares, dict):
            raise ValueError("'shares' must be an object")
        valid_shares = {}
        for path, permissions in shares.items():
            if not isinstance(permissions, str) or not set(permissions).issubset(
                ALLOWED_SHARE_PERMISSIONS
            ):
                logger.warning(
                    "Ignoring invalid permissions %r for %r", permissions, path
                )
                continue
            valid_shares[path] = permissions
        return cls(
            admin_domains=admin_domains,
            managed_domains=managed_domains,
            shares=valid_shares,
        )

    def administers(self, owner):
        """Check if these grants give access to the calendars of user owner."""
        return (
            ALL_DOMAINS in self.admin_domains or get_domain(owner) in self.admin_domains
        )

    def manages(self, domain):
        """Check if these grants give access to the shared calendars of domain."""
        return ALL_DOMAINS in self.managed_domains or domain in self.managed_domains

    def principal_permissions(self, owner):
        """Return permissions on the principal collection of owner."""
        if is_domain_collection(owner):
            return MANAGER_DOMAIN_PERMISSIONS if self.manages(owner) else ""
        return ADMIN_PRINCIPAL_PERMISSIONS if self.administers(owner) else ""

    def calendar_permissions(self, owner, path):
        """Return permissions on calendar collection path, owned by owner."""
        if is_domain_collection(owner):
            return MANAGER_CALENDAR_PERMISSIONS if self.manages(owner) else ""
        if self.administers(owner):
            return ADMIN_CALENDAR_PERMISSIONS
        return self.shares.get(path, "")


EMPTY_GRANTS = Grants()


@dataclass(frozen=True)
class CacheEntry:
    fetched_at: float
    grants: Grants


class Rights(rights.BaseRights):
    """
    Rights management based on Modoboa.

    Access to a user's own collections and to domain shared calendars is
    decided locally. Access to collections owned by someone else (shared
    calendars, administrators) is asked to the Modoboa API, and cached.

    Configuration:

    [rights]
    type = radicale_modoboa_rights
    modoboa_rights_endpoint = https://<modoboa>/api/v2/calendar-rights/
    modoboa_client_id = <client id of Radicale's OAuth2 application>
    modoboa_client_secret = <client secret of Radicale's OAuth2 application>
    # Optional, defaults to /api/o/token/ on the host of the rights endpoint
    modoboa_token_endpoint = https://<modoboa>/api/o/token/
    # Optional settings (values in seconds)
    modoboa_rights_cache_ttl = 60
    modoboa_rights_refresh_interval = 5
    modoboa_rights_stale_max_age = 3600
    modoboa_rights_timeout = 2
    modoboa_rights_retry_delay = 10
    """

    def __init__(self, configuration):
        super().__init__(configuration)
        self._endpoint = self._get_required_option("modoboa_rights_endpoint")
        try:
            self._token_endpoint = self.configuration.get(
                "rights", "modoboa_token_endpoint"
            )
        except KeyError:
            self._token_endpoint = urljoin(self._endpoint, TOKEN_ENDPOINT_PATH)
        client_id = self._get_required_option("modoboa_client_id")
        client_secret = self._get_required_option("modoboa_client_secret")
        # Client credentials are form-encoded before HTTP Basic (RFC 6749, 2.3.1)
        self._client_credentials = (quote_plus(client_id), quote_plus(client_secret))
        self._cache_ttl = self._get_number_option("modoboa_rights_cache_ttl")
        self._refresh_interval = self._get_number_option(
            "modoboa_rights_refresh_interval"
        )
        self._stale_max_age = self._get_number_option("modoboa_rights_stale_max_age")
        self._timeout = self._get_number_option("modoboa_rights_timeout")
        self._retry_delay = self._get_number_option("modoboa_rights_retry_delay")
        logger.info(
            "Using Modoboa rights endpoint: %s (token endpoint: %s)",
            self._endpoint,
            self._token_endpoint,
        )
        # Keep the connection to the API alive
        self._session = requests.Session()
        self._access_token = None
        self._access_token_expires_at = 0.0
        self._token_lock = threading.Lock()
        self._cache = {}
        self._lock = threading.Lock()
        self._retry_after = 0.0
        self._last_purge = time.monotonic()

    def _get_required_option(self, name):
        try:
            value = self.configuration.get("rights", name)
        except KeyError:
            raise RuntimeError(f"{name} must be set")
        if not value:
            raise RuntimeError(f"{name} must be set")
        return value

    def _get_number_option(self, name):
        try:
            value = self.configuration.get("rights", name)
        except KeyError:
            return DEFAULTS[name]
        try:
            value = float(value)
        except ValueError:
            raise RuntimeError(f"{name} must be a number")
        if value < 0:
            raise RuntimeError(f"{name} must be positive")
        return value

    def _request_access_token(self):
        """Get a new access token with the client credentials grant."""
        try:
            response = self._session.post(
                self._token_endpoint,
                data={"grant_type": "client_credentials"},
                auth=self._client_credentials,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            logger.error("Modoboa token request failed: %s", exc)
            return None
        if response.status_code != 200:
            logger.error(
                "Modoboa token endpoint returned status %d: check %s, "
                "modoboa_client_id and modoboa_client_secret",
                response.status_code,
                self._token_endpoint,
            )
            return None
        try:
            data = response.json()
            token = data["access_token"]
            expires_in = data.get("expires_in")
            expires_in = (
                DEFAULT_TOKEN_LIFETIME if expires_in is None else float(expires_in)
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            logger.error("Modoboa token endpoint returned invalid data")
            return None
        if not isinstance(token, str) or not token:
            logger.error("Modoboa token endpoint returned invalid data")
            return None
        self._access_token = token
        self._access_token_expires_at = time.monotonic() + max(
            expires_in - TOKEN_EXPIRY_MARGIN, 0
        )
        return token

    def _get_access_token(self):
        """Return a valid access token, None on failure."""
        with self._token_lock:
            if self._access_token and time.monotonic() < self._access_token_expires_at:
                return self._access_token
            return self._request_access_token()

    def _discard_access_token(self, token):
        """Forget token, refused by the API."""
        with self._token_lock:
            if self._access_token == token:
                self._access_token = None

    def _post_rights_request(self, user):
        """Send the rights request, with a new token if the current one is refused."""
        for attempt in range(2):
            token = self._get_access_token()
            if token is None:
                return None
            response = self._session.post(
                self._endpoint,
                json={"user": user},
                headers={"Authorization": f"Bearer {token}"},
                timeout=self._timeout,
            )
            if response.status_code != 401 or attempt:
                return response
            # Token expired or revoked before its expected expiration
            self._discard_access_token(token)
        return response

    def _fetch(self, user):
        """Ask the Modoboa API for the grants of user, None on failure."""
        if time.monotonic() < self._retry_after:
            return None
        try:
            response = self._post_rights_request(user)
        except requests.RequestException as exc:
            logger.error("Modoboa rights request failed: %s", exc)
            return self._fetch_failed()
        if response is None:
            return self._fetch_failed()
        if response.status_code == 404:
            logger.error(
                "Modoboa rights endpoint not found: check %s "
                "(Modoboa 2.11 or later is required)",
                self._endpoint,
            )
            return self._fetch_failed()
        if response.status_code == 403:
            logger.error(
                "Modoboa rights endpoint refused access: modoboa_client_id must "
                "be the client id of the OAuth2 application named Radicale"
            )
            return self._fetch_failed()
        if response.status_code != 200:
            logger.error(
                "Modoboa rights endpoint returned status %d", response.status_code
            )
            return self._fetch_failed()
        try:
            return Grants.from_json(response.json())
        except ValueError as exc:
            logger.error("Modoboa rights endpoint returned invalid data: %s", exc)
            return self._fetch_failed()

    def _fetch_failed(self):
        # Do not make every request wait for the timeout while the API is down
        self._retry_after = time.monotonic() + self._retry_delay
        return None

    def _purge_cache(self, now):
        """Drop entries too old to be used, even as stale ones."""
        if now - self._last_purge < self._cache_ttl:
            return
        self._last_purge = now
        self._cache = {
            user: entry
            for user, entry in self._cache.items()
            if now - entry.fetched_at < self._stale_max_age
        }

    def _get_grants(self, user, refresh=False):
        """Return the grants of user, from cache or from the API.

        With refresh, cached grants are renewed unless they were fetched
        less than refresh_interval seconds ago: this makes new shares
        visible quickly without letting denied requests flood the API.
        """
        now = time.monotonic()
        entry = self._cache.get(user)
        if entry:
            age = now - entry.fetched_at
            if age < (self._refresh_interval if refresh else self._cache_ttl):
                return entry.grants
        grants = self._fetch(user)
        if grants is None:
            if entry and now - entry.fetched_at < self._stale_max_age:
                logger.warning("Using stale Modoboa rights for %r", user)
                return entry.grants
            return EMPTY_GRANTS
        with self._lock:
            self._cache[user] = CacheEntry(now, grants)
            self._purge_cache(now)
        return grants

    def _foreign_permissions(self, user, owner, sane_path, is_principal):
        """Return permissions of user on a collection owned by someone else."""

        def lookup(grants):
            if is_principal:
                return grants.principal_permissions(owner)
            return grants.calendar_permissions(owner, sane_path)

        permissions = lookup(self._get_grants(user))
        if not permissions:
            permissions = lookup(self._get_grants(user, refresh=True))
        return permissions

    def authorization(self, user, path):
        if not user:
            return ""
        sane_path = pathutils.strip_path(path)
        if not sane_path:
            return "R"
        parts = sane_path.split("/")
        if len(parts) > 2:
            # Items: Radicale relies on the rights of the parent collection
            return ""
        owner = parts[0]
        if owner == user:
            if len(parts) == 1:
                return OWNER_PRINCIPAL_PERMISSIONS
            return OWNER_CALENDAR_PERMISSIONS
        if len(parts) == 2 and is_domain_collection(owner) and "@" in user:
            if get_domain(user) == owner:
                return DOMAIN_CALENDAR_PERMISSIONS
        return self._foreign_permissions(user, owner, sane_path, len(parts) == 1)
