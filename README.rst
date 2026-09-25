radicale-modoboa-rights
=======================

A rights management plugin for Radicale provided by Modoboa.

Access to a user's own collections and to the shared calendars of his
domain is decided locally. Access to collections owned by someone else
(calendars shared through Modoboa access rules, administrators) is asked
to the Modoboa API and cached, so Radicale and Modoboa can run on
different servers without sharing any file.

Requirements:

* Radicale 3.3 or later
* Modoboa 2.11 or later, which provides the rights endpoint. Modoboa is
  not a Python dependency of this package: it is usually installed on
  another server and only reached through its API.

Installation
------------

You can install this package from PyPi using the following command::

   pip install radicale-modoboa-rights

Configuration
-------------

Here is a configuration example::

   [rights]
   type = radicale_modoboa_rights

   modoboa_rights_endpoint = https://<modoboa>/api/v2/calendar-rights/
   # Credentials of Radicale's OAuth2 application in Modoboa
   modoboa_client_id = <client id>
   modoboa_client_secret = <client secret>

The OAuth2 application must be named ``Radicale`` and use the client
credentials grant. It is the one created for Radicale's authentication
plugin.

Optional settings:

``modoboa_token_endpoint`` (default: ``/api/o/token/`` on the host of ``modoboa_rights_endpoint``)
   Modoboa's OAuth2 token endpoint.

The following optional settings are in seconds:

``modoboa_rights_cache_ttl`` (default: 60)
   How long rights fetched from Modoboa are cached. This is also the
   maximum delay before a revoked access is enforced.

``modoboa_rights_refresh_interval`` (default: 5)
   When an access is denied, rights are fetched again if they are older
   than this, so new shares are usable almost immediately.

``modoboa_rights_stale_max_age`` (default: 3600)
   While the Modoboa API is unreachable, cached rights keep being used
   up to this age. Past it, access to other users' collections is denied.

``modoboa_rights_timeout`` (default: 2)
   Timeout of requests to the Modoboa API.

``modoboa_rights_retry_delay`` (default: 10)
   After a failed request, the Modoboa API is not called again before
   this delay.

Permissions
-----------

================================================  ===================
Collection                                        Permissions
================================================  ===================
Own principal (``user@domain/``)                  ``RW``
Own calendars (``user@domain/*``)                 ``rw``
Domain shared calendars, for domain members       ``rwd``
Domain collection, for its managers               ``RW``
Domain shared calendars, for their managers       ``rw``
User principals, for administrators               ``R``
User calendars, for administrators                ``rw``
Shared calendars                                  returned by Modoboa
================================================  ===================

The ``d`` permission forbids the deletion of the calendar itself when
``[rights] permit_delete_collection`` is enabled (the default).

Modoboa API
-----------

The plugin gets an access token from ``modoboa_token_endpoint`` with the
OAuth2 client credentials grant (client id and secret sent with HTTP
Basic). The token is kept until it is about to expire, or until the API
refuses it.

It then sends ``POST`` requests to ``modoboa_rights_endpoint`` with the
token (``Authorization: Bearer <token>``)::

   {"user": "bob@example.com"}

and expects the following answer::

   {
     "admin_domains": ["example.com"],
     "managed_domains": ["example.com"],
     "shares": {"alice@example.com/Work": "rwd"}
   }

``admin_domains``
   Domains whose user calendars the user administers. ``"*"`` means
   every domain.

``managed_domains``
   Domains whose shared calendars the user manages. ``"*"`` means every
   domain.

``shares``
   Calendars shared with the user, as ``path: permissions``. Only
   ``rwdDoOi`` permissions are accepted.

All keys are optional.
