# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from twisted.internet import defer, threads


import ldap3
import ldap3.core.exceptions

import logging


__version__ = "0.1.3"


try:
    import ldap3
    import ldap3.core.exceptions

    # ldap3 v2 changed ldap3.AUTH_SIMPLE -> ldap3.SIMPLE
    try:
        LDAP_AUTH_SIMPLE = ldap3.AUTH_SIMPLE
    except AttributeError:
        LDAP_AUTH_SIMPLE = ldap3.SIMPLE
except ImportError:
    ldap3 = None
    pass


logger = logging.getLogger(__name__)


class LDAPMode(object):
    SIMPLE = "simple",
    SEARCH = "search",

    LIST = (SIMPLE, SEARCH)


class LdapAuthProvider(object):
    __version__ = "0.1"

    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        if not ldap3:
            raise RuntimeError(
                'Missing ldap3 library. '
                'This is required for LDAP Authentication.'
            )

        self.ldap_mode = config.mode
        self.ldap_uri = config.uri
        self.ldap_start_tls = config.start_tls
        self.ldap_base = config.base
        self.ldap_attributes = config.attributes
        if self.ldap_mode == LDAPMode.SEARCH:
            self.ldap_bind_dn = config.bind_dn
            self.ldap_bind_password = config.bind_password
            self.ldap_filter = config.filter

    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        """ Attempt to authenticate a user against an LDAP Server
            and register an account if none exists.

            Returns:
                True if authentication against LDAP was successful
        """
        if not password:
            defer.returnValue(False)
        # user_id is of the form @foo:bar.com
        localpart = user_id.split(":", 1)[0][1:]

        try:
            server = ldap3.Server(self.ldap_uri, get_info=None)
            logger.debug(
                "Attempting LDAP connection with %s",
                self.ldap_uri
            )

            if self.ldap_mode == LDAPMode.SIMPLE:
                bind_dn = "{prop}={value},{base}".format(
                    prop=self.ldap_attributes['uid'],
                    value=localpart,
                    base=self.ldap_base
                )
                result, conn = yield self._ldap_simple_bind(
                    server=server, bind_dn=bind_dn, password=password
                )
                logger.debug(
                    'LDAP authentication method simple bind returned: '
                    '%s (conn: %s)',
                    result,
                    conn
                )
                if not result:
                    defer.returnValue(False)
            elif self.ldap_mode == LDAPMode.SEARCH:
                result, conn = yield self._ldap_authenticated_search(
                    server=server, localpart=localpart, password=password
                )
                logger.debug(
                    'LDAP auth method authenticated search returned: '
                    '%s (conn: %s)',
                    result,
                    conn
                )
                if not result:
                    defer.returnValue(False)
            else:
                raise RuntimeError(
                    'Invalid LDAP mode specified: {mode}'.format(
                        mode=self.ldap_mode
                    )
                )

            try:
                logger.info(
                    "User authenticated against LDAP server: %s",
                    conn
                )
            except NameError:
                logger.warning(
                    "Authentication method yielded no LDAP connection, "
                    "aborting!"
                )
                defer.returnValue(False)

            # check if user with user_id exists
            if (yield self.account_handler.check_user_exists(user_id)):
                # exists, authentication complete
                yield threads.deferToThread(conn.unbind)
                defer.returnValue(True)

            else:
                # does not exist, fetch metadata for account creation from
                # existing ldap connection
                query = "({prop}={value})".format(
                    prop=self.ldap_attributes['uid'],
                    value=localpart
                )

                if self.ldap_mode == LDAPMode.SEARCH and self.ldap_filter:
                    query = "(&{filter}{user_filter})".format(
                        filter=query,
                        user_filter=self.ldap_filter
                    )
                logger.debug(
                    "ldap registration filter: %s",
                    query
                )

                yield threads.deferToThread(
                    conn.search,
                    search_base=self.ldap_base,
                    search_filter=query,
                    attributes=[
                        self.ldap_attributes['name'],
                        self.ldap_attributes['mail']
                    ]
                )

                responses = [
                    response
                    for response
                    in conn.response
                    if response['type'] == 'searchResEntry'
                ]

                if len(responses) == 1:
                    attrs = responses[0]['attributes']
                    name = attrs[self.ldap_attributes['name']][0]
                    try:
                        mail = attrs[self.ldap_attributes['mail']][0]
                    except (KeyError, IndexError):
                        mail = None

                    # create account
                    user_id, access_token = (
                        yield self.account_handler.register(localpart=localpart)
                    )

                    # TODO: bind email, set displayname with data from
                    #       ldap directory

                    logger.info(
                        "Registration based on LDAP data was successful: "
                        "%d: %s (%s, %)",
                        user_id, localpart, name, mail
                    )

                    defer.returnValue(True)
                else:
                    if len(responses) == 0:
                        logger.warning("LDAP registration failed, no result.")
                    else:
                        logger.warning(
                            "LDAP registration failed, too many results (%s)",
                            len(responses)
                        )

                    defer.returnValue(False)

            defer.returnValue(False)

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during ldap authentication: %s", e)
            defer.returnValue(False)

    @staticmethod
    def parse_config(config):
        class _LdapConfig(object):
            pass

        ldap_config = _LdapConfig()

        ldap_config.enabled = config.get("enabled", False)

        ldap_config.mode = LDAPMode.SIMPLE

        # verify config sanity
        _require_keys(config, [
            "uri",
            "base",
            "attributes",
        ])

        ldap_config.uri = config["uri"]
        ldap_config.start_tls = config.get("start_tls", False)
        ldap_config.base = config["base"]
        ldap_config.attributes = config["attributes"]

        if "bind_dn" in config:
            ldap_config.mode = LDAPMode.SEARCH
            _require_keys(config, [
                "bind_dn",
                "bind_password",
            ])

            ldap_config.bind_dn = config["bind_dn"]
            ldap_config.bind_password = config["bind_password"]
            ldap_config.filter = config.get("filter", None)

        # verify attribute lookup
        _require_keys(config['attributes'], [
            "uid",
            "name",
            "mail",
        ])

        return ldap_config

    @defer.inlineCallbacks
    def _ldap_simple_bind(self, server, bind_dn, password):
        """ Attempt a simple bind with the credentials
            given by the user against the LDAP server.

            Returns True, LDAP3Connection
                if the bind was successful
            Returns False, None
                if an error occured
        """

        try:
            # bind with the the local users ldap credentials
            conn = yield threads.deferToThread(
                ldap3.Connection,
                server, bind_dn, password,
                authentication=LDAP_AUTH_SIMPLE,
                read_only=True,
            )
            logger.debug(
                "Established LDAP connection in simple bind mode: %s",
                conn
            )

            if self.ldap_start_tls:
                yield threads.deferToThread(conn.open)
                yield threads.deferToThread(conn.start_tls)
                logger.debug(
                    "Upgraded LDAP connection in simple bind mode through "
                    "StartTLS: %s",
                    conn
                )

            if (yield threads.deferToThread(conn.bind)):
                # GOOD: bind okay
                logger.debug("LDAP Bind successful in simple bind mode.")
                defer.returnValue((True, conn))

            # BAD: bind failed
            logger.info(
                "Binding against LDAP failed for '%s' failed: %s",
                bind_dn, conn.result['description']
            )
            yield threads.deferToThread(conn.unbind)
            defer.returnValue((False, None))

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during LDAP authentication: %s", e)
            defer.returnValue((False, None))

    @defer.inlineCallbacks
    def _ldap_authenticated_search(self, server, localpart, password):
        """ Attempt to login with the preconfigured bind_dn
            and then continue searching and filtering within
            the base_dn

            Returns (True, LDAP3Connection)
                if a single matching DN within the base was found
                that matched the filter expression, and with which
                a successful bind was achieved

                The LDAP3Connection returned is the instance that was used to
                verify the password not the one using the configured bind_dn.
            Returns (False, None)
                if an error occured
        """

        try:
            conn = yield threads.deferToThread(
                ldap3.Connection,
                server,
                self.ldap_bind_dn,
                self.ldap_bind_password
            )
            logger.debug(
                "Established LDAP connection in search mode: %s",
                conn
            )

            if self.ldap_start_tls:
                yield threads.deferToThread(conn.open)
                yield threads.deferToThread(conn.start_tls)
                logger.debug(
                    "Upgraded LDAP connection in search mode through "
                    "StartTLS: %s",
                    conn
                )

            if not (yield threads.deferToThread(conn.bind)):
                logger.warning(
                    "Binding against LDAP with `bind_dn` failed: %s",
                    conn.result['description']
                )
                yield threads.deferToThread(conn.unbind)
                defer.returnValue((False, None))

            # construct search_filter like (uid=localpart)
            query = "({prop}={value})".format(
                prop=self.ldap_attributes['uid'],
                value=localpart
            )
            if self.ldap_filter:
                # combine with the AND expression
                query = "(&{query}{filter})".format(
                    query=query,
                    filter=self.ldap_filter
                )
            logger.debug(
                "LDAP search filter: %s",
                query
            )
            yield threads.deferToThread(
                conn.search,
                search_base=self.ldap_base,
                search_filter=query
            )

            responses = [
                response
                for response
                in conn.response
                if response['type'] == 'searchResEntry'
            ]

            if len(responses) == 1:
                # GOOD: found exactly one result
                user_dn = responses[0]['dn']
                logger.debug('LDAP search found dn: %s', user_dn)

                # unbind and simple bind with user_dn to verify the password
                # Note: do not use rebind(), for some reason it did not verify
                #       the password for me!
                yield threads.deferToThread(conn.unbind)
                result = yield self._ldap_simple_bind(
                    server=server, bind_dn=user_dn, password=password
                )

                defer.returnValue(result)
            else:
                # BAD: found 0 or > 1 results, abort!
                if len(responses) == 0:
                    logger.info(
                        "LDAP search returned no results for '%s'",
                        localpart
                    )
                else:
                    logger.info(
                        "LDAP search returned too many (%s) results for '%s'",
                        len(responses), localpart
                    )
                yield threads.deferToThread(conn.unbind)
                defer.returnValue((False, None))

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during LDAP authentication: %s", e)
            defer.returnValue((False, None))


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "LDAP enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )
