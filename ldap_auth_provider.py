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

import logging
import ssl
from typing import Optional

import ldap3
import ldap3.core.exceptions
import synapse
from pkg_resources import parse_version
from twisted.internet import threads

__version__ = "0.1.5"

logger = logging.getLogger(__name__)


class ActiveDirectoryUPNException(Exception):
    """Raised in case the user's login credentials cannot be mapped to a UPN"""

    pass


class LDAPMode(object):
    SIMPLE = ("simple",)
    SEARCH = ("search",)

    LIST = (SIMPLE, SEARCH)


class LdapAuthProvider(object):
    _ldap_tls = ldap3.Tls(validate=ssl.CERT_REQUIRED)

    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        self.ldap_mode = config.mode
        self.ldap_uris = [config.uri] if isinstance(config.uri, str) else config.uri
        self.ldap_start_tls = config.start_tls
        self.ldap_base = config.base
        self.ldap_attributes = config.attributes
        if self.ldap_mode == LDAPMode.SEARCH:
            self.ldap_bind_dn = config.bind_dn
            self.ldap_bind_password = config.bind_password
            self.ldap_filter = config.filter

        self.ldap_active_directory = config.active_directory
        if self.ldap_active_directory:
            self.ldap_default_domain = config.default_domain
            # Either: the Active Directory root domain (type str); empty string in case
            # of error; or None if there was no attempt to fetch root domain yet
            self.ldap_root_domain = None  # type: Optional[str]

    def get_supported_login_types(self):
        return {"m.login.password": ("password",)}

    async def check_auth(self, username, login_type, login_dict):
        """Attempt to authenticate a user against an LDAP Server
        and register an account if none exists.

        Returns:
            Canonical user ID if authentication against LDAP was successful
        """
        password = login_dict["password"]
        # According to section 5.1.2. of RFC 4513 an attempt to log in with
        # non-empty DN and empty password is called Unauthenticated
        # Authentication Mechanism of Simple Bind which is used to establish
        # an anonymous authorization state and not suitable for user
        # authentication.
        if not password:
            return False

        if username.startswith("@") and ":" in username:
            # username is of the form @foo:bar.com
            username = username.split(":", 1)[0][1:]

        # Used in LDAP queries as value of ldap_attributes['uid'] attribute.
        uid_value = username
        # Default display name for the user, if a new account is registered.
        default_display_name = username
        # Local part of Matrix ID which will be used in registration process
        localpart = username

        if self.ldap_active_directory:
            try:
                (login, domain, localpart) = await self._map_login_to_upn(username)
                uid_value = login + "@" + domain
                default_display_name = login
            except ActiveDirectoryUPNException:
                return False

        try:
            server = self._get_server()
            logger.debug("Attempting LDAP connection with %s", self.ldap_uris)

            if self.ldap_mode == LDAPMode.SIMPLE:
                bind_dn = "{prop}={value},{base}".format(
                    prop=self.ldap_attributes["uid"],
                    value=uid_value,
                    base=self.ldap_base,
                )
                result, conn = await self._ldap_simple_bind(
                    server=server, bind_dn=bind_dn, password=password
                )
                logger.debug(
                    "LDAP authentication method simple bind returned: " "%s (conn: %s)",
                    result,
                    conn,
                )
                if not result:
                    return False
            elif self.ldap_mode == LDAPMode.SEARCH:
                filters = [(self.ldap_attributes["uid"], uid_value)]
                result, conn, _ = await self._ldap_authenticated_search(
                    server=server, password=password, filters=filters
                )
                logger.debug(
                    "LDAP auth method authenticated search returned: " "%s (conn: %s)",
                    result,
                    conn,
                )
                if not result:
                    return False
            else:  # pragma: no cover
                raise RuntimeError(
                    "Invalid LDAP mode specified: {mode}".format(mode=self.ldap_mode)
                )

            try:
                logger.info("User authenticated against LDAP server: %s", conn)
            except NameError:  # pragma: no cover
                logger.warning(
                    "Authentication method yielded no LDAP connection, " "aborting!"
                )
                return False

            # Get full user id from localpart
            user_id = self.account_handler.get_qualified_user_id(localpart)

            # check if user with user_id exists
            if await self.account_handler.check_user_exists(user_id):
                # exists, authentication complete
                if hasattr(conn, "unbind"):
                    await threads.deferToThread(conn.unbind)
                return user_id

            else:
                # does not exist, register
                if self.ldap_mode == LDAPMode.SEARCH:
                    # search enabled, fetch metadata for account creation from
                    # existing ldap connection
                    filters = [(self.ldap_attributes["uid"], uid_value)]

                    result, conn, response = await self._ldap_authenticated_search(
                        server=server,
                        password=password,
                        filters=filters,
                    )

                    # These results will always return an array
                    display_name = response["attributes"].get(
                        self.ldap_attributes["name"], [localpart]
                    )
                    display_name = (
                        display_name[0]
                        if len(display_name) == 1
                        else default_display_name
                    )

                    mail = response["attributes"].get("mail", [None])
                    mail = mail[0] if len(mail) == 1 else None
                else:
                    # search disabled, register account with basic information
                    display_name = default_display_name
                    mail = None

                # Register the user
                user_id = await self.register_user(localpart, display_name, mail)

                return user_id

            return False

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during ldap authentication: %s", e)
            return False

    async def check_3pid_auth(self, medium, address, password):
        """Handle authentication against thirdparty login types, such as email

        Args:
            medium (str): Medium of the 3PID (e.g email, msisdn).
            address (str): Address of the 3PID (e.g bob@example.com for email).
            password (str): The provided password of the user.

        Returns:
            user_id (str|None): ID of the user if authentication
                successful. None otherwise.
        """
        if self.ldap_mode != LDAPMode.SEARCH:
            logger.debug(
                "3PID LDAP login/register attempted but LDAP search mode "
                "not enabled. Bailing."
            )
            return None

        # We currently only support email
        if medium != "email":
            return None

        # Talk to LDAP and check if this email/password combo is correct
        try:
            server = self._get_server()
            logger.debug("Attempting LDAP connection with %s", self.ldap_uris)

            search_filter = [(self.ldap_attributes["mail"], address)]
            result, conn, response = await self._ldap_authenticated_search(
                server=server,
                password=password,
                filters=search_filter,
            )

            logger.debug(
                "LDAP auth method authenticated search returned: "
                "%s (conn: %s) (response: %s)",
                result,
                conn,
                response,
            )

            # Close connection
            if hasattr(conn, "unbind"):
                await threads.deferToThread(conn.unbind)

            if not result:
                return None

            # Extract the username from the search response from the LDAP server
            localpart = response["attributes"].get(self.ldap_attributes["uid"], [None])
            localpart = localpart[0] if len(localpart) == 1 else None
            if self.ldap_active_directory and localpart and "@" in localpart:
                (login, domain) = localpart.lower().rsplit("@", 1)
                localpart = login + "/" + domain

                if (
                    self.ldap_default_domain
                    and domain.lower() == self.ldap_default_domain.lower()
                ):
                    # Users in default AD domain don't have `/domain` suffix
                    localpart = login

            givenName = response["attributes"].get(
                self.ldap_attributes["name"], [localpart]
            )
            givenName = givenName[0] if len(givenName) == 1 else localpart

            # Register the user
            user_id = await self.register_user(localpart, givenName, address)

            return user_id

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during ldap authentication: %s", e)
            raise

    async def register_user(self, localpart, name, email_address):
        """Register a Synapse user, first checking if they exist.

        Args:
            localpart (str): Localpart of the user to register on this homeserver.
            name (str): Full name of the user.
            email_address (str): Email address of the user.

        Returns:
            user_id (str): User ID of the newly registered user.
        """
        # Get full user id from localpart
        user_id = self.account_handler.get_qualified_user_id(localpart)

        if await self.account_handler.check_user_exists(user_id):
            # exists, authentication complete
            return user_id

        # register an email address if one exists
        emails = [email_address] if email_address is not None else []

        # create account
        # check if we're running a version of synapse that supports binding emails
        # from password providers
        if parse_version(synapse.__version__) <= parse_version("0.99.3"):
            user_id, access_token = await self.account_handler.register(
                localpart=localpart,
                displayname=name,
            )
        else:
            # If Synapse has support, bind emails
            user_id, access_token = await self.account_handler.register(
                localpart=localpart,
                displayname=name,
                emails=emails,
            )

        logger.info(
            "Registration based on LDAP data was successful: %s",
            user_id,
        )

        return user_id

    @staticmethod
    def parse_config(config):
        class _LdapConfig(object):
            pass

        ldap_config = _LdapConfig()

        ldap_config.enabled = config.get("enabled", False)

        ldap_config.mode = LDAPMode.SIMPLE

        # verify config sanity
        _require_keys(
            config,
            [
                "uri",
                "base",
                "attributes",
            ],
        )

        ldap_config.uri = config["uri"]
        ldap_config.start_tls = config.get("start_tls", False)
        ldap_config.base = config["base"]
        ldap_config.attributes = config["attributes"]

        if "bind_dn" in config:
            ldap_config.mode = LDAPMode.SEARCH
            _require_keys(
                config,
                [
                    "bind_dn",
                    "bind_password",
                ],
            )

            ldap_config.bind_dn = config["bind_dn"]
            ldap_config.bind_password = config["bind_password"]
            ldap_config.filter = config.get("filter", None)

        # verify attribute lookup
        _require_keys(
            config["attributes"],
            [
                "uid",
                "name",
                "mail",
            ],
        )

        ldap_config.active_directory = config.get("active_directory", False)
        if ldap_config.active_directory:
            ldap_config.default_domain = config.get("default_domain", None)

        return ldap_config

    def _get_server(self, get_info: Optional[str] = None) -> ldap3.ServerPool:
        """Constructs ServerPool from configured LDAP URIs

        Args:
            get_info (str, optional): specifies if the server schema and server
            specific info must be read. Defaults to None.

        Returns:
            Servers grouped in a ServerPool
        """
        return ldap3.ServerPool(
            [
                ldap3.Server(uri, get_info=get_info, tls=self._ldap_tls)
                for uri in self.ldap_uris
            ],
        )

    async def _fetch_root_domain(self) -> str:
        """Fetches root domain from LDAP and saves it to ``self.ldap_root_domain``

        Returns:
            The root domain of Active Directory forest
        """
        if self.ldap_root_domain is not None:
            return self.ldap_root_domain

        self.ldap_root_domain = ""

        if self.ldap_mode != LDAPMode.SEARCH:
            logger.info("Fetching root domain is supported in search mode only")
            return self.ldap_root_domain

        server = self._get_server(get_info=ldap3.DSA)
        result, conn = await self._ldap_simple_bind(
            server=server,
            bind_dn=self.ldap_bind_dn,
            password=self.ldap_bind_password,
        )

        if not result:
            logger.warning("Unable to get root domain due to failed LDAP bind")
            return self.ldap_root_domain

        if conn.server.info.other and conn.server.info.other.get(
            "rootDomainNamingContext"
        ):
            # conn.server.info.other["rootDomainNamingContext"][0]
            # is of the form DC=example,DC=org
            self.ldap_root_domain = ".".join(
                [
                    dc.split("=")[1]
                    for dc in conn.server.info.other["rootDomainNamingContext"][
                        0
                    ].split(",")
                    if "=" in dc
                ]
            )
            logger.info('Obtained root domain "%s"', self.ldap_root_domain)

        if not self.ldap_root_domain:
            logger.warning(
                "No valid `rootDomainNamingContext` attribute was found in the RootDSE. "
                "Logging in using short domain name will be unavailable."
            )

        await threads.deferToThread(conn.unbind)

        return self.ldap_root_domain

    async def _ldap_simple_bind(self, server, bind_dn, password):
        """Attempt a simple bind with the credentials
        given by the user against the LDAP server.

        Returns True, LDAP3Connection
            if the bind was successful
        Returns False, None
            if an error occured
        """

        try:
            # bind with the the local user's ldap credentials
            conn = await threads.deferToThread(
                ldap3.Connection,
                server,
                bind_dn,
                password,
                authentication=ldap3.SIMPLE,
                read_only=True,
            )
            logger.debug("Established LDAP connection in simple bind mode: %s", conn)

            if self.ldap_start_tls:
                await threads.deferToThread(conn.open)
                await threads.deferToThread(conn.start_tls)
                logger.debug(
                    "Upgraded LDAP connection in simple bind mode through "
                    "StartTLS: %s",
                    conn,
                )

            if await threads.deferToThread(conn.bind):
                # GOOD: bind okay
                logger.debug("LDAP Bind successful in simple bind mode.")
                return (True, conn)

            # BAD: bind failed
            logger.info(
                "Binding against LDAP failed for '%s' failed: %s",
                bind_dn,
                conn.result["description"],
            )
            await threads.deferToThread(conn.unbind)
            return (False, None)

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during LDAP authentication: %s", e)
            raise

    async def _ldap_authenticated_search(self, server, password, filters):
        """Attempt to login with the preconfigured bind_dn and then continue
        searching and filtering within the base_dn.

        Fetches the attributes that correspond to uid/name/mail as defined in
        the config.

        Args:
            server (str): The LDAP server to connect to.
            password (str): The user's password.
            filters (List[Tuple[str,str]]): A list of tuples of key/value
                pairs to filter the LDAP search by.

        Returns:
            Deferred[tuple[bool, LDAP3Connection, response]]: Returns a 3-tuple
            where first field is whether a *single* entry was found, the second
            is the open connection bound to the found user and the final field
            is the LDAP entry of the found entry. If first field is False then
            second and third field will both be None.
        """

        try:
            result, conn = await self._ldap_simple_bind(
                server=server,
                bind_dn=self.ldap_bind_dn,
                password=self.ldap_bind_password,
            )

            if not result:
                return (False, None, None)

            # Construct search filter
            query = ""
            for filter in filters:
                query += "({key}={value})".format(
                    key=filter[0],
                    value=filter[1],
                )

            if self.ldap_filter:
                query += self.ldap_filter

            # Create an AND query
            query = "(&{query})".format(
                query=query,
            )

            logger.debug("LDAP search filter: %s", query)
            await threads.deferToThread(
                conn.search,
                search_base=self.ldap_base,
                search_filter=query,
                attributes=[
                    self.ldap_attributes["uid"],
                    self.ldap_attributes["name"],
                    self.ldap_attributes["mail"],
                ],
            )

            responses = [
                response
                for response in conn.response
                if response["type"] == "searchResEntry"
            ]

            if len(responses) == 1:
                # GOOD: found exactly one result
                user_dn = responses[0]["dn"]
                logger.debug("LDAP search found dn: %s", user_dn)

                # unbind and simple bind with user_dn to verify the password
                # Note: do not use rebind(), for some reason it did not verify
                #       the password for me!
                await threads.deferToThread(conn.unbind)
                result, conn = await self._ldap_simple_bind(
                    server=server, bind_dn=user_dn, password=password
                )

                return (result, conn, responses[0])
            else:
                # BAD: found 0 or > 1 results, abort!
                if len(responses) == 0:
                    logger.info("LDAP search returned no results for '%s'", filters)
                else:
                    logger.info(
                        "LDAP search returned too many (%s) results for '%s'",
                        len(responses),
                        filters,
                    )
                await threads.deferToThread(conn.unbind)

                return (False, None, None)

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during LDAP authentication: %s", e)
            raise

    async def _map_login_to_upn(self, username):
        """Maps user provided login to Active Directory UPN and
        local part of Matrix ID.

        Args:
            username (str): The user's login

        Raises:
            ActiveDirectoryUPNException: if username can not be
                mapped to userPrincipalName

        Returns:
            Tuple[str, str, str]: a tuple of Active Directory login,
            Active Directory domain and local part of Matrix ID.
        """
        login = username.lower()
        domain = self.ldap_default_domain
        localpart = username

        if "\\" in username:
            (domain, login) = username.lower().rsplit("\\", 1)
            ldap_root_domain = await self._fetch_root_domain()
            if ldap_root_domain and not domain.endswith(ldap_root_domain):
                domain += "." + ldap_root_domain
        elif "/" in username:
            (login, domain) = username.lower().rsplit("/", 1)
        else:
            if not self.ldap_default_domain:
                logger.info(
                    'No LDAP separator "/" was found in uid "%s" '
                    "and LDAP default domain was not configured.",
                    username,
                )
                raise ActiveDirectoryUPNException()

        if self.ldap_default_domain and domain == self.ldap_default_domain.lower():
            localpart = login
        else:
            localpart = login + "/" + domain

        return (login, domain, localpart)


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "LDAP enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )
