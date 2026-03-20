# -*- coding: utf-8 -*-
# Copyright 2026
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

"""Tests for user_mapping functionality (numeric ID mapping)."""

import logging
from unittest.mock import AsyncMock, Mock

from twisted.internet import defer
from twisted.trial import unittest

# Import test helpers from the tests package
# These would be in tests/__init__.py
from . import (
    create_auth_provider,
    create_ldap_server,
    get_qualified_user_id,
    make_awaitable,
)

logging.basicConfig()


class LdapUserMappingTestCase(unittest.TestCase):
    """Test user_mapping functionality with numeric ID mapping (e.g., '790159' -> 'u790159')."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up LDAP server and auth provider with user_mapping configuration."""
        self.ldap_server = yield defer.ensureDeferred(create_ldap_server())
        
        # Track registered users and their external IDs
        self.registered_users = {}
        self.user_external_ids = {}
        
        # Mock ModuleApi with all required methods
        module_api = Mock(
            spec_set=[
                "check_user_exists",
                "get_qualified_user_id",
                "register",
                "record_user_external_id",
                "register_password_auth_provider_callbacks",
                "_store",
            ]
        )
        
        # Mock check_user_exists to check our registered_users dict
        def check_user_exists(user_id):
            exists = user_id in self.registered_users
            return make_awaitable(exists)
        
        module_api.check_user_exists.side_effect = check_user_exists
        module_api.get_qualified_user_id = get_qualified_user_id
        
        # Mock register to track registered users
        async def mock_register(localpart, displayname=None, emails=None):
            user_id = get_qualified_user_id(localpart)
            self.registered_users[user_id] = {
                "localpart": localpart,
                "displayname": displayname,
                "emails": emails or [],
            }
            return (user_id, "fake_access_token")
        
        module_api.register = AsyncMock(side_effect=mock_register)
        
        # Mock record_user_external_id to track external IDs
        async def mock_record_external_id(auth_provider, external_id, user_id):
            if user_id not in self.user_external_ids:
                self.user_external_ids[user_id] = []
            self.user_external_ids[user_id].append((auth_provider, external_id))
        
        module_api.record_user_external_id = AsyncMock(side_effect=mock_record_external_id)
        
        # Mock _store with db_pool for SQL queries
        mock_store = Mock()
        mock_db_pool = Mock()
        
        # Mock simple_select_one_onecol for getting original localpart
        async def mock_select_one_onecol(table, keyvalues, retcol, allow_none=True, desc=None):
            if table == "user_external_ids":
                user_id = keyvalues.get("user_id")
                auth_provider = keyvalues.get("auth_provider")
                
                if user_id and user_id in self.user_external_ids:
                    for stored_provider, stored_external_id in self.user_external_ids[user_id]:
                        if stored_provider == auth_provider:
                            return stored_external_id
                
                # Also support lookup by external_id
                external_id = keyvalues.get("external_id")
                if external_id and auth_provider:
                    for uid, ids in self.user_external_ids.items():
                        for stored_provider, stored_external_id in ids:
                            if stored_provider == auth_provider and stored_external_id == external_id:
                                return uid
            return None
        
        mock_db_pool.simple_select_one_onecol = AsyncMock(side_effect=mock_select_one_onecol)
        mock_store.db_pool = mock_db_pool
        
        # Mock get_external_ids_by_user
        async def mock_get_external_ids_by_user(user_id):
            return self.user_external_ids.get(user_id, [])

        mock_store.get_external_ids_by_user = AsyncMock(side_effect=mock_get_external_ids_by_user)

        module_api._store = mock_store


        # Create auth provider with user_mapping configuration
        self.auth_provider = create_auth_provider(
            self.ldap_server,
            module_api,
            config={
                "enabled": True,
                "uri": "ldap://localhost:%d" % self.ldap_server.listener.getHost().port,
                "base": "ou=people,dc=example,dc=org",
                "attributes": {
                    "uid": "cn",
                    "name": "gn",
                    "mail": "mail",
                },
                "user_mapping": {
                    "localpart_template": "u{localpart}",
                },
            },
        )

    def tearDown(self):
        """Clean up LDAP server."""
        self.ldap_server.close()

    @defer.inlineCallbacks
    def test_mapping_applied_on_registration(self):
        """Test (1): Verify that mapping is applied on registration.

        When a user 'bob' logs in for the first time, they should be registered
        as 'ubob' (with template 'u{localpart}').
        """
        # First login - user doesn't exist yet
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )

        # Should return mapped user ID
        self.assertEqual(result, "@ubob:test")

        # Verify user was registered with mapped localpart
        self.assertIn("@ubob:test", self.registered_users)
        self.assertEqual(self.registered_users["@ubob:test"]["localpart"], "ubob")

        # Verify original localpart was stored in user_external_ids
        self.assertIn("@ubob:test", self.user_external_ids)
        external_ids = self.user_external_ids["@ubob:test"]
        self.assertEqual(len(external_ids), 1)
        self.assertEqual(external_ids[0], ("ldap_original", "bob"))

    @defer.inlineCallbacks
    def test_subsequent_login_with_mapped_localpart(self):
        """Test (2): Verify that subsequent logins work when user supplies the mapped localpart.

        After initial registration, user should be able to log in with their
        mapped username and the system should correctly reverse-map it to find
        the original LDAP username.
        """
        # First login - register the user
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )
        self.assertEqual(result, "@ubob:test")

        # Second login - user now exists, login with mapped username
        # The system should reverse-map 'ubob' -> 'bob' for LDAP query
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "ubob", "m.login.password", {"password": "secret"}
            )
        )

        # Should successfully authenticate
        self.assertEqual(result, "@ubob:test")

    @defer.inlineCallbacks
    def test_original_localpart_stored_and_queried(self):
        """Test (3a): Verify that original localpart is stored and queried correctly.

        The original LDAP localpart should be stored in user_external_ids
        and retrieved correctly for reverse mapping.
        """
        # Register user
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )
        self.assertEqual(result, "@ubob:test")

        # Verify storage
        self.assertIn("@ubob:test", self.user_external_ids)
        external_ids = self.user_external_ids["@ubob:test"]
        self.assertEqual(external_ids[0], ("ldap_original", "bob"))

        # Test reverse mapping via _get_original_localpart
        original = yield defer.ensureDeferred(
            self.auth_provider._get_original_localpart("ubob")
        )
        self.assertEqual(original, "bob")

    @defer.inlineCallbacks
    def test_template_reversal_fallback(self):
        """Test (3b): Verify that template reversal fallback works when storage is unavailable.

        If the database lookup fails or returns None, the system should fall back
        to reversing the template transformation.
        """
        # Test _reverse_template directly
        reversed_localpart = self.auth_provider._reverse_template("ubob", "u{localpart}")
        self.assertEqual(reversed_localpart, "bob")

        # Test with numeric ID (the main use case)
        reversed_localpart = self.auth_provider._reverse_template("u790159", "u{localpart}")
        self.assertEqual(reversed_localpart, "790159")

        # Test _reverse_user_mapping when user doesn't exist in database
        # (simulates database lookup failure)
        original = yield defer.ensureDeferred(
            self.auth_provider._reverse_user_mapping("u790159")
        )
        # Should fall back to template reversal
        self.assertEqual(original, "790159")

    @defer.inlineCallbacks
    def test_numeric_id_mapping(self):
        """Test the main use case: numeric ID mapping (e.g., '790159' -> 'u790159').

        This is the primary use case for the user_mapping feature.
        Note: This test uses 'bob' as a proxy since our test LDAP doesn't have numeric users.
        """
        # Simulate numeric user login (using 'bob' as proxy)
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )

        # Should be mapped to 'ubob'
        self.assertEqual(result, "@ubob:test")

        # Verify the mapping chain works:
        # 1. Original: bob
        # 2. Mapped: ubob
        # 3. Stored in external_ids: bob
        # 4. Reverse lookup: ubob -> bob

        original = yield defer.ensureDeferred(
            self.auth_provider._get_original_localpart("ubob")
        )
        self.assertEqual(original, "bob")

        # Subsequent login with mapped name should work
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "ubob", "m.login.password", {"password": "secret"}
            )
        )
        self.assertEqual(result, "@ubob:test")


class LdapUserMappingSearchModeTestCase(unittest.TestCase):
    """Test user_mapping functionality in SEARCH mode."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up LDAP server and auth provider with user_mapping in SEARCH mode."""
        self.ldap_server = yield defer.ensureDeferred(create_ldap_server())

        # Track registered users and their external IDs
        self.registered_users = {}
        self.user_external_ids = {}

        # Mock ModuleApi (same as simple mode)
        module_api = Mock(
            spec_set=[
                "check_user_exists",
                "get_qualified_user_id",
                "register",
                "record_user_external_id",
                "register_password_auth_provider_callbacks",
                "_store",
            ]
        )

        def check_user_exists(user_id):
            exists = user_id in self.registered_users
            return make_awaitable(exists)

        module_api.check_user_exists.side_effect = check_user_exists
        module_api.get_qualified_user_id = get_qualified_user_id

        async def mock_register(localpart, displayname=None, emails=None):
            user_id = get_qualified_user_id(localpart)
            self.registered_users[user_id] = {
                "localpart": localpart,
                "displayname": displayname,
                "emails": emails or [],
            }
            return (user_id, "fake_access_token")

        module_api.register = AsyncMock(side_effect=mock_register)

        async def mock_record_external_id(auth_provider, external_id, user_id):
            if user_id not in self.user_external_ids:
                self.user_external_ids[user_id] = []
            self.user_external_ids[user_id].append((auth_provider, external_id))

        module_api.record_user_external_id = AsyncMock(side_effect=mock_record_external_id)

        # Mock _store
        mock_store = Mock()
        mock_db_pool = Mock()

        async def mock_select_one_onecol(table, keyvalues, retcol, allow_none=True, desc=None):
            if table == "user_external_ids":
                user_id = keyvalues.get("user_id")
                auth_provider = keyvalues.get("auth_provider")

                if user_id and user_id in self.user_external_ids:
                    for stored_provider, stored_external_id in self.user_external_ids[user_id]:
                        if stored_provider == auth_provider:
                            return stored_external_id

                external_id = keyvalues.get("external_id")
                if external_id and auth_provider:
                    for uid, ids in self.user_external_ids.items():
                        for stored_provider, stored_external_id in ids:
                            if stored_provider == auth_provider and stored_external_id == external_id:
                                return uid
            return None

        mock_db_pool.simple_select_one_onecol = AsyncMock(side_effect=mock_select_one_onecol)
        mock_store.db_pool = mock_db_pool

        async def mock_get_external_ids_by_user(user_id):
            return self.user_external_ids.get(user_id, [])

        mock_store.get_external_ids_by_user = AsyncMock(side_effect=mock_get_external_ids_by_user)
        module_api._store = mock_store

        # Create auth provider with SEARCH mode and user_mapping
        self.auth_provider = create_auth_provider(
            self.ldap_server,
            module_api,
            config={
                "enabled": True,
                "uri": "ldap://localhost:%d" % self.ldap_server.listener.getHost().port,
                "base": "ou=people,dc=example,dc=org",
                "bind_dn": "cn=jsmith,ou=people,dc=example,dc=org",
                "bind_password": "eekretsay",
                "attributes": {
                    "uid": "cn",
                    "name": "gn",
                    "mail": "mail",
                },
                "user_mapping": {
                    "localpart_template": "u{localpart}",
                },
            },
        )

    def tearDown(self):
        """Clean up LDAP server."""
        self.ldap_server.close()

    @defer.inlineCallbacks
    def test_search_mode_with_mapping(self):
        """Test that user_mapping works correctly in SEARCH mode."""
        # First login
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )

        # Should be mapped
        self.assertEqual(result, "@ubob:test")

        # Verify external ID stored
        self.assertIn("@ubob:test", self.user_external_ids)
        self.assertEqual(self.user_external_ids["@ubob:test"][0], ("ldap_original", "bob"))

        # Second login with mapped name
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "ubob", "m.login.password", {"password": "secret"}
            )
        )

        self.assertEqual(result, "@ubob:test")
