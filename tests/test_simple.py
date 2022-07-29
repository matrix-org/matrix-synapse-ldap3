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
from unittest.mock import Mock

from twisted.internet import defer
from twisted.trial import unittest

from . import (
    create_auth_provider,
    create_ldap_server,
    get_qualified_user_id,
    make_awaitable,
)

logging.basicConfig()


class LdapSimpleTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.ldap_server = yield defer.ensureDeferred(create_ldap_server())
        module_api = Mock(
            spec_set=[
                "check_user_exists",
                "get_qualified_user_id",
                "register_password_auth_provider_callbacks",
            ]
        )
        module_api.check_user_exists.side_effect = lambda user_id: make_awaitable(
            user_id
        )
        module_api.get_qualified_user_id = get_qualified_user_id

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
            },
        )

    def tearDown(self):
        self.ldap_server.close()

    @defer.inlineCallbacks
    def test_unknown_user(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "non_existent", "m.login.password", {"password": "password"}
            )
        )
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_incorrect_pwd(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "wrong_password"}
            )
        )
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_correct_pwd(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )
        self.assertEqual(result, "@bob:test")

    @defer.inlineCallbacks
    def test_no_pwd(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth("bob", "m.login.password", {"password": ""})
        )
        self.assertFalse(result)


class LdapSearchTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.ldap_server = yield defer.ensureDeferred(create_ldap_server())
        module_api = Mock(
            spec_set=[
                "check_user_exists",
                "get_qualified_user_id",
                "register_password_auth_provider_callbacks",
            ]
        )
        module_api.check_user_exists.side_effect = lambda user_id: make_awaitable(
            user_id
        )
        module_api.get_qualified_user_id = get_qualified_user_id

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
            },
        )

    def tearDown(self):
        self.ldap_server.close()

    @defer.inlineCallbacks
    def test_correct_pwd_search_mode(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "secret"}
            )
        )
        self.assertEqual(result, "@bob:test")

    @defer.inlineCallbacks
    def test_incorrect_pwd_search_mode(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "bob", "m.login.password", {"password": "wrong_password"}
            )
        )
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_unknown_user_search_mode(self):
        result = yield defer.ensureDeferred(
            self.auth_provider.check_auth(
                "foobar", "m.login.password", {"password": "some_password"}
            )
        )
        self.assertFalse(result)
