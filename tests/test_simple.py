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

from twisted.trial import unittest

from mock import Mock

from . import create_ldap_server, create_auth_provider

import logging
logging.basicConfig()


class LdapSimpleTestCase(unittest.TestCase):
    async def setUp(self):
        self.ldap_server = await create_ldap_server()
        account_handler = Mock(spec_set=["check_user_exists"])
        account_handler.check_user_exists.return_value = True

        self.auth_provider = create_auth_provider(
            self.ldap_server, account_handler,
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

    async def test_unknown_user(self):
        result = await self.auth_provider.check_password("@non_existent:test", "password")
        self.assertFalse(result)

    async def test_incorrect_pwd(self):
        result = await self.auth_provider.check_password("@bob:test", "wrong_password")
        self.assertFalse(result)

    async def test_correct_pwd(self):
        result = await self.auth_provider.check_password("@bob:test", "secret")
        self.assertTrue(result)

    async def test_no_pwd(self):
        result = await self.auth_provider.check_password("@bob:test", "")
        self.assertFalse(result)


class LdapSearchTestCase(unittest.TestCase):
    async def setUp(self):
        self.ldap_server = await create_ldap_server()
        account_handler = Mock(spec_set=["check_user_exists"])
        account_handler.check_user_exists.return_value = True

        self.auth_provider = create_auth_provider(
            self.ldap_server, account_handler,
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

    async def test_correct_pwd_search_mode(self):
        result = await self.auth_provider.check_password("@bob:test", "secret")
        self.assertTrue(result)

    async def test_incorrect_pwd_search_mode(self):
        result = await self.auth_provider.check_password("@bob:test", "wrong_password")
        self.assertFalse(result)

    async def test_unknown_user_search_mode(self):
        result = await self.auth_provider.check_password("@foobar:test", "some_password")
        self.assertFalse(result)
