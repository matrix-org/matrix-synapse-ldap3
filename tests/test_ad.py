# -*- coding: utf-8 -*-
# Copyright 2020 Yuri Konotopov <ykonotopov@gnome.org>
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
from twisted.internet.defer import ensureDeferred
from twisted.trial import unittest
from twisted.internet import defer

from mock import Mock

from . import (
    create_ldap_server,
    create_auth_provider,
    get_qualified_user_id,
    make_awaitable,
)

import logging
logging.basicConfig()


class AbstractLdapActiveDirectoryTestCase():
    @defer.inlineCallbacks
    def setUp(self):
        self.ldap_server = yield ensureDeferred(create_ldap_server())
        account_handler = Mock(spec_set=["check_user_exists", "get_qualified_user_id"])
        account_handler.check_user_exists.return_value = make_awaitable(True)
        account_handler.get_qualified_user_id = get_qualified_user_id

        self.auth_provider = create_auth_provider(
            self.ldap_server, account_handler,
            config=self.getConfig(),
        )

    def getConfig(self):
        return self.getDefaultConfig()

    def getDefaultConfig(self):
        return {
            "enabled": True,
            "active_directory": True,
            "uri": "ldap://localhost:%d" % self.ldap_server.listener.getHost().port,
            "base": "dc=example,dc=org",
            "bind_dn": "cn=jsmith,ou=people,dc=example,dc=org",
            "bind_password": "eekretsay",
            "attributes": {
                "uid": "userPrincipalName",
                "name": "gn",
                "mail": "mail",
            },
        }

    def tearDown(self):
        self.ldap_server.close()


class LdapActiveDirectoryTestCase(AbstractLdapActiveDirectoryTestCase, unittest.TestCase):
    @defer.inlineCallbacks
    def test_correct_pwd(self):
        result = yield ensureDeferred(self.auth_provider.check_auth(
            "main.example.org\\mainuser",
            'm.login.password',
            {"password": "abracadabra"}
        ))
        self.assertEqual(result, "@mainuser/main.example.org:test")

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "subsidiary.example.org\\nonmainuser",
            'm.login.password',
            {"password": "simsalabim"}
        ))
        self.assertEqual(result, "@nonmainuser/subsidiary.example.org:test")

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "subsidiary.example.org\\mainuser",
            'm.login.password',
            {"password": "changeit"}
        ))
        self.assertEqual(result, "@mainuser/subsidiary.example.org:test")

    @defer.inlineCallbacks
    def test_single_email(self):
        result = yield ensureDeferred(self.auth_provider.check_3pid_auth(
            "email",
            "mainuser@main.example.org",
            "abracadabra",
        ))
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_incorrect_pwd(self):
        result = yield ensureDeferred(self.auth_provider.check_auth(
            "main.example.org\\mainuser",
            'm.login.password',
            {"password": "bruteforce"}
        ))
        self.assertFalse(result)

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "subsidiary.example.org\\mainuser",
            'm.login.password',
            {"password": "abracadabra"}
        ))
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_email_login(self):
        result = yield ensureDeferred(self.auth_provider.check_3pid_auth(
            "email",
            "uniqueuser@main.example.org",
            "nothing",
        ))
        self.assertEqual(result, "@uniqueuser/main.example.org:test")


class LdapActiveDirectoryDefaultDomainTestCase(
    AbstractLdapActiveDirectoryTestCase,
    unittest.TestCase
):
    def getConfig(self):
        return dict(
            self.getDefaultConfig(),
            default_domain="main.example.org"
        )

    @defer.inlineCallbacks
    def test_correct_pwd(self):
        result = yield ensureDeferred(self.auth_provider.check_auth(
            "mainuser",
            'm.login.password',
            {"password": "abracadabra"}
        ))
        self.assertEqual(result, "@mainuser:test")

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "main.example.org\\mainuser",
            'm.login.password',
            {"password": "abracadabra"}
        ))
        self.assertEqual(result, "@mainuser:test")

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "subsidiary.example.org\\nonmainuser",
            'm.login.password',
            {"password": "simsalabim"}
        ))
        self.assertEqual(result, "@nonmainuser/subsidiary.example.org:test")

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "subsidiary.example.org\\mainuser",
            'm.login.password',
            {"password": "changeit"}
        ))
        self.assertEqual(result, "@mainuser/subsidiary.example.org:test")

    @defer.inlineCallbacks
    def test_incorrect_pwd(self):
        result = yield ensureDeferred(self.auth_provider.check_auth(
            "mainuser",
            'm.login.password',
            {"password": "changeit"}
        ))
        self.assertFalse(result)

        result = yield ensureDeferred(self.auth_provider.check_auth(
            "subsidiary.example.org\\mainuser",
            'm.login.password',
            {"password": "abracadabra"}
        ))
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_email_login(self):
        result = yield ensureDeferred(self.auth_provider.check_3pid_auth(
            "email",
            "uniqueuser@main.example.org",
            "nothing",
        ))
        self.assertEqual(result, "@uniqueuser:test")
