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
from twisted.internet import defer

from mock import Mock

from . import create_ldap_server, create_auth_provider

import logging
logging.basicConfig()


class LdapSimpleTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def test_unknown_user(self):
        server = yield create_ldap_server()
        with server:
            account_handler = Mock(spec_set=[])
            provider = create_auth_provider(server, account_handler)

            result = yield provider.check_password("@non_existent:test", "password")
            self.assertFalse(result)

    @defer.inlineCallbacks
    def test_incorrect_pwd(self):
        server = yield create_ldap_server()
        with server:
            account_handler = Mock(spec_set=[])
            provider = create_auth_provider(server, account_handler)

            result = yield provider.check_password("@bob:test", "wrong_password")
            self.assertFalse(result)

    @defer.inlineCallbacks
    def test_correct_pwd(self):
        server = yield create_ldap_server()
        with server:
            account_handler = Mock(spec_set=["check_user_exists"])
            account_handler.check_user_exists.return_value = True
            provider = create_auth_provider(server, account_handler)

            result = yield provider.check_password("@bob:test", "secret")
            self.assertTrue(result)

    @defer.inlineCallbacks
    def test_no_pwd(self):
        server = yield create_ldap_server()
        with server:
            account_handler = Mock(spec_set=["check_user_exists"])
            account_handler.check_user_exists.return_value = True
            provider = create_auth_provider(server, account_handler)

            result = yield provider.check_password("@bob:test", "")
            self.assertFalse(result)
