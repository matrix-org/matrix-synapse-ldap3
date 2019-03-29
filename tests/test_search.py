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


class LdapSearchTestCase(unittest.TestCase):

    def ldap_search_config(self, server_port):
        """A config for the auth provider that supports searching"""
        return {
            "enabled": True,
            "mode": "search",
            "uri": "ldap://localhost:%d" % server_port,
            "base": "ou=people,dc=example,dc=org",
            "attributes": {
                "uid": "cn",
                "name": "gn",
                "mail": "mail",
            },
            "bind_dn": "cn=jsmith,dc=example,dc=org",
            "bind_password": "eekretsay",
        }

    @defer.inlineCallbacks
    def test_3pid_auth_fails_without_search_config(self):
        """Check that 3pid auth bails without the provider being in search mode"""
        server = yield create_ldap_server()
        with server:
            user_id = "@bob:example.com"
            email = "bob@example.com"

            account_handler = Mock(spec_set=["register", "check_user_exists"])
            account_handler.check_user_exists.return_value = False
            account_handler.register.return_value = (user_id, "accesstoken")
            provider = create_auth_provider(server, account_handler)

            result = yield provider.check_3pid_auth("email", email, "secret")
            self.assertEquals(result, None)
            account_handler.check_user_exists.assert_not_called()

    @defer.inlineCallbacks
    def test_3pid_auth(self):
        server = yield create_ldap_server()
        with server:
            user_id = "@bob:example.com"
            email = "bob@example.com"
            name = "bob"

            account_handler = Mock(spec_set=["register", "check_user_exists"])
            account_handler.check_user_exists.return_value = False
            account_handler.register.return_value = (user_id, "accesstoken")
            provider = create_auth_provider(
                server, account_handler, self.ldap_search_config(
                    server.listener.getHost().port,
                ),
            )

            result = yield provider.check_3pid_auth("email", email, "secret")
            self.assertEquals(result, user_id)
            self.assertItemsEqual(
                account_handler.register.call_args_list, [user_id, name, [email]],
            )
