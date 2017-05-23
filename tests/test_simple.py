# -*- coding: utf-8 -*-

import unittest
from . import create_auth_provider
from .ldap_server import get_reactor
import threading

from mock import Mock


class LdapSimpleTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Starts the Twisted-based "ldaptor" LDAP server in the
        background with some dummy data.
        """
        cls.reactor, cls.port = get_reactor()
        threading.Thread(target=cls.reactor.run, args=(False,)).start()

    @classmethod
    def tearDownClass(cls):
        """
        Stops the "ldaptor" LDAP server after tests done.
        """
        cls.reactor.callFromThread(cls.reactor.stop)

    def test_unknown_user(self):
        """
        Test for non existent user
        Must return: False
        """
        account_handler = Mock(spec_set=[])
        provider = create_auth_provider(self.port, account_handler)
        result = yield provider.check_password("@non_existent:test", "password")
        self.assertFalse(result)

    def test_incorrect_pwd(self):
        """
        Test incorrect password
        Must return: False
        """
        account_handler = Mock(spec_set=[])
        provider = create_auth_provider(self.port, account_handler)
        result = yield provider.check_password("@bob:test", "wrong_password")
        self.assertFalse(result)

    def test_correct_pwd(self):
        """
        Test for correct password
        Must return: True
        """
        account_handler = Mock(spec=["check_user_exists", "register", "hs"])
        account_handler.hs.get_handlers().profile_handler.store = Mock(
            spec_set=["user_add_threepid", "set_profile_displayname"]
        )
        account_handler.check_user_exists.return_value = True
        provider = create_auth_provider(self.port, account_handler)
        result = yield provider.check_password("@bob:test", "secret")
        self.assertTrue(result)

    def test_no_pwd(self):
        """
        Test for auth without password
        Must return: True
        """
        account_handler = Mock(spec=["check_user_exists", "register", "hs"])
        account_handler.hs.get_handlers().profile_handler.store = Mock(
            spec_set=["user_add_threepid", "set_profile_displayname"]
        )
        account_handler.check_user_exists.return_value = True
        provider = create_auth_provider(self.port, account_handler)
        result = yield provider.check_password("@bob:test", "")
        self.assertFalse(result)

    def test_no_mail_and_name(self):
        """
        Test for auth user without main and name attributes filed
        Must return: True
        """
        account_handler = Mock(spec=["check_user_exists", "register", "hs"])
        account_handler.hs.get_handlers().profile_handler.store = Mock(
            spec_set=["user_add_threepid", "set_profile_displayname"]
        )
        account_handler.check_user_exists.return_value = True
        provider = create_auth_provider(self.port, account_handler)
        result = yield provider.check_password("@jdoe:test", "terces")
        self.assertFalse(result)

    def test_multi_email(self):
        """
        Test for multiply email values
        Must return: True
        """
        account_handler = Mock(spec=["check_user_exists", "register", "hs"])
        account_handler.hs.get_handlers().profile_handler.store = Mock(
            spec_set=["user_add_threepid", "set_profile_displayname"]
        )
        account_handler.check_user_exists.return_value = True
        provider = create_auth_provider(self.port, account_handler)
        result = yield provider.check_password("@jin:test", "secret")
        self.assertTrue(result)
