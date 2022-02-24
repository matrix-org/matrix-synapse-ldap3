from asyncio.futures import Future
from typing import Any, Awaitable, Type

from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO

from ldap_auth_provider import LdapAuthProviderModule

LDIF = b"""\
dn: dc=org
dc: org
objectClass: dcObject

dn: dc=example,dc=org
dc: example
objectClass: dcObject
objectClass: organization

dn: dc=main,dc=example,dc=org
dc: main
objectClass: dcObject
objectClass: organization

dn: dc=subsidiary,dc=example,dc=org
dc: subsidiary
objectClass: dcObject
objectClass: organization

dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=users,dc=main,dc=example,dc=org
objectClass: organizationalUnit
ou: users

dn: ou=users,dc=subsidiary,dc=example,dc=org
objectClass: organizationalUnit
ou: users

dn: cn=bob,ou=people,dc=example,dc=org
cn: bob
objectclass: person
gn: bob
mail: bob@example.org
# password is: secret
userPassword: {SSHA}JMjHQf5qSsxHsPrCIisx5bghXbkU0JHKa97geQ==

dn: cn=jdoe,ou=people,dc=example,dc=org
cn: jdoe
gn: John Doe
objectClass: person
# password is: terces
userPassword: {SSHA}6QrGxQ1jDkE6HFflgoO9FJPdkOWe9/FLFZzVMw==

dn: cn=jsmith,ou=people,dc=example,dc=org
cn: jsmith
gn: John Smith
objectClass: person
# password is: eekretsay
userPassword: {SSHA}mtIQXzjeID+j1LdjduYB1kjaHPgup8UnK4ofgw==

dn: cn=mainuser,ou=users,dc=main,dc=example,dc=org
userPrincipalName: mainuser@main.example.org
cn: mainuser
gn: One Of
mail: mainuser@main.example.org
objectClass: user
# password is: abracadabra
userPassword: {SSHA}qLzlip9HesTLxT6qpWIawKXeKsy4L2h6

dn: cn=uniqueuser,ou=users,dc=main,dc=example,dc=org
userPrincipalName: uniqueuser@main.example.org
cn: uniqueuser
gn: One Of
mail: uniqueuser@main.example.org
objectClass: user
# password is: nothing
userPassword: {SSHA}jK5IJ/ozmZnEE5g6UU9WBsBBPe6LKFZz

dn: cn=nonmainuser,ou=users,dc=subsidiary,dc=example,dc=org
userPrincipalName: nonmainuser@subsidiary.example.org
cn: nonmainuser
gn: Someone Else
mail: nonmainuser@subsidiary.example.org
objectClass: user
# password is: simsalabim
userPassword: {SSHA}sHNj89kojBZ5DBHWDwwvzqmL0iuXn0mM

dn: cn=mainuser,ou=users,dc=subsidiary,dc=example,dc=org
userPrincipalName: mainuser@subsidiary.example.org
cn: mainuser
gn: One Of
mail: mainuser@main.example.org
objectClass: user
# password is: changeit
userPassword: {SSHA}AmOdJt9kOXZ2X4L89w00eKaPQN69W6yb

"""


async def _create_db():
    f = BytesIO(LDIF)
    db = await fromLDIFFile(f)
    f.close()
    return db


class _LDAPServerFactory(ServerFactory):
    def __init__(self, root, ldap_server_type: Type[LDAPServer] = LDAPServer):
        self.root = root
        self.protocol = ldap_server_type

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        return proto


class _LdapServer(object):
    def __init__(self, listener):
        self.listener = listener

        self._closed = False

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if not self._closed:
            self._closed = True
            self.listener.stopListening()


# When the LDAP Server protocol wants to manipulate the DIT, it invokes
# `root = interfaces.IConnectedLDAPEntry(self.factory)` to get the root
# of the DIT.  The factory that creates the protocol must therefore
# be adapted to the IConnectedLDAPEntry interface.
registerAdapter(lambda x: x.root, _LDAPServerFactory, IConnectedLDAPEntry)


async def create_ldap_server(ldap_server_type: Type[LDAPServer] = LDAPServer):
    "Returns a context manager that represents the LDAP server."

    db = await _create_db()
    factory = _LDAPServerFactory(db, ldap_server_type)
    factory.debug = True

    # We just pick an arbitrary port to listen on.
    serverEndpointStr = "tcp:0"
    e = serverFromString(reactor, serverEndpointStr)
    listener = await e.listen(factory)

    return _LdapServer(listener)


def create_auth_provider(server, api, config=None):
    "Creates an LdapAuthProviderModule from an LDAP server and a mock Module API"

    if config:
        config = LdapAuthProviderModule.parse_config(config)
    else:
        config = LdapAuthProviderModule.parse_config(
            {
                "enabled": True,
                "uri": "ldap://localhost:%d" % server.listener.getHost().port,
                "base": "ou=people,dc=example,dc=org",
                "attributes": {
                    "uid": "cn",
                    "name": "gn",
                    "mail": "mail",
                },
            }
        )

    return LdapAuthProviderModule(config, api=api)


def make_awaitable(result: Any) -> Awaitable[Any]:
    """
    Makes an awaitable, suitable for mocking an `async` function.
    This uses Futures as they can be awaited multiple times so can be returned
    to multiple callers.
    """
    future = Future()
    future.set_result(result)
    return future


def get_qualified_user_id(username):
    if not username.startswith("@"):
        return "@%s:test" % username

    return username
