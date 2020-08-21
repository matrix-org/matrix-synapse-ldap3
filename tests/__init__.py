from typing import Any

from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import ServerFactory
from twisted.internet import reactor
from twisted.python.components import registerAdapter
from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer
try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO

from ldap_auth_provider import LdapAuthProvider


LDIF = b"""\
dn: dc=org
dc: org
objectClass: dcObject

dn: dc=example,dc=org
dc: example
objectClass: dcObject
objectClass: organization

dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

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

"""


async def _create_db():
    f = BytesIO(LDIF)
    db = await fromLDIFFile(f)
    f.close()
    return db


class _LDAPServerFactory(ServerFactory):
    protocol = LDAPServer

    def __init__(self, root):
        self.root = root

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
registerAdapter(
    lambda x: x.root,
    _LDAPServerFactory,
    IConnectedLDAPEntry
)


async def create_ldap_server():
    "Returns a context manager that represents the LDAP server."

    db = await _create_db()
    factory = _LDAPServerFactory(db)
    factory.debug = True

    # We just pick an arbitrary port to listen on.
    serverEndpointStr = "tcp:0"
    e = serverFromString(reactor, serverEndpointStr)
    listener = await e.listen(factory)

    return _LdapServer(listener)


def create_auth_provider(server, account_handler, config=None):
    "Creates an LdapAuthProvider from an LDAP server and a mock account_handler"

    if config:
        config = LdapAuthProvider.parse_config(config)
    else:
        config = LdapAuthProvider.parse_config({
            "enabled": True,
            "uri": "ldap://localhost:%d" % server.listener.getHost().port,
            "base": "ou=people,dc=example,dc=org",
            "attributes": {
                "uid": "cn",
                "name": "gn",
                "mail": "mail",
            },
        })

    return LdapAuthProvider(config, account_handler=account_handler)


async def make_awaitable(result: Any) -> Any:
    return result
