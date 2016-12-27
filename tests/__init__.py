from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import ServerFactory
from twisted.internet import reactor, defer
from twisted.python.components import registerAdapter
from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from cStringIO import StringIO

from ldap_auth_provider import LdapAuthProvider


LDIF = """\
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
userPassword: {SSHA}JMjHQf5qSsxHsPrCIisx5bghXbkU0JHKa97geQ==

dn: cn=jdoe,ou=people,dc=example,dc=org
cn: jdoe
gn: John Doe
objectClass: person
userPassword: {SSHA}6QrGxQ1jDkE6HFflgoO9FJPdkOWe9/FLFZzVMw==

dn: cn=jsmith,ou=people,dc=example,dc=org
cn: jsmith
gn: John Smith
objectClass: person
userPassword: {SSHA}mtIQXzjeID+j1LdjduYB1kjaHPgup8UnK4ofgw==

"""


@defer.inlineCallbacks
def _create_db():
    f = StringIO(LDIF)
    db = yield fromLDIFFile(f)
    f.close()
    defer.returnValue(db)


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


@defer.inlineCallbacks
def create_ldap_server():
    "Returns a context manager that represents the LDAP server."

    db = yield _create_db()
    factory = _LDAPServerFactory(db)
    factory.debug = True

    # We just pick an arbitrary port to listen on.
    serverEndpointStr = "tcp:0"
    e = serverFromString(reactor, serverEndpointStr)
    listener = yield e.listen(factory)

    defer.returnValue(_LdapServer(listener))


def create_auth_provider(server, account_handler):
    "Creates an LdapAuthProvider from an LDAP server and a mock account_handler"

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
