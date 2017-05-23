from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter
from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from cStringIO import StringIO

"""
This is a pure Python implementation of a very simple
LDAP server, based on "ldaptor" and the example from the
"ldaptor" documentation.
"""

# Dummy LDAP data. This needs to be valid LDIF, so the
# indentation and newlines are important here.
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
userPassword: secret
gn: Bob

dn: cn=jin,ou=people,dc=example,dc=org
cn: jin
objectclass: person
gn: jin
mail: jinn@example.org
mail: jin@example.org
userPassword: secret
gn: Jin

dn: cn=jdoe,ou=people,dc=example,dc=org
cn: jdoe
gn: John Doe
objectClass: person
userPassword: terces

dn: cn=jsmith,ou=people,dc=example,dc=org
cn: jsmith
gn: John Smith
objectClass: person
userPassword: eekretsay

"""


class Tree(object):

    def __init__(self):
        global LDIF
        self.f = StringIO(LDIF)
        d = fromLDIFFile(self.f)
        d.addCallback(self.ldifRead)

    def ldifRead(self, result):
        self.f.close()
        self.db = result


class LDAPServerFactory(ServerFactory):
    protocol = LDAPServer

    def __init__(self, root):
        self.root = root

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        return proto


def get_reactor():
    """
    :returns: the twisted reactor and the port number for the LDAP server
    :rtype: tuple
    """
    from twisted.internet import reactor
    # We initialize our tree
    tree = Tree()
    # When the LDAP Server protocol wants to manipulate the DIT, it invokes
    # `root = interfaces.IConnectedLDAPEntry(self.factory)` to get the root
    # of the DIT.  The factory that creates the protocol must therefore
    # be adapted to the IConnectedLDAPEntry interface.
    registerAdapter(
        lambda x: x.root,
        LDAPServerFactory,
        IConnectedLDAPEntry)
    factory = LDAPServerFactory(tree.db)
    factory.debug = False
    listener = reactor.listenTCP(0, factory)
    port = listener.getHost().port
    return reactor, port


if __name__ == '__main__':
    reactor, port = get_reactor()
    print("Running LDAP on port %s" % port)
    reactor.run()
