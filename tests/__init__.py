# __init__.py
from ldap_auth_provider import LdapAuthProvider


def create_auth_provider(port, account_handler):
    "Creates an LdapAuthProvider from an LDAP server and a mock account_handler"

    config = LdapAuthProvider.parse_config({
        "enabled": True,
        "uri": "ldap://localhost:%s" % port,
        "base": "ou=people,dc=example,dc=org",
        "attributes": {
            "uid": "cn",
            "name": "gn",
            "mail": "mail",
        },
    })

    return LdapAuthProvider(config, account_handler=account_handler)
