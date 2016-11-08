Synapse LDAP Auth Provider
==========================

Allows synapse to use LDAP as a password provider.


Usage
-----

Example synapse config:

.. code:: yaml

   password_providers:
    - module: "ldap_auth_provider.LdapAuthProvider"
      config:
        enabled: true
        uri: "ldap://ldap.example.com:389"
        start_tls: true
        base: "ou=users,dc=example,dc=com"
        attributes:
           uid: "cn"
           mail: "email"
           name: "givenName"
        #bind_dn:
        #bind_password:
        #filter: "(objectClass=posixAccount)"
