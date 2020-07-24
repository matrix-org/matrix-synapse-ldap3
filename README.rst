Synapse LDAP Auth Provider
==========================

Allows synapse to use LDAP as a password provider.

This allows users to log in to synapse with their username and password from an
LDAP server. There is also ma1sd (https://github.com/ma1uta/ma1sd) (3rd party)
that offers more fully-featured integration.

Installation
------------
- Included as standard in the deb packages and docker images from matrix.org.
- If you installed into a virtualenv: `pip install matrix-synapse-ldap3`.
- For other installation mechanisms, see the documentation provided by the maintainer.

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
           mail: "mail"
           name: "givenName"
        #bind_dn:
        #bind_password:
        #filter: "(objectClass=posixAccount)"

If you would like to specify more than one LDAP server for HA, you can provide uri parameter with a list.
Default HA strategy of ldap3.ServerPool is employed, so first available server is used.

.. code:: yaml

   password_providers:
    - module: "ldap_auth_provider.LdapAuthProvider"
      config:
        enabled: true
        uri:
           - "ldap://ldap1.example.com:389"
           - "ldap://ldap2.example.com:389"
        start_tls: true
        base: "ou=users,dc=example,dc=com"
        attributes:
           uid: "cn"
           mail: "email"
           name: "givenName"
        #bind_dn:
        #bind_password:
        #filter: "(objectClass=posixAccount)"

If you would like to enable login/registration via email, or givenName/email
binding upon registration, you need to enable search mode. An example config
in search mode is provided below:

.. code:: yaml

   password_providers:
    - module: "ldap_auth_provider.LdapAuthProvider"
      config:
        enabled: true
        mode: "search"
        uri: "ldap://ldap.example.com:389"
        start_tls: true
        base: "ou=users,dc=example,dc=com"
        attributes:
           uid: "cn"
           mail: "mail"
           name: "givenName"
        # Search auth if anonymous search not enabled
        bind_dn: "cn=hacker,ou=svcaccts,dc=example,dc=com"
        bind_password: "ch33kym0nk3y"
        #filter: "(objectClass=posixAccount)"

Active Directory forest accounts are also supported with custom
separator (`=` or `/`) in the following form: `login<separator>domain`.

Please note that common domain separators `@` and `\\` can not be used in Matrix
User Indentifiers (https://matrix.org/docs/spec/appendices#user-identifiers)
and `/` separator is used by default.

Let's say you have several domains in example.com forest:

.. code:: yaml

   password_providers:
    - module: "ldap_auth_provider.LdapAuthProvider"
      config:
        enabled: true
        mode: "search"
        uri: "ldap://main.example.com:389"
        base: "dc=example,dc=com"
        # Must be true for this feature to work
        ad_forest: true
        # Optional. Users from this domain may login
        # without specifying domain part
        default_domain: main.example.com
        # Optional. Default /
        mxid_domain_separator: /
        attributes:
           # This must be set to userPrincipalName
           # when ad_forest is true
           uid: "userPrincipalName"
           mail: "mail"
           name: "givenName"
        bind_dn: "cn=hacker,ou=svcaccts,dc=example,dc=com"
        bind_password: "ch33kym0nk3y"
        filter: "(objectClass=user)"

With this configuration you can use logins:

- `someuser/main.example.com` or `someuser`

  to login as `someuser` in domain `main.example.com`
- `someuser2/second.example.com`

  to login as `someuser2` in domain `second.example.com`

Troubleshooting and Debugging
-----------------------------

``matrix-synapse-ldap3`` logging is included in the Synapse homeserver log
(typically ``homeserver.log``). The LDAP plugin log level can be increased to
``DEBUG`` for troubleshooting and debugging by making the following modifications
to your Synapse server's logging configuration file:

- Set the value for `handlers.file.level` to `DEBUG`:

.. code:: yaml

   handlers:
     file:
       # [...]
       level: DEBUG

- Add the following to the `loggers` section:

.. code:: yaml

   loggers:
      # [...]
      ldap3:
        level: DEBUG
      ldap_auth_provider:
        level: DEBUG

Finally, restart your Synapse server for the changes to take effect:

.. code:: sh

   synctl restart
