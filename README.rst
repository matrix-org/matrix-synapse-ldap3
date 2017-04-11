Synapse LDAP Auth Provider
==========================

Allows synapse to use LDAP as a password provider.

Installation
------------
- Via deb package `python-matrix-synapse-ldap3` available in the same repo as the synapse package
- Via python's package manager: `pip install matrix-synapse-ldap3`
- Via python's package manager from git: `pip install https://github.com/matrix-org/matrix-synapse-ldap3/tarball/master`

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
           uid: "samaccountname"
           mail: "email"
           name: "DisplayName"
        #bind_dn:
        #bind_password:
        #filter: "(&(objectClass=user)(objectCategory=person))"

Do not use ``cn`` attribute as uid. It's common mistake: ``cn`` attribute not uniqe in LDAP tree in most schemas!
It's work fine only in very simple LDAP installations without complex Organizational Units structire.
You can use: ``samaccountname``, ``uid`` or ``userPrincipalName`` (depending on the schemes in your system). These attributes are always unique.


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

