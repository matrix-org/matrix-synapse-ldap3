# How to release `matrix-synapse-ldap3`

Releasing `matrix-synapse-ldap3` involves bumping the version number, creating
a new tag on Github, then uploading release packages to
[PyPi](https://pypi.org) and Matrix.org's debian repos.

You will need push access to this repo as well as an account on PyPi with push
access to the
[matrix-synapse-ldap3](https://pypi.org/project/matrix-synapse-ldap3/) package.

## Git repository

1. Edit the `__version__` variable of `ldap_auth_provider.py` to the new release
version. This repository uses [Semantic Versioning](https://semver.org/).

1. Commit and push with the commit message `X.Y.Z`.

1. Create a git tag with `git tag -s vX.Y.Z`. Set the first line of the message
   to `vX.Y.Z`, and the rest to the changes since the last release (looking at
   the commit history can help).

1. Push the tag with `git push origin tag vX.Y.Z`

## Uploading to PyPi

Ensure you have access to the `twine` command.

1. Run `python setup.py sdist` to build the package

1. `twine upload dist/matrix-synapse-ldap3-X.Y.Z.tar.gz` to upload the package to PyPi.

## Uploading debian packages

TODO
