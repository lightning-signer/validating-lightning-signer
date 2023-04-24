## Troubleshooting

### Resolving `poetry install` Failure Due to Keyring, DBus, or Unlock Issues in Headless Situations

When running poetry install in headless environments, you may
encounter issues related to unlocking the user's keyring. This is
because the standard keyring relies on a GUI. For more information,
refer to the following resources:

- [Using keyring on headless Linux systems](https://github.com/jaraco/keyring#using-keyring-on-headless-linux-systems)
- [Poetry issue #1917](https://github.com/python-poetry/poetry/issues/1917)

#### Solution

To work around this issue, set the `PYTHON_KEYRING_BACKEND` environment
variable to use the null keyring backend:
```bash
export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
```

By using the null keyring backend, Poetry will no longer attempt to
unlock the user's keyring during installation, thus avoiding the issue
in headless situations.

### Resolving `make` Failure While Building `lowdown` in the c-lightning Tree

When building c-lightning, you may encounter a `make` failure related
to `lowdown`. The actual error mentioning `lowdown` may be difficult
to spot due to the extensive diagnostic output from `make`. You may
need to scroll back or search carefully to find the error.

c-lightning uses `lowdown` to format its documentation. If `lowdown`
is not detected on your system, the build process will attempt to
create a copy, which might lead to an error.

#### Solution

To resolve this issue, manually install `lowdown` on your system.
For Ubuntu users, you can install `lowdown` using `apt-get`.
Fedora users can build from source.

After `lowdown` is installed the following commands should be executed from the
top-levrel `vls-hsmd` directory:
```bash
export HAVE_LOWDOWN=1
(cd lightning && ./configure)
make
```
