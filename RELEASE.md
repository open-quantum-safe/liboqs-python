# liboqs-python version 0.16.0.1

---

This is a maintenance release of liboqs-python 0.16.0 that fixes a security
issue. It is still built for liboqs 0.16.0. All users of liboqs-python
0.10.0 through 0.16.0 who rely on liboqs being installed automatically
should upgrade.

# Security fix in version 0.16.0.1

- **Shell command injection in automatic liboqs installation**
  ([GHSA-pw23-r5gj-42g8](https://github.com/open-quantum-safe/liboqs-python/security/advisories/GHSA-pw23-r5gj-42g8)).
  When liboqs was not found at import time, liboqs-python built it by running
  git and CMake through a shell, so shell metacharacters in `PYOQS_VERSION`,
  `OQS_INSTALL_PATH`, `HOME`, or `TMPDIR` could execute arbitrary commands.
  These commands now run without a shell, and `PYOQS_VERSION` is validated.

# Other changes in version 0.16.0.1

- Fixed automatic installation of liboqs release candidates (e.g.,
  `0.16.0-rc1`) and install paths that contain spaces.
- Added support for the ML-DSA external-mu variants when liboqs provides them
  (they are not in liboqs 0.16.0).
- Added installation instructions for Windows and Raspberry Pi.
- Releases are now published to PyPI automatically.

## About

The **Open Quantum Safe (OQS) project** has the goal of developing and
prototyping quantum-resistant cryptography. More information on OQS can be
found on our website https://openquantumsafe.org/ and on GitHub at
https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic
algorithms. See more about liboqs at
[https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/),
including a list of supported algorithms.

**liboqs-python** is an open source Python 3 wrapper for the liboqs C library
for quantum-resistant cryptographic algorithms. Details about liboqs-python can
be found in
[README.md](https://github.com/open-quantum-safe/liboqs-python/blob/main/README.md).
See in particular limitations on intended use.

---

## Release notes

This release of liboqs-python was released on September 23, 2026. Its release
page on GitHub is
https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.1.

---

## What's New

For a list of changes see
[CHANGES.md](https://github.com/open-quantum-safe/liboqs-python/blob/main/CHANGES.md).
