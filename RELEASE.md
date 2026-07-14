# liboqs-python version 0.16.0

---

# Added in version 0.16.0 <!-- TODO: release month/year -->

- Updated to liboqs 0.16.0.
- Added the `PYOQS_VERSION` environment variable to override the liboqs
  release that is installed automatically at runtime.
- Fixed the Windows shared library lookup to search for both `oqs.dll` and
  `liboqs.dll`.
- Fixed a `StatefulSignature` segfault when liboqs is built without stateful
  signature key generation support.

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

This release of liboqs-python was released on <!-- TODO: release date -->. Its release
page on GitHub is
https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.

---

## What's New

For a list of changes see
[CHANGES.md](https://github.com/open-quantum-safe/liboqs-python/blob/main/CHANGES.md).
