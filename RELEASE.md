# liboqs-python version 0.16.0.2

---

This is a maintenance release of liboqs-python 0.16.0 that fixes a security
issue. It is still built for liboqs 0.16.0. All users of liboqs-python
0.16.0.1 or earlier should upgrade.

# Security fix in version 0.16.0.2

- **ML-DSA signature forgery and ML-KEM shared-secret recovery with short
  public keys**
  ([GHSA-w696-4vrr-x6x3](https://github.com/open-quantum-safe/liboqs-python/security/advisories/GHSA-w696-4vrr-x6x3)).
  liboqs-python did not check the length of public keys, ciphertexts, and
  secret keys, and silently zero-padded a short value before passing it to
  liboqs. If an application passed an empty or very short public key, for
  example because a key field was missing or truncated, `Signature.verify`
  could accept a forged ML-DSA signature on any message, and
  `KeyEncapsulation.encap_secret` could produce an ML-KEM shared secret that
  anyone who sees the ciphertext can compute. `StatefulSignature.verify`
  instead let liboqs read past the end of a short public key. Public keys,
  ciphertexts, and secret keys of the wrong length now raise `ValueError`.

# Other fixes in version 0.16.0.2

- **`StatefulSignature` releases its native resources.** `free()`, which is
  also called when a `with` block exits, now frees the native `OQS_SIG_STFL`
  struct and securely erases and frees the native secret key. Both previously
  leaked.
- **`free()` is safe to call more than once.** Calling `free()` on a
  `KeyEncapsulation` or `Signature` after its `with` block had exited
  previously freed the native struct twice.

# Behavior changes in version 0.16.0.2

These fixes can make code that previously ran without error raise an
exception:

- A public key, ciphertext, or secret key of the wrong length raises
  `ValueError`. An empty `secret_key` passed to the `KeyEncapsulation` or
  `Signature` constructor also raises `ValueError` instead of being ignored.
- Calling a `StatefulSignature` method after `free()` raises `RuntimeError`.
  Previously it could crash, and `verify()` returned `False`.
- `StatefulSignature.free()` erases the native secret key, so call
  `export_secret_key()` first if you still need it.

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

This release of liboqs-python was released on October 28, 2026. Its release
page on GitHub is
https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.2.

---

## What's New

For a list of changes see
[CHANGES.md](https://github.com/open-quantum-safe/liboqs-python/blob/main/CHANGES.md).
