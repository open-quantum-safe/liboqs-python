# OQS-python

This docker image contains python3 with library support for quantum-safe crypto
(QSC) operations.

To this end, it contains [liboqs](https://github.com/open-quantum-safe/liboqs)
as well as [OQS-OpenSSL](https://github.com/open-quantum-safe/openssl) from the
[OpenQuantumSafe](https://openquantumsafe.org) project all wrapped up in Python
APIs using [liboqs-python](https://github.com/open-quantum-safe/liboqs-python).

## Quick start

- Executing `docker run -it openquantumsafe/python` tests all QSC algorithms
  against the interop server at https://test.openquantumsafe.org.
- Executing `docker run -it openquantumsafe/python sh` provides a shell
  environment where liboqs and QSC-enabled SSL/TLS is available for use. See
  the included file `minitest.py` for sample code exercizing this
  functionality.

## Further examples

More samples are available at
[liboqs-python examples](https://github.com/open-quantum-safe/liboqs-python/tree/main/examples).
