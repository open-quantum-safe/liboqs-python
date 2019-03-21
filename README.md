liboqs-python
=============

[![CircleCI](https://circleci.com/gh/open-quantum-safe/liboqs-python.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/liboqs-python)

**liboqs-python** offers a python module wrapping the [Open Quantum Safe](https://openquantumsafe.org/) [liboqs](https://github.com/open-quantum-safe/liboqs/) C library.

Contents
--------

The project contains the following files:

 - `oqs/wrapper.py`: a python 3 module wrapper for the liboqs C library.
 - `examples/example.py`: illustrates the usage of the liboqs python wrapper.
 - `tests/test_*.py`: unit tests for the python liboqs python wrapper.

Usage
-----

liboqs-python defines two main classes: `KeyEncapsulation` and `Signature`, providing post-quantum key encapsulation and signture mechanisms, respectively. Each must be instantiated with a string identifying one of mechanisms supported by liboqs; these can be enumerated using the `get_enabled_KEM_mechanisms` and `get_enabled_sig_mechanisms` functions. The `example.py` file details the wrapper's API.

liboqs installation
-------------------

liboqs-python depends on the liboqs C library; it must be compiled as a Linux/macOS library or Windows DLL, and installed in one of:

* any file path specified by the LIBOQS_INSTALL_PATH environment variable (e.g. `LIBOQS_INSTALL_PATH="/path/to/liboqs.so"`)
* system-wide folder
* the liboqs Python module's current folder

`wrapper.py` checks the above locations in that order. At present, only liboqs master branch can be installed; see the [liboqs project](https://github.com/open-quantum-safe/liboqs/) for installation instructions.

liboqs-python does not depend on any other python packages. The package isn't hosted on PyPI yet, but can be installed into a virtualenv using:

	# create & activate virtual environment, e.g.:
	python3 -venv <virtualenv_name>

	cd /some/dir/liboqs-python
	python3 setup.py install

Running
-------

The liboqs-python project should be in the PYTHONPATH:

	export PYTHONPATH=/some/dir/liboqs-python

As any python module, liboqs wrapper components can be imported into python programs with `import oqs`.

To run the example program:

	python3 examples/example.py

To run the unit tests with a test runner (e.g. nose or rednose (`apt install python3-nose python3-rednose` or `pip3 install nose rednose`)):

	python3 -m nose --rednose --verbose

To run the unit tests without a test runner:

	python3 tests/test_kem.py
	python3 tests/test_sig.py

The module has been tested using Python 3 on Linux Debian 10 (Buster), Linux Ubuntu 16.04.5, macOS 10.14.3, and Windows 10.  We run continuous integration tests on CircleCI on Linux Debian 10 (Buster) on amd64.

Limitations and security
------------------------

liboqs is designed for prototyping and evaluating quantum-resistant cryptography. Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms. liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project. We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

Just like liboqs, liboqs-python is provided "as is", without warranty of any kind. See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs-python/blob/master/LICENSE.txt) for the full disclaimer.

License
-------

liboqs-python is licensed under the MIT License; see [LICENSE.txt](https://github.com/open-quantum-safe/liboqs-python/blob/master/LICENSE.txt) for details.

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

### Contributors

Contributors to the liboqs-python wrapper include:

- Ben Davies (University of Waterloo)
- Christian Paquin (Microsoft Research)
