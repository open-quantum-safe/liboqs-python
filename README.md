# liboqs-python: Python 3 bindings for liboqs

[![GitHub actions](https://github.com/open-quantum-safe/liboqs-python/actions/workflows/python_simplified.yml/badge.svg)](https://github.com/open-quantum-safe/liboqs-python/actions)

---

## About

The **Open Quantum Safe (OQS) project** has the goal of developing and
prototyping quantum-resistant cryptography.

**liboqs-python** offers a Python 3 wrapper for the
[Open Quantum Safe](https://openquantumsafe.org/)
[liboqs](https://github.com/open-quantum-safe/liboqs/)
C library, which is a C library for quantum-resistant cryptographic algorithms.

The wrapper is written in Python 3, hence in the following it is assumed that
you have access to a Python 3 interpreter. liboqs-python has been extensively
tested on Linux, macOS and Windows platforms. Continuous integration is
provided via GitHub actions.

The project contains the following files and directories:

- **`oqs/oqs.py`: a Python 3 module wrapper for the liboqs C library.**
- `oqs/rand.py`: a Python 3 module supporting RNGs from `<oqs/rand.h>`
- `examples/kem.py`: key encapsulation example
- `examples/rand.py`: RNG example
- `examples/sig.py`: signature example
- `tests`: unit tests

---

## Pre-requisites

- [liboqs](https://github.com/open-quantum-safe/liboqs)
- [git](https://git-scm.com/)
- [CMake](https://cmake.org/)
- C compiler,
  e.g., [gcc](https://gcc.gnu.org/), [clang](https://clang.llvm.org),
  [MSVC](https://visualstudio.microsoft.com/vs/) etc.
- [Python 3](https://www.python.org/)

---

## Installation

### Configure, build and install liboqs

Execute in a Terminal/Console/Administrator Command Prompt

```shell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
cmake --build liboqs/build --target install
```

The last line may require prefixing it by `sudo` on UNIX-like systems. Change
`--parallel 8` to match the number of available cores on your system.

On UNIX-like platforms, you may need to set the `LD_LIBRARY_PATH`
(`DYLD_LIBRARY_PATH` on macOS) environment variable to point to the path to
liboqs' library directory, e.g.,

```shell
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

On Windows platforms, **you must ensure** that you add the
`-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE` flag to CMake, and that the liboqs
shared library `oqs.dll` is visible system-wide, i.e., set the `PATH`
environment variable accordingly by using the "Edit the system environment
variables" Control Panel tool or executing in a Command Prompt

```shell
set PATH=%PATH%;C:\Program Files (x86)\liboqs\bin
```

You can change liboqs' installation directory by configuring the build to use
an alternative path, e.g., `C:\liboqs`, by passing the
`-DCMAKE_INSTALL_PREFIX=/path/to/liboqs` flag to CMake, e.g.,

```shell
cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX="C:\liboqs" -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -DBUILD_SHARED_LIBS=ON
```

### Let liboqs-python install liboqs automatically

If liboqs is not detected at runtime by liboqs-python, it will be downloaded,
configured and installed automatically (as a shared library). This process will
be performed only once, at runtime, i.e., when loading the liboqs-python
wrapper. The liboqs source directory will be automatically removed at the end
of the process.

This is convenient in case you want to avoid installing liboqs manually, as
described in the subsection above.

### Install and activate a Python virtual environment

Execute in a Terminal/Console/Administrator Command Prompt

```shell
python3 -m venv venv
. venv/bin/activate
python3 -m ensurepip --upgrade
```

On Windows, replace the line

```shell
. venv/bin/activate
```

by

```shell
venv\Scripts\activate.bat
```

### Configure and install the wrapper

Execute in a Terminal/Console/Administrator Command Prompt

```shell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```

### Run the examples

Execute

```shell
python3 liboqs-python/examples/kem.py
python3 liboqs-python/examples/sig.py
python3 liboqs-python/examples/rand.py
```

### Run the unit test

Execute

```shell
nose2 --verbose liboqs-python
```

---

## Usage in standalone applications

liboqs-python can be imported into Python programs with

```python
import oqs
```

liboqs-python defines two main classes: `KeyEncapsulation` and `Signature`,
providing post-quantum key encapsulation and signature mechanisms,
respectively. Each must be instantiated with a string identifying one of
mechanisms supported by liboqs; these can be enumerated using the
`get_enabled_KEM_mechanisms()` and `get_enabled_sig_mechanisms()` functions.
The files in `examples/` demonstrate the wrapper's API. Support for alternative
RNGs is provided via the `randombytes_*()` functions.

The liboqs-python project should be in the `PYTHONPATH`. To ensure this on
UNIX-like systems, execute

```shell
export PYTHONPATH=$PYTHONPATH:/path/to/liboqs-python
```

or, on Windows platforms, use the "Edit the system environment variables"
Control Panel tool or execute in a Command Prompt

```shell
set PYTHONPATH=%PYTHONPATH%;C:\path\to\liboqs-python
```

---

## Docker

A self-explanatory minimalistic Docker file is provided in
[`Dockerfile`](https://github.com/open-quantum-safe/liboqs-python/tree/main/Dockerfile).

Build the image by executing

```shell
docker build -t oqs-python .
```

Run, e.g., the key encapsulation example by executing

```shell
docker run -it oqs-python sh -c ". venv/bin/activate && python liboqs-python/examples/kem.py"
```

Or, run the unit tests with

```shell
docker run -it oqs-python sh -c ". venv/bin/activate && nose2 --verbose liboqs-python"
```

In case you want to use the Docker container as a development environment,
mount your current project in the Docker container with

```shell
docker run --rm -it --workdir=/app -v ${PWD}:/app oqs-python /bin/bash
```

A more comprehensive Docker example is provided in the directory
[`docker`](https://github.com/open-quantum-safe/liboqs-python/tree/main/docker).

---

## Limitations and security

liboqs is designed for prototyping and evaluating quantum-resistant
cryptography. Security of proposed quantum-resistant algorithms may rapidly
change as research advances, and may ultimately be completely insecure against
either classical or quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is
currently the best avenue to identifying potentially quantum-resistant
algorithms. liboqs does not intend to "pick winners", and we strongly recommend
that applications and protocols rely on the outcomes of the NIST
standardization project when deploying post-quantum cryptography.

We acknowledge that some parties may want to begin deploying post-quantum
cryptography prior to the conclusion of the NIST standardization project. We
strongly recommend that any attempts to do make use of so-called
**hybrid cryptography**, in which post-quantum public-key algorithms are used
alongside traditional public key algorithms (like RSA or elliptic curves) so
that the solution is at least no less secure than existing traditional
cryptography.

Just like liboqs, liboqs-python is provided "as is", without warranty of any
kind. See
[LICENSE](https://github.com/open-quantum-safe/liboqs-python/blob/main/LICENSE)
for the full disclaimer.

---

## License

liboqs-python is licensed under the MIT License; see
[LICENSE](https://github.com/open-quantum-safe/liboqs-python/blob/main/LICENSE)
for details.

---

## Team

The Open Quantum Safe project is led by
[Douglas Stebila](https://www.douglas.stebila.ca/research/) and
[Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of
Waterloo.

### Contributors

Contributors to the liboqs-python wrapper include:

- Ben Davies (University of Waterloo)
- Vlad Gheorghiu ([softwareQ Inc.](https://www.softwareq.ca) and the University
  of Waterloo)
- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)

---

## Support

Financial support for the development of Open Quantum Safe has been provided by
Amazon Web Services and the Canadian Centre for Cyber Security.

We'd like to make a special acknowledgement to the companies who have dedicated
programmer time to contribute source code to OQS, including Amazon Web
Services, evolutionQ, softwareQ, and Microsoft Research.

Research projects which developed specific components of OQS have been
supported by various research grants, including funding from the Natural
Sciences and Engineering Research Council of Canada (NSERC); see the source
papers for funding acknowledgments.
