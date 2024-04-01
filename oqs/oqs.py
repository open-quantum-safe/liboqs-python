"""
Open Quantum Safe (OQS) Python wrapper for liboqs

The liboqs project provides post-quantum public key cryptography algorithms:
https://github.com/open-quantum-safe/liboqs

This module provides a Python 3 interface to liboqs.
"""

import ctypes as ct  # to call native
import ctypes.util as ctu
import importlib.metadata  # to determine module version at runtime
import os  # to run OS commands (install liboqs on demand if not found)
import platform  # to learn the OS we're on
import sys
import tempfile  # to install liboqs on demand
import time
import warnings


def oqs_python_version():
    """liboqs-python version string."""
    try:
        result = importlib.metadata.version("liboqs-python")
    except importlib.metadata.PackageNotFoundError:
        warnings.warn("Please install liboqs-python using pip install")
        return None
    return result


# liboqs-python tries to automatically install and load this liboqs version in
# case no other version is found
OQS_VERSION = oqs_python_version()


def _countdown(seconds):
    while seconds > 0:
        print(seconds, end=" ")
        sys.stdout.flush()
        seconds -= 1
        time.sleep(1)
    print()


def _load_shared_obj(name, additional_searching_paths=None):
    """Attempts to load shared library."""
    paths = []
    dll = ct.windll if platform.system() == "Windows" else ct.cdll

    # Search additional path, if any
    if additional_searching_paths:
        for path in additional_searching_paths:
            if platform.system() == "Darwin":
                paths.append(
                    os.path.abspath(path) + os.path.sep + "lib" + name + ".dylib"
                )
            elif platform.system() == "Windows":
                paths.append(os.path.abspath(path) + os.path.sep + name + ".dll")
                # Does not work
                # os.environ["PATH"] += os.path.abspath(path)
            else:  # Linux/FreeBSD/UNIX
                paths.append(os.path.abspath(path) + os.path.sep + "lib" + name + ".so")
                # https://stackoverflow.com/questions/856116/changing-ld-library-path-at-runtime-for-ctypes
                # os.environ["LD_LIBRARY_PATH"] += os.path.abspath(path)

    # Search typical locations
    try:
        paths.insert(0, ctu.find_library(name))
    except FileNotFoundError:
        pass
    try:
        paths.insert(0, ctu.find_library("lib" + name))
    except FileNotFoundError:
        pass

    for path in paths:
        if path:
            try:
                lib = dll.LoadLibrary(path)
                return lib
            except OSError:
                pass

    raise RuntimeError("No " + name + " shared libraries found")


def _install_liboqs(target_directory, oqs_version=None):
    """Install liboqs version oqs_version (if None, installs latest at HEAD) in the target_directory."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        oqs_install_str = (
            "cd "
            + tmpdirname
            + " && git clone https://github.com/open-quantum-safe/liboqs"
        )
        if oqs_version:
            oqs_install_str += " --branch " + oqs_version
        oqs_install_str += (
            " --depth 1 && cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX="
            + target_directory
        )
        if platform.system() == "Windows":
            oqs_install_str += " -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE"
        oqs_install_str += " && cmake --build liboqs/build --parallel 4 && cmake --build liboqs/build --target install"
        print("liboqs not found, installing it in " + target_directory)
        _countdown(5)
        os.system(oqs_install_str)
        print("Done installing liboqs")


def _load_liboqs():
    home_dir = os.path.expanduser("~")
    oqs_install_dir = os.path.abspath(home_dir + os.path.sep + "_oqs")  # $HOME/_oqs
    oqs_lib_dir = (
        os.path.abspath(oqs_install_dir + os.path.sep + "bin")  # $HOME/_oqs/bin
        if platform.system() == "Windows"
        else os.path.abspath(oqs_install_dir + os.path.sep + "lib")  # $HOME/_oqs/lib
    )
    try:
        _liboqs = _load_shared_obj(name="oqs", additional_searching_paths=[oqs_lib_dir])
        assert _liboqs
    except RuntimeError:
        # We don't have liboqs, so we try to install it automatically
        _install_liboqs(target_directory=oqs_install_dir, oqs_version=OQS_VERSION)
        # Try loading it again
        try:
            _liboqs = _load_shared_obj(
                name="oqs", additional_searching_paths=[oqs_lib_dir]
            )
            assert _liboqs
        except RuntimeError:
            sys.exit("Could not load liboqs shared library")

    return _liboqs


_liboqs = _load_liboqs()


# Expected return value from native OQS functions
OQS_SUCCESS = 0
OQS_ERROR = -1


def native():
    """Handle to native liboqs handler."""
    return _liboqs


# liboqs initialization
native().OQS_init()


def oqs_version():
    """liboqs version string."""
    native().OQS_version.restype = ct.c_char_p
    return ct.c_char_p(native().OQS_version()).value.decode("UTF-8")


# Warn the user if the liboqs version differs from liboqs-python version
if oqs_version() != oqs_python_version():
    warnings.warn(
        "liboqs version {} differs from liboqs-python version {}".format(
            oqs_version(), oqs_python_version()
        )
    )


class MechanismNotSupportedError(Exception):
    """Exception raised when an algorithm is not supported by OQS."""

    def __init__(self, alg_name):
        """
        :param alg_name: requested algorithm name.
        """
        self.alg_name = alg_name
        self.message = alg_name + " is not supported by OQS"


class MechanismNotEnabledError(MechanismNotSupportedError):
    """Exception raised when an algorithm is supported but not enabled by OQS."""

    def __init__(self, alg_name):
        """
        :param alg_name: requested algorithm name.
        """
        self.alg_name = alg_name
        self.message = alg_name + " is supported but not enabled by OQS"


class KeyEncapsulation(ct.Structure):
    """
    An OQS KeyEncapsulation wraps native/C liboqs OQS_KEM structs.

    The wrapper maps methods to the C equivalent as follows:

    Python            |  C liboqs
    -------------------------------
    generate_keypair  |  keypair
    encap_secret      |  encaps
    decap_secret      |  decaps
    free              |  OQS_KEM_free
    """

    _fields_ = [
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("claimed_nist_level", ct.c_ubyte),
        ("ind_cca", ct.c_ubyte),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_ciphertext", ct.c_size_t),
        ("length_shared_secret", ct.c_size_t),
        ("keypair_cb", ct.c_void_p),
        ("encaps_cb", ct.c_void_p),
        ("decaps_cb", ct.c_void_p),
    ]

    def __init__(self, alg_name, secret_key=None):
        """
        Creates new KeyEncapsulation with the given algorithm.

        :param alg_name: KEM mechanism algorithm name. Enabled KEM mechanisms can be obtained with
        get_enabled_KEM_mechanisms().
        :param secret_key: optional if generating by generate_keypair() later.
        """
        super().__init__()
        self.alg_name = alg_name
        if alg_name not in _enabled_KEMs:
            # perhaps it's a supported but not enabled alg
            if alg_name in _supported_KEMs:
                raise MechanismNotEnabledError(alg_name)
            else:
                raise MechanismNotSupportedError(alg_name)

        self._kem = native().OQS_KEM_new(ct.create_string_buffer(alg_name.encode()))

        self.details = {
            "name": self._kem.contents.method_name.decode(),
            "version": self._kem.contents.alg_version.decode(),
            "claimed_nist_level": int(self._kem.contents.claimed_nist_level),
            "is_ind_cca": bool(self._kem.contents.ind_cca),
            "length_public_key": int(self._kem.contents.length_public_key),
            "length_secret_key": int(self._kem.contents.length_secret_key),
            "length_ciphertext": int(self._kem.contents.length_ciphertext),
            "length_shared_secret": int(self._kem.contents.length_shared_secret),
        }

        if secret_key:
            self.secret_key = ct.create_string_buffer(
                secret_key, self._kem.contents.length_secret_key
            )

    def __enter__(self):
        return self

    def __exit__(self, ctx_type, ctx_value, ctx_traceback):
        self.free()

    def generate_keypair(self):
        """
        Generates a new keypair and returns the public key.

        If needed, the secret key can be obtained with export_secret_key().
        """
        public_key = ct.create_string_buffer(self._kem.contents.length_public_key)
        self.secret_key = ct.create_string_buffer(self._kem.contents.length_secret_key)
        rv = native().OQS_KEM_keypair(
            self._kem, ct.byref(public_key), ct.byref(self.secret_key)
        )
        return bytes(public_key) if rv == OQS_SUCCESS else 0

    def export_secret_key(self):
        """Exports the secret key."""
        return bytes(self.secret_key)

    def encap_secret(self, public_key):
        """
        Generates and encapsulates a secret using the provided public key.

        :param public_key: the peer's public key.
        """
        my_public_key = ct.create_string_buffer(
            public_key, self._kem.contents.length_public_key
        )
        ciphertext = ct.create_string_buffer(self._kem.contents.length_ciphertext)
        shared_secret = ct.create_string_buffer(self._kem.contents.length_shared_secret)
        rv = native().OQS_KEM_encaps(
            self._kem, ct.byref(ciphertext), ct.byref(shared_secret), my_public_key
        )
        return bytes(ciphertext), bytes(shared_secret) if rv == OQS_SUCCESS else 0

    def decap_secret(self, ciphertext):
        """
        Decapsulates the ciphertext and returns the secret.

        :param ciphertext: the ciphertext received from the peer.
        """
        my_ciphertext = ct.create_string_buffer(
            ciphertext, self._kem.contents.length_ciphertext
        )
        shared_secret = ct.create_string_buffer(self._kem.contents.length_shared_secret)
        rv = native().OQS_KEM_decaps(
            self._kem, ct.byref(shared_secret), my_ciphertext, self.secret_key
        )
        return bytes(shared_secret) if rv == OQS_SUCCESS else 0

    def free(self):
        """Releases the native resources."""
        if hasattr(self, "secret_key"):
            native().OQS_MEM_cleanse(
                ct.byref(self.secret_key), self._kem.contents.length_secret_key
            )
        native().OQS_KEM_free(self._kem)

    def __repr__(self):
        return "Key encapsulation mechanism: " + self._kem.contents.method_name.decode()


native().OQS_KEM_new.restype = ct.POINTER(KeyEncapsulation)
native().OQS_KEM_alg_identifier.restype = ct.c_char_p


def is_kem_enabled(alg_name):
    """
    Returns True if the KEM algorithm is enabled.

    :param alg_name: a KEM mechanism algorithm name.
    """
    return native().OQS_KEM_alg_is_enabled(ct.create_string_buffer(alg_name.encode()))


_KEM_alg_ids = [
    native().OQS_KEM_alg_identifier(i) for i in range(native().OQS_KEM_alg_count())
]
_supported_KEMs = [i.decode() for i in _KEM_alg_ids]
_enabled_KEMs = [i for i in _supported_KEMs if is_kem_enabled(i)]


def get_enabled_kem_mechanisms():
    """Returns the list of enabled KEM mechanisms."""
    return _enabled_KEMs


def get_supported_kem_mechanisms():
    """Returns the list of supported KEM mechanisms."""
    return _supported_KEMs


class Signature(ct.Structure):
    """
    An OQS Signature wraps native/C liboqs OQS_SIG structs.

    The wrapper maps methods to the C equivalent as follows:

    Python            |  C liboqs
    -------------------------------
    generate_keypair  |  keypair
    sign              |  sign
    verify            |  verify
    free              |  OQS_SIG_free
    """

    _fields_ = [
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("claimed_nist_level", ct.c_ubyte),
        ("euf_cma", ct.c_ubyte),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_signature", ct.c_size_t),
        ("keypair_cb", ct.c_void_p),
        ("sign_cb", ct.c_void_p),
        ("verify_cb", ct.c_void_p),
    ]

    def __init__(self, alg_name, secret_key=None):
        """
        Creates new Signature with the given algorithm.

        :param alg_name: a signature mechanism algorithm name. Enabled signature mechanisms can be obtained with
        get_enabled_sig_mechanisms().
        :param secret_key: optional, if generated by generate_keypair().
        """
        super().__init__()
        if alg_name not in _enabled_sigs:
            # perhaps it's a supported but not enabled alg
            if alg_name in _supported_sigs:
                raise MechanismNotEnabledError(alg_name)
            else:
                raise MechanismNotSupportedError(alg_name)

        self._sig = native().OQS_SIG_new(ct.create_string_buffer(alg_name.encode()))
        self.details = {
            "name": self._sig.contents.method_name.decode(),
            "version": self._sig.contents.alg_version.decode(),
            "claimed_nist_level": int(self._sig.contents.claimed_nist_level),
            "is_euf_cma": bool(self._sig.contents.euf_cma),
            "length_public_key": int(self._sig.contents.length_public_key),
            "length_secret_key": int(self._sig.contents.length_secret_key),
            "length_signature": int(self._sig.contents.length_signature),
        }

        if secret_key:
            self.secret_key = ct.create_string_buffer(
                secret_key, self._sig.contents.length_secret_key
            )

    def __enter__(self):
        return self

    def __exit__(self, ctx_type, ctx_value, ctx_traceback):
        self.free()

    def generate_keypair(self):
        """
        Generates a new keypair and returns the public key.

        If needed, the secret key can be obtained with export_secret_key().
        """
        public_key = ct.create_string_buffer(self._sig.contents.length_public_key)
        self.secret_key = ct.create_string_buffer(self._sig.contents.length_secret_key)
        rv = native().OQS_SIG_keypair(
            self._sig, ct.byref(public_key), ct.byref(self.secret_key)
        )
        return bytes(public_key) if rv == OQS_SUCCESS else 0

    def export_secret_key(self):
        """Exports the secret key."""
        return bytes(self.secret_key)

    def sign(self, message):
        """
        Signs the provided message and returns the signature.

        :param message: the message to sign.
        """
        # Provide length to avoid extra null char
        my_message = ct.create_string_buffer(message, len(message))
        message_len = ct.c_int(len(my_message))
        signature = ct.create_string_buffer(self._sig.contents.length_signature)
        sig_len = ct.c_int(
            self._sig.contents.length_signature
        )  # initialize to maximum signature size
        rv = native().OQS_SIG_sign(
            self._sig,
            ct.byref(signature),
            ct.byref(sig_len),
            my_message,
            message_len,
            self.secret_key,
        )

        return bytes(signature[: sig_len.value]) if rv == OQS_SUCCESS else 0

    def verify(self, message, signature, public_key):
        """
        Verifies the provided signature on the message; returns True if valid.

        :param message: the signed message.
        :param signature: the signature on the message.
        :param public_key: the signer's public key.
        """
        # Provide length to avoid extra null char
        my_message = ct.create_string_buffer(message, len(message))
        message_len = ct.c_int(len(my_message))

        # Provide length to avoid extra null char in sig
        my_signature = ct.create_string_buffer(signature, len(signature))
        sig_len = ct.c_int(len(my_signature))
        my_public_key = ct.create_string_buffer(
            public_key, self._sig.contents.length_public_key
        )
        rv = native().OQS_SIG_verify(
            self._sig, my_message, message_len, my_signature, sig_len, my_public_key
        )
        return True if rv == OQS_SUCCESS else False

    def free(self):
        """Releases the native resources."""
        if hasattr(self, "secret_key"):
            native().OQS_MEM_cleanse(
                ct.byref(self.secret_key), self._sig.contents.length_secret_key
            )
        native().OQS_SIG_free(self._sig)

    def __repr__(self):
        return "Signature mechanism: " + self._sig.contents.method_name.decode()


native().OQS_SIG_new.restype = ct.POINTER(Signature)
native().OQS_SIG_alg_identifier.restype = ct.c_char_p


def is_sig_enabled(alg_name):
    """
    Returns True if the signature algorithm is enabled.

    :param alg_name: a signature mechanism algorithm name.
    """
    return native().OQS_SIG_alg_is_enabled(ct.create_string_buffer(alg_name.encode()))


_sig_alg_ids = [
    native().OQS_SIG_alg_identifier(i) for i in range(native().OQS_SIG_alg_count())
]
_supported_sigs = [i.decode() for i in _sig_alg_ids]
_enabled_sigs = [i for i in _supported_sigs if is_sig_enabled(i)]


def get_enabled_sig_mechanisms():
    """Returns the list of enabled signature mechanisms."""
    return _enabled_sigs


def get_supported_sig_mechanisms():
    """Returns the list of supported signature mechanisms."""
    return _supported_sigs
