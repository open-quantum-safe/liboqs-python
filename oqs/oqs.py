"""
Open Quantum Safe (OQS) Python wrapper for liboqs.

The liboqs project provides post-quantum public key cryptography algorithms:
https://github.com/open-quantum-safe/liboqs

This module provides a Python 3 interface to liboqs.
"""

from __future__ import annotations

import ctypes as ct  # to call native
import ctypes.util as ctu
import importlib.metadata  # to determine module version at runtime
import logging
import platform  # to learn the OS we're on
import subprocess
import tempfile  # to install liboqs on demand
import time
import faulthandler

faulthandler.enable()

try:
    import tomllib  # Python 3.11+
except ImportError:  # Fallback for older versions
    import tomli as tomllib
import warnings
from os import environ
from pathlib import Path
from sys import stdout
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Final,
    TypeVar,
    Union,
    cast,
    Optional,
)

if TYPE_CHECKING:
    from collections.abc import Sequence, Iterable
    from types import TracebackType

TKeyEncapsulation = TypeVar("TKeyEncapsulation", bound="KeyEncapsulation")
TSignature = TypeVar("TSignature", bound="Signature")
TStatefulSignature = TypeVar("TStatefulSignature", bound="StatefulSignature")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(stdout))

# Expected return value from native OQS functions
OQS_SUCCESS: Final[int] = 0
OQS_ERROR: Final[int] = -1


def oqs_python_version() -> Union[str, None]:
    """liboqs-python version string."""
    try:
        result = importlib.metadata.version("liboqs-python")
    except importlib.metadata.PackageNotFoundError:
        warnings.warn("Please install liboqs-python using pip install", stacklevel=2)
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        try:
            # Fallback to version specified in pyproject.toml when running from the
            # source tree. This allows workflows to use the correct liboqs version
            # before the package is installed.
            with pyproject.open("rb") as f:
                data = tomllib.load(f)
            return data["project"]["version"]
        except (FileNotFoundError, KeyError, tomllib.TOMLDecodeError):
            warnings.warn(
                "Please install liboqs-python using pip install",
                stacklevel=2,
            )
            return None
    return result


# liboqs-python tries to automatically install and load this liboqs version in
# case no other version is found
OQS_VERSION = oqs_python_version()


def version(version_str: str) -> tuple[str, str, str]:
    parts = version_str.split(".")

    major = parts[0] if len(parts) > 0 else ""
    minor = parts[1] if len(parts) > 1 else ""
    patch = parts[2] if len(parts) > 2 else ""

    return major, minor, patch


def _load_shared_obj(
    name: str,
    additional_searching_paths: Union[Sequence[Path], None] = None,
) -> ct.CDLL:
    """Attempt to load shared library."""
    paths: list[Path] = []
    dll = ct.windll if platform.system() == "Windows" else ct.cdll

    # Search additional path, if any
    if additional_searching_paths:
        for path in additional_searching_paths:
            if platform.system() == "Darwin":
                paths.append(path.absolute() / Path(f"lib{name}").with_suffix(".dylib"))
            elif platform.system() == "Windows":
                # Try both oqs.dll and liboqs.dll in the install path
                for dll_name in (name, f"lib{name}"):
                    paths.append(
                        path.absolute() / Path(dll_name).with_suffix(".dll")
                    )
            else:  # Linux/FreeBSD/UNIX
                paths.append(path.absolute() / Path(f"lib{name}").with_suffix(".so"))
                # https://stackoverflow.com/questions/856116/changing-ld-library-path-at-runtime-for-ctypes
                # os.environ["LD_LIBRARY_PATH"] += os.path.abspath(path)

    # Search typical locations
    try:
        if found_lib := ctu.find_library(name):
            paths.insert(0, Path(found_lib))
    except:
        pass

    try:
        if found_lib := ctu.find_library("lib" + name):
            paths.insert(0, Path(found_lib))
    except:
        pass

    for path in paths:
        if path:
            try:
                lib: ct.CDLL = dll.LoadLibrary(str(path))
            except OSError:
                pass
            else:
                return lib

    msg = f"No {name} shared libraries found"
    raise RuntimeError(msg)


def _countdown(seconds: int) -> None:
    while seconds > 0:
        logger.info("Installing in %s seconds...", seconds)
        stdout.flush()
        seconds -= 1
        time.sleep(1)


def _install_liboqs(
    target_directory: Path,
    oqs_version_to_install: Union[str, None] = None,
) -> None:
    """Install liboqs version oqs_version (if None, installs latest at HEAD) in the target_directory."""  # noqa: E501
    # Set explicit to `None` to install the lastest `liboqs` code.
    if oqs_version_to_install is None:
        pass

    elif "rc" in oqs_version_to_install:
        # removed the "-" from the version string
        tmp = oqs_version_to_install.split("rc")
        oqs_version_to_install = tmp[0] + "-rc" + tmp[1]

    with tempfile.TemporaryDirectory() as tmpdirname:
        oqs_install_cmd = [
            "cd",
            tmpdirname,
            "&&",
            "git",
            "clone",
            "https://github.com/open-quantum-safe/liboqs",
        ]
        if oqs_version_to_install:
            oqs_install_cmd.extend(["--branch", oqs_version_to_install])

        oqs_install_cmd.extend(
            [
                "--depth",
                "1",
                "&&",
                "cmake",
                "-S",
                "liboqs",
                "-B",
                "liboqs/build",
                "-DBUILD_SHARED_LIBS=ON",
                "-DOQS_BUILD_ONLY_LIB=ON",
                # Stateful signature algorithms:
                "-DOQS_ENABLE_SIG_STFL_LMS=ON",  # LMS family
                "-DOQS_ENABLE_SIG_STFL_XMSS=ON",  # XMSS family
                # To support key-generation.
                "-DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON",
                f"-DCMAKE_INSTALL_PREFIX={target_directory}",
            ],
        )

        if platform.system() == "Windows":
            oqs_install_cmd.append("-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE")

        oqs_install_cmd.extend(
            [
                "&&",
                "cmake",
                "--build",
                "liboqs/build",
                "--parallel",
                "4",
                "&&",
                "cmake",
                "--build",
                "liboqs/build",
                "--target",
                "install",
            ],
        )
        logger.info("liboqs not found, installing it in %s", str(target_directory))
        _countdown(5)

        _retcode = subprocess.call(" ".join(oqs_install_cmd), shell=True)  # noqa: S602

        if _retcode != 0:
            logger.exception("Error installing liboqs.")
            raise SystemExit(1)

        logger.info("Done installing liboqs")


def _load_liboqs() -> ct.CDLL:
    if "OQS_INSTALL_PATH" in environ:
        oqs_install_dir = Path(environ["OQS_INSTALL_PATH"])
    else:
        home_dir = Path.home()
        oqs_install_dir = home_dir / "_oqs"
    oqs_lib_dir = (
        oqs_install_dir / "bin"  # $HOME/_oqs/bin
        if platform.system() == "Windows"
        else oqs_install_dir / "lib"  # $HOME/_oqs/lib
    )
    oqs_lib64_dir = (
        oqs_install_dir / "bin"  # $HOME/_oqs/bin
        if platform.system() == "Windows"
        else oqs_install_dir / "lib64"  # $HOME/_oqs/lib64
    )
    try:
        liboqs = _load_shared_obj(
            name="oqs",
            additional_searching_paths=[oqs_lib_dir, oqs_lib64_dir],
        )
        assert liboqs  # noqa: S101
    except RuntimeError:
        # We don't have liboqs, so we try to install it automatically
        _install_liboqs(target_directory=oqs_install_dir, oqs_version_to_install=OQS_VERSION)
        # Try loading it again
        try:
            liboqs = _load_shared_obj(
                name="oqs",
                additional_searching_paths=[oqs_lib_dir],
            )
            assert liboqs  # noqa: S101
        except RuntimeError:
            msg = "Could not load liboqs shared library"
            raise SystemExit(msg) from None

    return liboqs


_liboqs = _load_liboqs()


def native() -> ct.CDLL:
    """Handle to native liboqs handler."""
    return _liboqs


# liboqs initialization
native().OQS_init()


def oqs_version() -> str:
    """liboqs version string."""
    native().OQS_version.restype = ct.c_char_p
    return ct.c_char_p(native().OQS_version()).value.decode("UTF-8")  # type: ignore[union-attr]


oqs_ver = oqs_version()
oqs_ver_major, oqs_ver_minor, oqs_ver_patch = version(oqs_ver)


oqs_python_ver = oqs_python_version()
if oqs_python_ver:
    oqs_python_ver_major, oqs_python_ver_minor, oqs_python_ver_patch = version(oqs_python_ver)
    # Warn the user if the liboqs version differs from liboqs-python version
    if not (oqs_ver_major == oqs_python_ver_major and oqs_ver_minor == oqs_python_ver_minor):
        warnings.warn(
            f"liboqs version (major, minor) {oqs_version()} differs from liboqs-python version "
            f"{oqs_python_version()}",
            stacklevel=2,
        )


class MechanismNotSupportedError(Exception):
    """Exception raised when an algorithm is not supported by OQS."""

    def __init__(self, alg_name: str, supported: Optional[Iterable[str]] = None) -> None:
        """
        Initialize the exception.

        :param alg_name: Requested algorithm name.
        :param supported: A list of supported algorithms to include in the message.
            Defaults to `None`.
        """
        supported_str = ""
        if supported is not None:
            supported_str = ", ".join(supported)
            supported_str = f". Supported algorithms: {supported_str}"

        self.alg_name = alg_name
        self.message = f"{alg_name} is not supported by OQS" + supported_str


class MechanismNotEnabledError(MechanismNotSupportedError):
    """Exception raised when an algorithm is supported but not enabled by OQS."""

    def __init__(self, alg_name: str, enabled: Optional[Iterable[str]] = None) -> None:
        """
        Initialize the exception.

        :param alg_name: Requested algorithm name.
        :param enabled: A list of enabled algorithms to include in the message. Defaults to `None`.
        """
        enabled_str = ""
        if enabled is not None:
            enabled_str = ", ".join(enabled)
            enabled_str = f". Enabled algorithms: {enabled_str}"

        self.alg_name = alg_name
        self.message = f"{alg_name} is supported but not enabled by OQS" + enabled_str


class KeyEncapsulation(ct.Structure):
    """
    An OQS KeyEncapsulation wraps native/C liboqs OQS_KEM structs.

    The wrapper maps methods to the C equivalent as follows:

    Python                 |  C liboqs
    -------------------------------
    generate_keypair      |  keypair
    generate_keypair_seed |  keypair
    encap_secret          |  encaps
    decap_secret          |  decaps
    free                  |  OQS_KEM_free
    """

    _fields_: ClassVar[Sequence[tuple[str, Any]]] = [
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("claimed_nist_level", ct.c_ubyte),
        ("ind_cca", ct.c_bool),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_ciphertext", ct.c_size_t),
        ("length_shared_secret", ct.c_size_t),
        ("length_keypair_seed", ct.c_size_t),
        ("keypair_derand_cb", ct.c_void_p),
        ("keypair_cb", ct.c_void_p),
        ("encaps_cb", ct.c_void_p),
        ("decaps_cb", ct.c_void_p),
    ]

    def __init__(self, alg_name: str, secret_key: Union[int, bytes, None] = None) -> None:
        """
        Create new KeyEncapsulation with the given algorithm.

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
            raise MechanismNotSupportedError(alg_name)

        self._kem = native().OQS_KEM_new(ct.create_string_buffer(alg_name.encode()))

        self.method_name = self._kem.contents.method_name
        self.alg_version = self._kem.contents.alg_version
        self.claimed_nist_level = self._kem.contents.claimed_nist_level
        self.ind_cca = self._kem.contents.ind_cca
        self.length_public_key = self._kem.contents.length_public_key
        self.length_secret_key = self._kem.contents.length_secret_key
        self.length_ciphertext = self._kem.contents.length_ciphertext
        self.length_shared_secret = self._kem.contents.length_shared_secret
        self.length_keypair_seed = self._kem.contents.length_keypair_seed

        self.details = {
            "name": self.method_name.decode(),
            "version": self.alg_version.decode(),
            "claimed_nist_level": int(self.claimed_nist_level),
            "is_ind_cca": bool(self.ind_cca),
            "length_public_key": int(self.length_public_key),
            "length_secret_key": int(self.length_secret_key),
            "length_ciphertext": int(self.length_ciphertext),
            "length_shared_secret": int(self.length_shared_secret),
            "length_keypair_seed": int(self.length_keypair_seed),
        }

        if secret_key:
            self.secret_key = ct.create_string_buffer(
                secret_key,
                self._kem.contents.length_secret_key,
            )

    def __enter__(self: TKeyEncapsulation) -> TKeyEncapsulation:
        return self

    def __exit__(
        self,
        exc_type: Union[type[BaseException], None],
        exc_value: Union[BaseException, None],
        traceback: Union[TracebackType, None],
    ) -> None:
        self.free()

    def generate_keypair_seed(self, seed: bytes) -> bytes:
        """
        Generate a new keypair using the provided seed and returns the public key.

        :param seed: A seed to use for key generation.
        If the seed is None, a random seed will be generated.
        """
        if self.length_keypair_seed == 0:
            msg = f"Key generation with seed is not supported. Got {self.alg_name}."
            raise RuntimeError(msg)

        if len(seed) != self._kem.contents.length_keypair_seed:
            msg = (
                f"Seed length must be {self._kem.contents.length_keypair_seed} bytes, "
                f"got {len(seed)} bytes"
            )
            raise ValueError(msg)

        c_seed = ct.create_string_buffer(seed, self._kem.contents.length_keypair_seed)
        public_key = ct.create_string_buffer(self._kem.contents.length_public_key)
        self.secret_key = ct.create_string_buffer(self._kem.contents.length_secret_key)

        rv = native().OQS_KEM_keypair_derand(
            self._kem,
            ct.byref(public_key),
            ct.byref(self.secret_key),
            c_seed,
        )
        if rv == OQS_SUCCESS:
            return bytes(public_key)
        msg = "Can not generate keypair with provided seed"
        raise RuntimeError(msg)

    def generate_keypair(self) -> bytes:
        """
        Generate a new keypair and returns the public key.

        If needed, the secret key can be obtained with export_secret_key().
        """
        public_key = ct.create_string_buffer(self._kem.contents.length_public_key)
        self.secret_key = ct.create_string_buffer(self._kem.contents.length_secret_key)
        rv = native().OQS_KEM_keypair(
            self._kem,
            ct.byref(public_key),
            ct.byref(self.secret_key),
        )
        if rv == OQS_SUCCESS:
            return bytes(public_key)
        msg = "Can not generate keypair"
        raise RuntimeError(msg)

    def export_secret_key(self) -> bytes:
        """Export the secret key."""
        return bytes(self.secret_key)

    def encap_secret(self, public_key: Union[int, bytes]) -> tuple[bytes, bytes]:
        """
        Generate and encapsulates a secret using the provided public key.

        :param public_key: the peer's public key.
        """
        c_public_key = ct.create_string_buffer(
            public_key,
            self._kem.contents.length_public_key,
        )
        ciphertext: ct.Array[ct.c_char] = ct.create_string_buffer(
            self._kem.contents.length_ciphertext,
        )
        shared_secret: ct.Array[ct.c_char] = ct.create_string_buffer(
            self._kem.contents.length_shared_secret,
        )
        rv = native().OQS_KEM_encaps(
            self._kem,
            ct.byref(ciphertext),
            ct.byref(shared_secret),
            c_public_key,
        )
        if rv == OQS_SUCCESS:
            return bytes(ciphertext), bytes(shared_secret)
        msg = "Can not encapsulate secret"
        raise RuntimeError(msg)

    def decap_secret(self, ciphertext: Union[int, bytes]) -> bytes:
        """
        Decapsulate the ciphertext and returns the secret.

        :param ciphertext: the ciphertext received from the peer.
        """
        c_ciphertext = ct.create_string_buffer(
            ciphertext,
            self._kem.contents.length_ciphertext,
        )
        shared_secret: ct.Array[ct.c_char] = ct.create_string_buffer(
            self._kem.contents.length_shared_secret,
        )
        rv = native().OQS_KEM_decaps(
            self._kem,
            ct.byref(shared_secret),
            c_ciphertext,
            self.secret_key,
        )
        if rv == OQS_SUCCESS:
            return bytes(shared_secret)
        msg = "Can not decapsulate secret"
        raise RuntimeError(msg)

    def free(self) -> None:
        """Releases the native resources."""
        if hasattr(self, "secret_key"):
            native().OQS_MEM_cleanse(
                ct.byref(self.secret_key),
                self._kem.contents.length_secret_key,
            )
        native().OQS_KEM_free(self._kem)

    def __repr__(self) -> str:
        return f"Key encapsulation mechanism: {self._kem.contents.method_name.decode()}"


native().OQS_KEM_new.restype = ct.POINTER(KeyEncapsulation)
native().OQS_KEM_alg_identifier.restype = ct.c_char_p


def is_kem_enabled(alg_name: str) -> bool:
    """
    Return True if the KEM algorithm is enabled.

    :param alg_name: a KEM mechanism algorithm name.
    """
    return native().OQS_KEM_alg_is_enabled(ct.create_string_buffer(alg_name.encode()))


_KEM_alg_ids = [native().OQS_KEM_alg_identifier(i) for i in range(native().OQS_KEM_alg_count())]
_supported_KEMs: tuple[str, ...] = tuple([i.decode() for i in _KEM_alg_ids])  # noqa: N816
_enabled_KEMs: tuple[str, ...] = tuple([i for i in _supported_KEMs if is_kem_enabled(i)])  # noqa: N816


def get_enabled_kem_mechanisms() -> tuple[str, ...]:
    """Return the list of enabled KEM mechanisms."""
    return _enabled_KEMs


def get_supported_kem_mechanisms() -> tuple[str, ...]:
    """Return the list of supported KEM mechanisms."""
    return _supported_KEMs


# Register the OQS_SIG_supports_ctx_str function from the C library
native().OQS_SIG_supports_ctx_str.restype = ct.c_bool
native().OQS_SIG_supports_ctx_str.argtypes = [ct.c_char_p]


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

    _fields_: ClassVar[Sequence[tuple[str, Any]]] = [
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("claimed_nist_level", ct.c_ubyte),
        ("euf_cma", ct.c_bool),
        ("suf_cma", ct.c_bool),
        ("sig_with_ctx_support", ct.c_bool),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_signature", ct.c_size_t),
        ("keypair_cb", ct.c_void_p),
        ("sign_cb", ct.c_void_p),
        ("sign_with_ctx_cb", ct.c_void_p),
        ("verify_cb", ct.c_void_p),
        ("verify_with_ctx_cb", ct.c_void_p),
    ]

    def __init__(self, alg_name: str, secret_key: Union[int, bytes, None] = None) -> None:
        """
        Create new Signature with the given algorithm.

        :param alg_name: a signature mechanism algorithm name. Enabled signature mechanisms can be
        obtained with get_enabled_sig_mechanisms().
        :param secret_key: optional, if generated by generate_keypair().
        """
        super().__init__()
        if alg_name not in _enabled_sigs:
            # perhaps it's a supported but not enabled alg
            if alg_name in _supported_sigs:
                raise MechanismNotEnabledError(alg_name)
            raise MechanismNotSupportedError(alg_name)

        self._sig = native().OQS_SIG_new(ct.create_string_buffer(alg_name.encode()))

        self.method_name = self._sig.contents.method_name
        self.alg_version = self._sig.contents.alg_version
        self.claimed_nist_level = self._sig.contents.claimed_nist_level
        self.euf_cma = self._sig.contents.euf_cma
        self.sig_with_ctx_support = bool(self._sig.contents.sig_with_ctx_support)
        self.length_public_key = self._sig.contents.length_public_key
        self.length_secret_key = self._sig.contents.length_secret_key
        self.length_signature = self._sig.contents.length_signature

        self.details = {
            "name": self.method_name.decode(),
            "version": self.alg_version.decode(),
            "claimed_nist_level": int(self.claimed_nist_level),
            "is_euf_cma": bool(self.euf_cma),
            "is_suf_cma": bool(self.suf_cma),
            "supports_context_signing": bool(self.sig_with_ctx_support),
            "sig_with_ctx_support": bool(self.sig_with_ctx_support),
            "length_public_key": int(self.length_public_key),
            "length_secret_key": int(self.length_secret_key),
            "length_signature": int(self.length_signature),
        }

        if secret_key:
            self.secret_key = ct.create_string_buffer(
                secret_key,
                self._sig.contents.length_secret_key,
            )

    def __enter__(self: TSignature) -> TSignature:
        return self

    def __exit__(
        self,
        exc_type: Union[type[BaseException], None],
        exc_value: Union[BaseException, None],
        traceback: Union[TracebackType, None],
    ) -> None:
        self.free()

    def generate_keypair(self) -> bytes:
        """
        Generate a new keypair and returns the public key.

        If needed, the secret key can be obtained with export_secret_key().
        """
        public_key: ct.Array[ct.c_char] = ct.create_string_buffer(
            self._sig.contents.length_public_key,
        )
        self.secret_key = ct.create_string_buffer(self._sig.contents.length_secret_key)
        rv = native().OQS_SIG_keypair(
            self._sig,
            ct.byref(public_key),
            ct.byref(self.secret_key),
        )
        if rv == OQS_SUCCESS:
            return bytes(public_key)
        msg = "Can not generate keypair"
        raise RuntimeError(msg)

    def export_secret_key(self) -> bytes:
        """Export the secret key."""
        return bytes(self.secret_key)

    def sign(self, message: bytes) -> bytes:
        """
        Signs the provided message and returns the signature.

        :param message: the message to sign.
        """
        # Provide length to avoid extra null char
        c_message = ct.create_string_buffer(message, len(message))
        c_message_len = ct.c_size_t(len(c_message))
        c_signature = ct.create_string_buffer(self._sig.contents.length_signature)

        # Initialize to maximum signature size
        c_signature_len = ct.c_size_t(self._sig.contents.length_signature)

        rv = native().OQS_SIG_sign(
            self._sig,
            ct.byref(c_signature),
            ct.byref(c_signature_len),
            c_message,
            c_message_len,
            self.secret_key,
        )
        if rv == OQS_SUCCESS:
            return bytes(cast("bytes", c_signature[: c_signature_len.value]))
        msg = "Can not sign message"
        raise RuntimeError(msg)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify the provided signature on the message; returns True if valid.

        :param message: the signed message.
        :param signature: the signature on the message.
        :param public_key: the signer's public key.
        """
        # Provide length to avoid extra null char
        c_message = ct.create_string_buffer(message, len(message))
        c_message_len = ct.c_size_t(len(c_message))
        c_signature = ct.create_string_buffer(signature, len(signature))
        c_signature_len = ct.c_size_t(len(c_signature))
        c_public_key = ct.create_string_buffer(
            public_key,
            self._sig.contents.length_public_key,
        )

        rv = native().OQS_SIG_verify(
            self._sig,
            c_message,
            c_message_len,
            c_signature,
            c_signature_len,
            c_public_key,
        )
        return rv == OQS_SUCCESS

    def sign_with_ctx_str(self, message: bytes, context: bytes) -> bytes:
        """
        Sign the provided message with context string and returns the signature.

        :param context: the context string.
        :param message: the message to sign.
        """
        if context and not self._sig.contents.sig_with_ctx_support:
            msg = (
                f"Signing with context is not supported for: "
                f"{self._sig.contents.method_name.decode()}"
            )
            raise RuntimeError(msg)

        # Provide length to avoid extra null char
        c_message = ct.create_string_buffer(message, len(message))
        c_message_len = ct.c_size_t(len(c_message))
        if len(context) == 0:
            c_context = None
            c_context_len = ct.c_size_t(0)
        else:
            c_context = ct.create_string_buffer(context, len(context))
            c_context_len = ct.c_size_t(len(c_context))
        c_signature = ct.create_string_buffer(self._sig.contents.length_signature)

        # Initialize to maximum signature size
        c_signature_len = ct.c_size_t(self._sig.contents.length_signature)
        rv = native().OQS_SIG_sign_with_ctx_str(
            self._sig,
            ct.byref(c_signature),
            ct.byref(c_signature_len),
            c_message,
            c_message_len,
            c_context,
            c_context_len,
            self.secret_key,
        )
        if rv == OQS_SUCCESS:
            return bytes(cast("bytes", c_signature[: c_signature_len.value]))
        msg = "Can not sign message with context string"
        raise RuntimeError(msg)

    def verify_with_ctx_str(
        self,
        message: bytes,
        signature: bytes,
        context: bytes,
        public_key: bytes,
    ) -> bool:
        """
        Verify the provided signature on the message with context string; returns True if valid.

        :param message: the signed message.
        :param signature: the signature on the message.
        :param context: the context string.
        :param public_key: the signer's public key.
        """
        if context and not self.sig_with_ctx_support:
            msg = "Verifying with context string not supported"
            raise RuntimeError(msg)

        # Provide length to avoid extra null char
        c_message = ct.create_string_buffer(message, len(message))
        c_message_len = ct.c_size_t(len(c_message))
        c_signature = ct.create_string_buffer(signature, len(signature))
        c_signature_len = ct.c_size_t(len(c_signature))
        if len(context) == 0:
            c_context = None
            c_context_len = ct.c_size_t(0)
        else:
            c_context = ct.create_string_buffer(context, len(context))
            c_context_len = ct.c_size_t(len(c_context))
        c_public_key = ct.create_string_buffer(
            public_key,
            self._sig.contents.length_public_key,
        )

        rv = native().OQS_SIG_verify_with_ctx_str(
            self._sig,
            c_message,
            c_message_len,
            c_signature,
            c_signature_len,
            c_context,
            c_context_len,
            c_public_key,
        )
        return rv == OQS_SUCCESS

    def free(self) -> None:
        """Releases the native resources."""
        if hasattr(self, "secret_key"):
            native().OQS_MEM_cleanse(
                ct.byref(self.secret_key),
                self._sig.contents.length_secret_key,
            )
        native().OQS_SIG_free(self._sig)

    def __repr__(self) -> str:
        return f"Signature mechanism: {self._sig.contents.method_name.decode()}"


native().OQS_SIG_new.restype = ct.POINTER(Signature)
native().OQS_SIG_alg_identifier.restype = ct.c_char_p

native().OQS_SIG_supports_ctx_str.restype = ct.c_bool


def is_sig_enabled(alg_name: str) -> bool:
    """
    Return `True` if the signature algorithm is enabled.

    :param alg_name: A signature mechanism algorithm name.
    """
    return native().OQS_SIG_alg_is_enabled(ct.create_string_buffer(alg_name.encode()))


def sig_supports_context(alg_name: str) -> bool:
    """
    Return `True` if the signature algorithm supports signing with a context string.

    :param alg_name: A signature mechanism algorithm name.
    """
    return bool(native().OQS_SIG_supports_ctx_str(ct.create_string_buffer(alg_name.encode())))


_sig_alg_ids = [native().OQS_SIG_alg_identifier(i) for i in range(native().OQS_SIG_alg_count())]
_supported_sigs: tuple[str, ...] = tuple([i.decode() for i in _sig_alg_ids])
_enabled_sigs: tuple[str, ...] = tuple([i for i in _supported_sigs if is_sig_enabled(i)])


def get_enabled_sig_mechanisms() -> tuple[str, ...]:
    """Return the list of enabled signature mechanisms."""
    return _enabled_sigs


def get_supported_sig_mechanisms() -> tuple[str, ...]:
    """Return the list of supported signature mechanisms."""
    return _supported_sigs


# Check enabled algorithms
native().OQS_SIG_STFL_alg_identifier.restype = ct.c_char_p


def is_stateful_sig_enabled(alg_name: str) -> bool:
    """Check if a stateful signature algorithm is enabled."""
    return native().OQS_SIG_STFL_alg_is_enabled(ct.create_string_buffer(alg_name.encode()))


_supported_stateful_sigs: tuple[str, ...] = tuple(
    native().OQS_SIG_STFL_alg_identifier(i).decode()
    for i in range(native().OQS_SIG_STFL_alg_count())
)
_enabled_stateful_sigs: tuple[str, ...] = tuple(
    alg for alg in _supported_stateful_sigs if is_stateful_sig_enabled(alg)
)


def get_enabled_stateful_sig_mechanisms() -> tuple[str, ...]:
    """Return a list of enabled stateful signature mechanisms."""
    return _enabled_stateful_sigs


def get_supported_stateful_sig_mechanisms() -> tuple[str, ...]:
    """Return a list of supported stateful signature mechanisms."""
    return _supported_stateful_sigs


def _filter_stfl_names(alg_name: str, alg_names: Iterable[str]) -> Optional[list[str]]:
    """Filter and return only stateful signature algorithm names."""
    if alg_name.startswith("LMS"):
        return [name for name in alg_names if name.startswith("LMS")]
    if alg_name.startswith("XMSS"):
        return [name for name in alg_names if name.startswith("XMSS")]
    if alg_name.startswith("XMSSMT"):
        return [name for name in alg_names if name.startswith("XMSSMT")]
    return None


def _check_alg(alg_name: str) -> None:
    """Check if the algorithm is supported and enabled."""
    if alg_name not in _supported_stateful_sigs:
        _filtered_names = _filter_stfl_names(alg_name, _supported_stateful_sigs)
        if _filtered_names is None:
            raise MechanismNotSupportedError(alg_name)
        raise MechanismNotSupportedError(alg_name, supported=_filtered_names)
    if alg_name not in _enabled_stateful_sigs:
        sup = _filter_stfl_names(alg_name, _enabled_stateful_sigs)
        raise MechanismNotEnabledError(alg_name, enabled=sup)


class StatefulSignature(ct.Structure):
    """
    An OQS StatefulSignature wraps native/C liboqs OQS_SIG structs.

    The wrapper maps methods to the C equivalent as follows:

    Python             |  C liboqs
    -------------------------------
    generate_keypair   |  keypair
    sign               |  sign
    verify             |  verify
    free               |  OQS_SIG_STFL_free
    sigs_remaining     |  OQS_SIG_STFL_sigs_remaining
    sigs_total         |  OQS_SIG_STFL_sigs_total

    """

    _fields_: ClassVar[Sequence[tuple[str, Any]]] = [
        ("oid", ct.c_uint32),
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("euf_cma", ct.c_bool),
        ("suf_cma", ct.c_bool),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_signature", ct.c_size_t),
        ("keypair_cb", ct.c_void_p),
        ("sign_cb", ct.c_void_p),
        ("verify_cb", ct.c_void_p),
        ("sigs_remaining_cb", ct.c_void_p),
        ("sigs_total_cb", ct.c_void_p),
    ]

    def __init__(self, alg_name: str, secret_key: Optional[bytes] = None) -> None:
        """
        Create a new stateful signature instance with the given algorithm.

        :param alg_name: A stateful signature mechanism algorithm name.
        :param secret_key: Optional secret key to load.
        """
        super().__init__()

        _check_alg(alg_name)
        self._sig = native().OQS_SIG_STFL_new(ct.create_string_buffer(alg_name.encode()))
        if not self._sig:
            msg = f"Could not allocate OQS_SIG_STFL for {alg_name}"
            raise RuntimeError(msg)

        for field, _ctype in self._fields_:
            if field == "oid" or field.endswith("cb"):
                continue
            setattr(self, field, getattr(self._sig.contents, field))

        self._secret_key: ct.c_void_p | None = None
        self._owns_secret = False
        self._used_keys: list[bytes] = []
        self._store_cb: Optional[ct.CFUNCTYPE] = None

        if secret_key is not None:
            self._load_secret_key(secret_key)

        self.details = {
            "name": self.method_name.decode(),
            "version": self.alg_version.decode(),
            "is_euf_cma": bool(self.euf_cma),
            "is_suf_cma": bool(self.suf_cma),
            "length_public_key": int(self.length_public_key),
            "length_secret_key": int(self.length_secret_key),
            "length_signature": int(self.length_signature),
        }

    def _attach_store_cb(self) -> None:
        """Attach a callback to store used keys in the stateful signature."""

        @ct.CFUNCTYPE(ct.c_int, ct.POINTER(ct.c_uint8), ct.c_size_t, ct.c_void_p)
        def _cb(buf: bytes, length: int, _: ct.c_void_p) -> int:
            self._used_keys.append(ct.string_at(buf, length))
            return OQS_SUCCESS

        self._store_cb = _cb  # keep ref
        native().OQS_SIG_STFL_SECRET_KEY_SET_store_cb(self._secret_key, self._store_cb, None)

    def _new_secret_key(self) -> None:
        """Create a new secret key for the stateful signature."""
        self._secret_key = native().OQS_SIG_STFL_SECRET_KEY_new(self.method_name)
        if not self._secret_key:
            msg = "Could not allocate OQS_SIG_STFL_SECRET_KEY"
            raise MemoryError(msg)
        self._attach_store_cb()

    def _load_secret_key(self, data: bytes) -> None:
        """Load a secret key from bytes."""
        self._new_secret_key()
        buf = ct.create_string_buffer(data, len(data))
        rc = native().OQS_SIG_STFL_SECRET_KEY_deserialize(self._secret_key, buf, len(data), None)
        if rc != OQS_SUCCESS:
            if len(data) != int(self.length_secret_key):
                msg = (
                    f"Secret key length must be {self.length_secret_key} bytes, "
                    f"got {len(data)} bytes"
                )
                raise ValueError(msg)

            msg = "Secret‑key deserialization failed"
            raise RuntimeError(msg)

    def generate_keypair(self) -> bytes:
        """
        Generate a new keypair for the stateful signature.

        :raise ValueError: If the keypair has already been generated.
        :raise RuntimeError: If the keypair generation fails or if a keypair already exists.
        :return: The generated public key as bytes.
        """
        if self._secret_key is not None:
            msg = "Keypair already generated, call free() to release the secret key"
            raise ValueError(msg)

        self._secret_key = native().OQS_SIG_STFL_SECRET_KEY_new(self.method_name)
        if not self._secret_key:
            msg = "Could not allocate OQS_SIG_STFL_SECRET_KEY"
            raise RuntimeError(msg)
        self._attach_store_cb()

        sig_struct = self._sig.contents
        pk_buf = ct.create_string_buffer(sig_struct.length_public_key)

        rc = native().OQS_SIG_STFL_keypair(self._sig, pk_buf, self._secret_key)
        if rc != OQS_SUCCESS:
            msg = "Keypair generation failed"
            raise RuntimeError(msg)
        return pk_buf.raw

    def sign(self, message: bytes) -> bytes:
        """
        Sign the provided message and return the signature.

        :param message: The message to sign.
        :raises NotImplementedError: If the method is LMS-based, as it is verify-only supported.
        :raises RuntimeError: If the secret key is not initialized.
        :raises ValueError: If the signing fails.
        :return: The signature on the message as bytes.
        """
        if self.method_name.startswith(b"LMS"):
            msg = "LMS algorithms are verify‑only supported."
            raise NotImplementedError(msg)
        if self._secret_key is None:
            msg = "Secret key not initialised – call generate_keypair() first"
            raise RuntimeError(msg)
        c_signature = ct.create_string_buffer(self.length_signature)
        c_signature_len = ct.c_size_t(self.length_signature)
        msg_buf = ct.create_string_buffer(message, len(message))
        rc = native().OQS_SIG_STFL_sign(
            self._sig,
            c_signature,
            ct.byref(c_signature_len),
            msg_buf,
            len(message),
            self._secret_key,
        )
        if rc != OQS_SUCCESS:
            msg = "Signing failed"
            raise ValueError(msg)
        return bytes(cast("bytes", c_signature[: c_signature_len.value]))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify the provided signature on the message; returns True if valid.

        :param message: The signed message.
        :param signature: The signature on the message.
        :param public_key: The signer's public key.
        :return: `True` if the signature is valid, `False` otherwise.
        """
        msg = ct.create_string_buffer(message, len(message))
        sig = ct.create_string_buffer(signature, len(signature))
        pk = ct.create_string_buffer(public_key, len(public_key))
        rc = native().OQS_SIG_STFL_verify(self._sig, msg, len(message), sig, len(signature), pk)
        return rc == OQS_SUCCESS

    def export_secret_key(self) -> bytes:
        """
        Serialize the secret key to bytes.

        :return: The serialized secret key as bytes.
        :raises ValueError: If the secret key is not initialized.
        """
        if self._secret_key is None:
            msg = "Secret key not initialised – call generate_keypair() first"
            raise ValueError(msg)
        buf_ptr = ct.POINTER(ct.c_uint8)()
        buf_len = ct.c_size_t()
        rc = native().OQS_SIG_STFL_SECRET_KEY_serialize(
            ct.byref(buf_ptr), ct.byref(buf_len), self._secret_key
        )
        if rc != OQS_SUCCESS:
            msg = "Secret‑key serialization failed"
            raise ValueError(msg)
        data = ct.string_at(buf_ptr, buf_len.value)
        ct.CDLL(ct.util.find_library("c")).free(buf_ptr)
        return data

    def sigs_total(self) -> int:
        """Get the total number of signatures that can be made with the secret key."""
        total = ct.c_uint64()
        rc = native().OQS_SIG_STFL_sigs_total(self._sig, ct.byref(total), self._secret_key)
        if rc != OQS_SUCCESS:
            msg = "Failed to get total signature count"
            raise RuntimeError(msg)
        return total.value

    def sigs_remaining(self) -> int:
        """Get the number of remaining signatures that can be made with the secret key."""
        if self._secret_key is None:
            msg = "Secret key not initialised – call generate_keypair() first"
            raise ValueError(msg)
        remain = ct.c_uint64()
        rc = native().OQS_SIG_STFL_sigs_remaining(self._sig, ct.byref(remain), self._secret_key)
        if rc != OQS_SUCCESS:
            msg = "Failed to get remaining signature count"
            raise ValueError(msg)
        return remain.value

    def export_used_keys(self) -> list[bytes]:
        """Export the list of used keys."""
        return self._used_keys.copy()

    def __enter__(self) -> TStatefulSignature:
        """Enter the context and return the StatefulSignature instance."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Free the resources when exiting the context."""
        self.free()

    def free(self) -> None:
        """Free the native resources."""
        if self._store_cb and self._secret_key:
            native().OQS_SIG_STFL_SECRET_KEY_SET_store_cb(self._secret_key, None, None)
            self._store_cb = None
        if self._secret_key and self._owns_secret:
            native().OQS_SIG_STFL_SECRET_KEY_free(self._secret_key)


native().OQS_SIG_STFL_new.restype = ct.POINTER(StatefulSignature)
native().OQS_SIG_STFL_SECRET_KEY_new.restype = ct.c_void_p
native().OQS_SIG_STFL_SECRET_KEY_new.argtypes = [ct.c_char_p]
# Added precise signatures for (de)serialization to avoid ABI issues
native().OQS_SIG_STFL_SECRET_KEY_serialize.restype = ct.c_int
native().OQS_SIG_STFL_SECRET_KEY_serialize.argtypes = [
    ct.POINTER(ct.POINTER(ct.c_uint8)),
    ct.POINTER(ct.c_size_t),
    ct.c_void_p,
]
native().OQS_SIG_STFL_SECRET_KEY_deserialize.restype = ct.c_int
native().OQS_SIG_STFL_SECRET_KEY_deserialize.argtypes = [
    ct.c_void_p,
    ct.c_void_p,
    ct.c_size_t,
    ct.c_void_p,
]
native().OQS_SIG_STFL_SECRET_KEY_SET_store_cb.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_void_p]
native().OQS_SIG_STFL_keypair.argtypes = [ct.POINTER(StatefulSignature), ct.c_void_p, ct.c_void_p]
native().OQS_SIG_STFL_sign.argtypes = [
    ct.POINTER(StatefulSignature),
    ct.c_void_p,
    ct.POINTER(ct.c_size_t),
    ct.c_void_p,
    ct.c_size_t,
    ct.c_void_p,
]
native().OQS_SIG_STFL_verify.argtypes = [
    ct.POINTER(StatefulSignature),
    ct.c_void_p,
    ct.c_size_t,
    ct.c_void_p,
    ct.c_size_t,
    ct.c_void_p,
]
native().OQS_SIG_STFL_sigs_remaining.argtypes = [
    ct.POINTER(StatefulSignature),
    ct.POINTER(ct.c_uint64),
    ct.c_void_p,
]
native().OQS_SIG_STFL_sigs_total.argtypes = [
    ct.POINTER(StatefulSignature),
    ct.POINTER(ct.c_uint64),
    ct.c_void_p,
]
