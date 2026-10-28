import contextlib
import ctypes as ct
import logging
import platform  # to learn the OS we're on
import random
from collections.abc import Callable, Iterator
from pathlib import Path
from unittest import mock

from typing import Tuple

from oqs.serialize import gen_or_load_stateful_signature_key

import oqs

_skip_names = ["LMS_SHA256_H20_W8_H10_W8", "LMS_SHA256_H20_W8_H15_W8", "LMS_SHA256_H20_W8_H20_W8"]

_KEY_DIR = Path(__file__).resolve().parent.parent / "data" / "xmss_xmssmt_keys"

# Sigs for which unit testing is disabled
disabled_sig_patterns = []

if platform.system() == "Windows":
    disabled_sig_patterns = [""]


def _load_or_generate_key(alg_name: str) -> Tuple[oqs.StatefulSignature, bytes]:
    private_key, public_key = gen_or_load_stateful_signature_key(alg_name, dir_name=_KEY_DIR)

    if private_key is not None:
        sig = oqs.StatefulSignature(alg_name, secret_key=private_key)
        return sig, public_key
    sig = oqs.StatefulSignature(alg_name)
    public_key = sig.generate_keypair()
    return sig, public_key


def test_correctness() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if alg_name.startswith("LMS"):
            continue

        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_correctness, alg_name


def check_correctness(alg_name: str) -> None:
    sig, public_key = _load_or_generate_key(alg_name)
    message = bytes(random.getrandbits(8) for _ in range(100))
    signature = sig.sign(message)
    assert sig.verify(message, signature, public_key)  # noqa: S101


def test_wrong_message() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if alg_name.startswith("LMS"):
            continue

        if any(item in alg_name for item in disabled_sig_patterns):
            continue

        yield check_wrong_message, alg_name


def check_wrong_message(alg_name: str) -> None:
    sig, public_key = _load_or_generate_key(alg_name)
    message = bytes(random.getrandbits(8) for _ in range(100))
    signature = sig.sign(message)
    wrong_message = bytes(random.getrandbits(8) for _ in range(len(message)))
    assert not (sig.verify(wrong_message, signature, public_key))  # noqa: S101


def test_wrong_signature() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if alg_name.startswith("LMS"):
            continue

        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_signature, alg_name


def check_wrong_signature(alg_name: str) -> None:
    sig, public_key = _load_or_generate_key(alg_name)
    message = bytes(random.getrandbits(8) for _ in range(100))
    signature = sig.sign(message)
    wrong_signature = bytes(random.getrandbits(8) for _ in range(len(signature)))
    assert not (sig.verify(message, wrong_signature, public_key))  # noqa: S101


def test_wrong_public_key() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if alg_name.startswith("LMS"):
            continue

        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_public_key, alg_name


def check_wrong_public_key(alg_name: str) -> None:
    sig, public_key = _load_or_generate_key(alg_name)
    message = bytes(random.getrandbits(8) for _ in range(100))
    signature = sig.sign(message)
    wrong_public_key = bytes(random.getrandbits(8) for _ in range(len(public_key)))
    assert not (sig.verify(message, signature, wrong_public_key))  # noqa: S101


def test_not_supported() -> None:
    try:
        with oqs.StatefulSignature("unsupported_sig"):
            pass
    except oqs.MechanismNotSupportedError:
        pass
    except Exception as ex:
        msg = f"An unexpected exception was raised: {ex}"
        raise AssertionError(msg) from ex
    else:
        msg = "oqs.MechanismNotSupportedError was not raised."
        raise AssertionError(msg)


def test_not_enabled() -> None:
    for alg_name in oqs.get_supported_stateful_sig_mechanisms():
        if alg_name not in oqs.get_enabled_stateful_sig_mechanisms():
            # Found a non-enabled but supported alg
            try:
                with oqs.StatefulSignature(alg_name):
                    pass
            except oqs.MechanismNotEnabledError:
                pass
            except Exception as ex:
                msg = f"An unexpected exception was raised: {ex}"
                raise AssertionError(msg) from ex
            else:
                msg = "oqs.MechanismNotEnabledError was not raised."
                raise AssertionError(msg)


def test_python_attributes() -> None:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if alg_name in _skip_names:
            logging.info("Skipping %s as it is in the skip list.", alg_name)
            continue

        with oqs.StatefulSignature(alg_name) as sig:
            if sig.method_name.decode() != alg_name:
                msg = "Incorrect oqs.StatefulSignature.method_name"
                raise AssertionError(msg)
            if sig.alg_version is None:
                msg = "Undefined oqs.StatefulSignature.alg_version"
                raise AssertionError(msg)
            if sig.length_public_key == 0:
                msg = "Incorrect oqs.StatefulSignature.length_public_key"
                raise AssertionError(msg)
            if sig.length_secret_key == 0:
                msg = "Incorrect oqs.StatefulSignature.length_secret_key"
                raise AssertionError(msg)
            if sig.length_signature == 0:
                msg = "Incorrect oqs.StatefulSignature.length_signature"
                raise AssertionError(msg)


# Fastest XMSS parameter set, used where a test needs a real secret key.
_KEYGEN_ALG = "XMSS-SHA2_10_256"

# Each native allocator paired with the function that releases what it returns.
_NATIVE_ALLOCATORS = {
    "OQS_SIG_STFL_new": "OQS_SIG_STFL_free",
    "OQS_SIG_STFL_SECRET_KEY_new": "OQS_SIG_STFL_SECRET_KEY_free",
}


@contextlib.contextmanager
def _track_native_allocations() -> Iterator[dict[str, list[int]]]:
    """Record the address of every native struct and secret key allocated or freed."""
    lib = oqs.native()
    log: dict[str, list[int]] = {name: [] for pair in _NATIVE_ALLOCATORS.items() for name in pair}

    def wrap(name: str, *, record_result: bool) -> object:
        real = getattr(lib, name)

        def wrapper(*args: object) -> object:
            result = real(*args)
            ptr = result if record_result else args[0]
            address = ct.cast(ptr, ct.c_void_p).value
            if address:
                log[name].append(address)
            return result

        return wrapper

    with contextlib.ExitStack() as stack:
        for new, free in _NATIVE_ALLOCATORS.items():
            stack.enter_context(mock.patch.object(lib, new, wrap(new, record_result=True)))
            stack.enter_context(mock.patch.object(lib, free, wrap(free, record_result=False)))
        yield log


def _assert_each_allocation_freed_once(log: dict[str, list[int]]) -> None:
    for new, free in _NATIVE_ALLOCATORS.items():
        if sorted(log[new]) != sorted(log[free]):
            msg = f"{new} returned {log[new]} but {free} received {log[free]}"
            raise AssertionError(msg)


def test_free() -> None:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        with _track_native_allocations() as log:
            sig = oqs.StatefulSignature(alg_name)
            sig.free()
            sig.free()  # A second call must not free anything again.
        if not log["OQS_SIG_STFL_new"]:
            msg = f"No OQS_SIG_STFL struct was allocated for {alg_name}"
            raise AssertionError(msg)
        _assert_each_allocation_freed_once(log)


def test_free_with_keypair() -> None:
    if _KEYGEN_ALG not in oqs.get_enabled_stateful_sig_mechanisms():
        return
    if any(item in _KEYGEN_ALG for item in disabled_sig_patterns):
        return
    with _track_native_allocations() as log:
        with oqs.StatefulSignature(_KEYGEN_ALG) as sig:
            sig.generate_keypair()
        sig.free()  # Explicit free after the context manager must be a no-op.
    if not log["OQS_SIG_STFL_SECRET_KEY_new"]:
        msg = "No secret key was allocated"
        raise AssertionError(msg)
    _assert_each_allocation_freed_once(log)


def test_constructor_failure_frees() -> None:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        with _track_native_allocations() as log:
            try:
                oqs.StatefulSignature(alg_name, secret_key=b"not a secret key")
            except ValueError:
                pass
            else:
                msg = f"An invalid secret key was accepted for {alg_name}"
                raise AssertionError(msg)
        if not log["OQS_SIG_STFL_SECRET_KEY_new"]:
            msg = f"No secret key was allocated for {alg_name}"
            raise AssertionError(msg)
        _assert_each_allocation_freed_once(log)


def _assert_raises_freed(label: str, call: Callable[[], object]) -> None:
    try:
        call()
    except RuntimeError as ex:
        if "freed" not in str(ex):
            msg = f"{label}() raised an unexpected error: {ex}"
            raise AssertionError(msg) from ex
    else:
        msg = f"{label}() did not raise after free()"
        raise AssertionError(msg)


def test_use_after_free() -> None:
    message, signature, public_key = b"message", b"signature", b"public key"
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        sig = oqs.StatefulSignature(alg_name)
        sig.free()
        calls: dict[str, Callable[[], object]] = {
            "generate_keypair": sig.generate_keypair,
            "sign": lambda s=sig: s.sign(message),
            "verify": lambda s=sig: s.verify(message, signature, public_key),
            "export_secret_key": sig.export_secret_key,
            "sigs_total": sig.sigs_total,
            "sigs_remaining": sig.sigs_remaining,
        }
        for name, call in calls.items():
            _assert_raises_freed(f"{alg_name}.{name}", call)


if __name__ == "__main__":
    try:
        import nose2

        nose2.main()
    except ImportError:
        msg_ = "nose2 module not found. Please install it with 'pip install nose2'."
        raise RuntimeError(msg_) from None
