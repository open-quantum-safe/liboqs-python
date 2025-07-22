import logging
import platform  # to learn the OS we're on
import random

import oqs

_skip_names = ["LMS_SHA256_H20_W8_H10_W8", "LMS_SHA256_H20_W8_H15_W8", "LMS_SHA256_H20_W8_H20_W8"]


# Sigs for which unit testing is disabled
disabled_sig_patterns = []

if platform.system() == "Windows":
    disabled_sig_patterns = [""]


def test_correctness() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_correctness, alg_name


def check_correctness(alg_name: str) -> None:
    with oqs.StatefulSignature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert sig.verify(message, signature, public_key)  # noqa: S101


def test_wrong_message() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_message, alg_name


def check_wrong_message(alg_name: str) -> None:
    with oqs.StatefulSignature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        wrong_message = bytes(random.getrandbits(8) for _ in range(len(message)))
        assert not (sig.verify(wrong_message, signature, public_key))  # noqa: S101


def test_wrong_signature() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_signature, alg_name


def check_wrong_signature(alg_name: str) -> None:
    with oqs.StatefulSignature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        wrong_signature = bytes(random.getrandbits(8) for _ in range(len(signature)))
        assert not (sig.verify(message, wrong_signature, public_key))  # noqa: S101


def test_wrong_public_key() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_public_key, alg_name


def check_wrong_public_key(alg_name: str) -> None:
    with oqs.StatefulSignature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
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


if __name__ == "__main__":
    try:
        import nose2

        nose2.main()
    except ImportError:
        msg_ = "nose2 module not found. Please install it with 'pip install nose2'."
        raise RuntimeError(msg_) from None
