import platform  # to learn the OS we're on
import random

import oqs

# Sigs for which unit testing is disabled
disabled_sig_patterns = []

if platform.system() == "Windows":
    disabled_sig_patterns = ["Rainbow-V"]


def test_correctness() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_correctness, alg_name


def check_correctness(alg_name: str) -> None:
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert sig.verify(message, signature, public_key)  # noqa: S101


def test_wrong_message() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_message, alg_name


def check_wrong_message(alg_name: str) -> None:
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        wrong_message = bytes(random.getrandbits(8) for _ in range(len(message)))
        assert not (sig.verify(wrong_message, signature, public_key))  # noqa: S101


def test_wrong_signature() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_signature, alg_name


def check_wrong_signature(alg_name: str) -> None:
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        wrong_signature = bytes(random.getrandbits(8) for _ in range(len(signature)))
        assert not (sig.verify(message, wrong_signature, public_key))  # noqa: S101


def test_wrong_public_key() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_sig_mechanisms():
        if any(item in alg_name for item in disabled_sig_patterns):
            continue
        yield check_wrong_public_key, alg_name


def check_wrong_public_key(alg_name: str) -> None:
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        wrong_public_key = bytes(random.getrandbits(8) for _ in range(len(public_key)))
        assert not (sig.verify(message, signature, wrong_public_key))  # noqa: S101


def test_not_supported() -> None:
    try:
        with oqs.Signature("bogus") as _sig:
            msg = "oqs.MechanismNotSupportedError was not raised."
            raise AssertionError(msg)  # noqa: TRY301
    except oqs.MechanismNotSupportedError:
        pass
    except Exception as ex:  # noqa: BLE001
        msg = f"An unexpected exception was raised. {ex}"
        raise AssertionError(msg)  # noqa: B904


def test_not_enabled() -> None:
    # TODO: test broken as the compiled lib determines which algorithms are supported and enabled
    for alg_name in oqs.get_supported_sig_mechanisms():
        if alg_name not in oqs.get_enabled_sig_mechanisms():
            # Found a non-enabled but supported alg
            try:
                with oqs.Signature(alg_name) as _sig:
                    msg = "oqs.MechanismNotEnabledError was not raised."
                    raise AssertionError(msg)  # noqa: TRY301
            except oqs.MechanismNotEnabledError:
                pass
            except Exception as ex:  # noqa: BLE001
                msg = f"An unexpected exception was raised. {ex}"
                raise AssertionError(msg)  # noqa: B904


if __name__ == "__main__":
    try:
        import nose2

        nose2.main()

    except ImportError:
        import nose

        nose.runmodule()
