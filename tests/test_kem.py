import platform  # to learn the OS we're on
import random

import oqs

# KEMs for which unit testing is disabled
disabled_KEM_patterns = []  # noqa: N816

if platform.system() == "Windows":
    disabled_KEM_patterns = [""]  # noqa: N816


def test_correctness() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_kem_mechanisms():
        if any(item in alg_name for item in disabled_KEM_patterns):
            continue
        yield check_correctness, alg_name


def check_correctness(alg_name: str) -> None:
    with oqs.KeyEncapsulation(alg_name) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret_server = kem.encap_secret(public_key)
        shared_secret_client = kem.decap_secret(ciphertext)
        assert shared_secret_client == shared_secret_server  # noqa: S101


def test_wrong_ciphertext() -> tuple[None, str]:
    for alg_name in oqs.get_enabled_kem_mechanisms():
        if any(item in alg_name for item in disabled_KEM_patterns):
            continue
        yield check_wrong_ciphertext, alg_name


def check_wrong_ciphertext(alg_name: str) -> None:
    with oqs.KeyEncapsulation(alg_name) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret_server = kem.encap_secret(public_key)
        wrong_ciphertext = bytes(random.getrandbits(8) for _ in range(len(ciphertext)))
        try:
            shared_secret_client = kem.decap_secret(wrong_ciphertext)
            assert shared_secret_client != shared_secret_server  # noqa: S101
        except RuntimeError:
            pass
        except Exception as ex:
            msg = f"An unexpected exception was raised: {ex}"
            raise AssertionError(msg) from ex


def test_not_supported() -> None:
    try:
        with oqs.KeyEncapsulation("unsupported_sig"):
            pass
    except oqs.MechanismNotSupportedError:
        pass
    except Exception as ex:
        msg = f"An unexpected exception was raised {ex}"
        raise AssertionError(msg) from ex
    else:
        msg = "oqs.MechanismNotSupportedError was not raised."
        raise AssertionError(msg)


def test_not_enabled() -> None:
    for alg_name in oqs.get_supported_kem_mechanisms():
        if alg_name not in oqs.get_enabled_kem_mechanisms():
            # Found a non-enabled but supported alg
            try:
                with oqs.KeyEncapsulation(alg_name):
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
    for alg_name in oqs.get_enabled_kem_mechanisms():
        with oqs.KeyEncapsulation(alg_name) as kem:
            if kem.method_name.decode() != alg_name:
                msg = "Incorrect oqs.KeyEncapsulation.method_name"
                raise AssertionError(msg)
            if kem.alg_version is None:
                msg = "Undefined oqs.KeyEncapsulation.alg_version"
                raise AssertionError(msg)
            if not 1 <= kem.claimed_nist_level <= 5:
                msg = "Invalid oqs.KeyEncapsulation.claimed_nist_level"
                raise AssertionError(msg)
            if kem.length_public_key == 0:
                msg = "Incorrect oqs.KeyEncapsulation.length_public_key"
                raise AssertionError(msg)
            if kem.length_secret_key == 0:
                msg = "Incorrect oqs.KeyEncapsulation.length_secret_key"
                raise AssertionError(msg)
            if kem.length_ciphertext == 0:
                msg = "Incorrect oqs.KeyEncapsulation.length_signature"
                raise AssertionError(msg)
            if kem.length_shared_secret == 0:
                msg = "Incorrect oqs.KeyEncapsulation.length_shared_secret"
                raise AssertionError(msg)


if __name__ == "__main__":
    try:
        import nose2

        nose2.main()
    except ImportError:
        msg_ = "nose2 module not found. Please install it with 'pip install nose2'."
        raise RuntimeError(msg_) from None
