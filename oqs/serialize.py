"""
Serialization and deserialization of stateful signature keys
using OneAsymmetricKey (PKCS#8) structure.
"""

import logging
from pathlib import Path
from typing import Optional, Union

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, tag

import oqs
from pyasn1_alt_modules import rfc5958

_NAME_2_OIDS = {
    "hss": "1.2.840.113549.1.9.16.3.17",  # RFC 9708
    "xmss": "1.3.6.1.5.5.7.6.34",  # RFC 9802
    "xmssmt": "1.3.6.1.5.5.7.6.35",  # RFC 9802
}
_OID_2_NAME = {v: k for k, v in _NAME_2_OIDS.items()}

_KEY_DIR = Path(__file__).resolve().parent.parent / "data" / "xmss_xmssmt_keys"


def _get_oid_from_name(name: str) -> str:
    """Get the OID corresponding to the stateful signature name."""
    if name.startswith("LMS"):
        return _NAME_2_OIDS["hss"]
    if name.startswith("XMSS-"):
        return _NAME_2_OIDS["xmss"]
    if name.startswith("XMSSMT-"):
        return _NAME_2_OIDS["xmssmt"]
    msg = f"Unsupported stateful signature name: {name}"
    raise ValueError(msg)


def serialize_stateful_signature_key(
    stateful_sig: oqs.StatefulSignature, public_key: bytes, fpath: Union[Path, str]
) -> None:
    """
    Serialize the stateful signature key to a `OneAsymmetricKey` structure.

    :param stateful_sig: The stateful signature object.
    :param public_key: The public key bytes.
    :param fpath: The file path to save the serialized key.
    """
    one_asym_key = rfc5958.OneAsymmetricKey()
    one_asym_key["version"] = 1
    one_asym_key["privateKeyAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
        _get_oid_from_name(stateful_sig.method_name.decode())
    )
    one_asym_key["privateKey"] = stateful_sig.export_secret_key()
    one_asym_key["publicKey"] = (
        rfc5958.PublicKey()
        .fromOctetString(public_key)
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    )

    der_data = encoder.encode(one_asym_key)
    fpath_obj = Path(fpath)
    with fpath_obj.open("wb") as f:
        f.write(der_data)
    logging.info("Wrote: %s", fpath_obj.name)


def deserialize_stateful_signature_key(
    key_name: str, dir_name: Union[str, Path] = _KEY_DIR
) -> tuple[bytes, bytes]:
    """
    Deserialize the stateful signature key from a `OneAsymmetricKey` structure.

    :param key_name: The base name of the serialized key (without extension).
    :param dir_name: The directory where the key files are stored.
    :return: A tuple (private_key_bytes, public_key_bytes).
    """
    key_name = key_name.replace("/", "_layers_", 1).lower()
    fpath = Path(dir_name) / f"{key_name}.der"

    with fpath.open("rb") as f:
        der_data = f.read()

    one_asym_key = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())[0]
    oid = str(one_asym_key["privateKeyAlgorithm"]["algorithm"])

    # Accept any OID for supported families
    if oid not in _OID_2_NAME:
        msg = f"Unsupported stateful signature OID: {oid}"
        raise ValueError(msg)

    private_key_bytes = one_asym_key["privateKey"].asOctets()
    public_key_bytes = one_asym_key["publicKey"].asOctets()
    return private_key_bytes, public_key_bytes


def _may_generate_stfl_key(
    key_name: str, dir_name: str
) -> tuple[Optional[bytes], Optional[bytes]]:
    """
    Decide whether to generate a stateful signature key for the given algorithm name.

    Currently, this function allows opportunistic generation only for fast XMSS parameter sets
    used in tests, specifically those starting with "XMSS-" and containing "_16_".

    :param key_name: The name of the stateful signature mechanism.
    :param dir_name: The directory where the key files are stored.
    :return: A tuple (private_key_bytes, public_key_bytes) if generated, else (None, None).
    """
    alt_path = Path(str(dir_name).replace("xmss_xmssmt_keys", "tmp_keys", 1))
    alt_fpath = alt_path / f"{key_name.replace('/', '_layers_', 1).lower()}.der"
    if key_name.startswith("XMSS-") and "_16_" in key_name:
        Path(alt_path).mkdir(parents=True, exist_ok=True)
        with oqs.StatefulSignature(key_name) as stfl_sig:
            public_key_bytes = stfl_sig.generate_keypair()
            private_key_bytes = stfl_sig.export_secret_key()
            serialize_stateful_signature_key(stfl_sig, public_key_bytes, str(alt_fpath))
            return private_key_bytes, public_key_bytes

    return None, None


def gen_or_load_stateful_signature_key(
    key_name: str, dir_name: Union[str, Path] = _KEY_DIR
) -> tuple[Optional[bytes], Optional[bytes]]:
    """
    Generate or load a stateful signature key pair.

    :param key_name: The name of the stateful signature mechanism.
    :param dir_name: The directory where the key files are stored.
    :return: A tuple (stateful_signature_object, public_key_bytes).
    """
    key_file_name = key_name.replace("/", "_layers_", 1).lower()
    fpath = Path(dir_name) / f"{key_file_name}.der"

    if Path(fpath).exists():
        return deserialize_stateful_signature_key(key_file_name, dir_name=dir_name)

    # Check alternative path for test keys, to avoid regenerating for every test run.
    alt_path = Path(str(_KEY_DIR).replace("xmss_xmssmt_keys", "tmp_keys", 1))
    alt_fpath = alt_path / f"{key_file_name}.der"
    if Path(alt_fpath).exists():
        private_key_bytes, public_key_bytes = deserialize_stateful_signature_key(
            key_name, dir_name=alt_path
        )
        return private_key_bytes, public_key_bytes

    # Opportunistic generation for fast XMSS parameter sets used in tests
    return _may_generate_stfl_key(key_name, dir_name)


if __name__ == "__main__":
    xmss_names = [
        name for name in oqs.get_enabled_stateful_sig_mechanisms() if name.startswith("XMSS-")
    ]
    xmssmt_names = [
        name for name in oqs.get_enabled_stateful_sig_mechanisms() if name.startswith("XMSSMT-")
    ]
    hss_names = [
        name for name in oqs.get_enabled_stateful_sig_mechanisms() if name.startswith("LMS")
    ]
    logging.info("xmss_names: %s", str(xmss_names))
    private_bytes, public_bytes = deserialize_stateful_signature_key(
        "XMSS-sha2_20_512", dir_name=_KEY_DIR
    )
    if private_bytes is None or public_bytes is None:
        ERROR_MSG = "Could not load the XMSS key"
        raise ValueError(ERROR_MSG)
    logging.info("Loaded XMSS key, public key len: %d", len(public_bytes))
