"""
Open Quantum Safe (OQS) Python Wrapper for liboqs

The liboqs project provides post-quantum public key cryptography algorithms:
https://github.com/open-quantum-safe/liboqs

This module provides a Python 3 interface to libOQS <oqs/rand.h> RNGs.
"""

import oqs


def randombytes(bytes_to_read):
    """
    Generates random bytes. This implementation uses either the default RNG algorithm ("system"), or whichever
    algorithm has been selected by random_bytes_switch_algorithm().

    :param bytes_to_read: the number of random bytes to generate.
    :return: random bytes.
    """
    result = oqs.ct.create_string_buffer(bytes_to_read)
    oqs.native().OQS_randombytes(result, oqs.ct.c_int(bytes_to_read))
    return bytes(result)


def randombytes_switch_algorithm(alg_name):
    """
    Switches the core OQS_randombytes to use the specified algorithm. See <oqs/rand.h> liboqs headers for more details.

    :param alg_name: algorithm name, possible values are "system" and "OpenSSL".
    """
    if (
        oqs.native().OQS_randombytes_switch_algorithm(
            oqs.ct.create_string_buffer(alg_name.encode())
        )
        != oqs.OQS_SUCCESS
    ):
        raise RuntimeError("Can not switch algorithm")
