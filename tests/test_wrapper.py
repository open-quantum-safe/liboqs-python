import unittest
import random

import oqs


class TestKEM(unittest.TestCase):

    def test_kem(self):
        for alg_name in oqs._enabled_KEMs:
            with self.subTest(alg_name=alg_name):
                kem = oqs.OQS_KEM(alg_name)
                public_key = kem.generate_keypair()
                ciphertext, shared_secret_server = kem.encap_secret(public_key)
                shared_secret_client = kem.decap_secret(ciphertext)
                self.assertEqual(shared_secret_client, shared_secret_server)

                # failure cases

                # wrong ciphertext
                wrong_ciphertext = bytes(random.getrandbits(8) for _ in range(kem.details['length_ciphertext']))
                shared_secret_client_2 = kem.decap_secret(wrong_ciphertext)
                self.assertNotEqual(shared_secret_client_2, shared_secret_server)

                # wrong secret key
                wrong_secret_key = bytes(random.getrandbits(8) for _ in range(kem.details['length_secret_key']))
                kem2 = oqs.OQS_KEM(alg_name, wrong_secret_key)
                shared_secret_client_3 = kem2.decap_secret(ciphertext)
                self.assertNotEqual(shared_secret_client_3, shared_secret_server)

                # clean-up
                kem.free()
                kem2.free()

    def test_not_supported(self):
        with self.assertRaises(oqs.MechanismNotSupportedError):
            kem = oqs.OQS_KEM('bogus')

    def test_not_enabled(self):
        for alg_name in oqs._supported_KEMs:
            if alg_name not in oqs._enabled_KEMs:
                # found an non-enabled but supported alg
                with self.assertRaises(oqs.MechanismNotEnabledError):
                    kem = oqs.OQS_KEM(alg_name)
                return

class TestSig(unittest.TestCase):

    def test_sig(self):
        for alg_name in oqs._enabled_sigs:
            with self.subTest(alg_name=alg_name):
                message = bytes(random.getrandbits(8) for _ in range(100))
                sig = oqs.Signature(alg_name)
                public_key = sig.generate_keypair()
                signature = sig.sign(message)
                self.assertTrue(sig.verify(message, signature, public_key))

                # failure cases
                # TODO: picnic prints out error messages when processing garbage data
                #       it'd be good to silence the output, following something like:
                #       https://stackoverflow.com/questions/5081657/how-do-i-prevent-a-c-shared-library-to-print-on-stdout-in-python

                # wrong message
                wrong_message = bytes(random.getrandbits(8) for _ in range(100))
                self.assertFalse(sig.verify(wrong_message, signature, public_key))

                # wrong signature
                wrong_signature = bytes(random.getrandbits(8) for _ in range(sig.details['length_signature']))
                self.assertFalse(sig.verify(message, wrong_signature, public_key))

                # wrong public key
                wrong_public_key = bytes(random.getrandbits(8) for _ in range(sig.details['length_public_key']))
                self.assertFalse(sig.verify(message, signature, wrong_public_key))

                # clean-up
                sig.free()


    def test_not_supported(self):
        with self.assertRaises(oqs.MechanismNotSupportedError):
            sig = oqs.Signature('bogus')

    def test_not_enabled(self):
        for alg_name in oqs._supported_sigs:
            if alg_name not in oqs._enabled_sigs:
                # found an non-enabled but supported alg
                with self.assertRaises(oqs.MechanismNotEnabledError):
                    sig = oqs.Signature(alg_name)
                return

if __name__ == '__main__':
    unittest.main()
