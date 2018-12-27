import unittest
import oqswrap
import random

class TestKEM(unittest.TestCase):

    def test_kem(self):
        for alg_name in oqswrap._enabled_KEMs:
            with self.subTest(alg_name=alg_name):
                kem = oqswrap.KeyEncapsulation(alg_name)
                public_key = kem.generate_keypair()
                encap_data = kem.encap_secret(public_key)
                shared_secret_client = kem.decap_secret(encap_data.ciphertext)
                self.assertEqual(shared_secret_client, encap_data.shared_secret)
                
                # failure cases
                
                # wrong ciphertext
                wrong_ciphertext = bytes(random.getrandbits(8) for _ in range(kem.details['length_ciphertext']))
                shared_secret_client_2 = kem.decap_secret(wrong_ciphertext)
                self.assertNotEqual(shared_secret_client_2, encap_data.shared_secret)
                
                # wrong secret key
                wrong_secret_key = bytes(random.getrandbits(8) for _ in range(kem.details['length_secret_key']))
                kem2 = oqswrap.KeyEncapsulation(alg_name, wrong_secret_key)
                shared_secret_client_3 = kem2.decap_secret(encap_data.ciphertext)
                self.assertNotEqual(shared_secret_client_3, encap_data.shared_secret)

                # clean-up
                kem.free()
                kem2.free()

    def test_not_supported(self):
        with self.assertRaises(oqswrap.MechanismNotSupportedError):
            kem = oqswrap.KeyEncapsulation('bogus')
        
    def test_not_enabled(self):
        for alg_name in oqswrap._supported_KEMs:
            if alg_name not in oqswrap._enabled_KEMs:
                # found an non-enabled but supported alg
                with self.assertRaises(oqswrap.MechanismNotEnabledError):
                    kem = oqswrap.KeyEncapsulation(alg_name)
                return
    
class TestSig(unittest.TestCase):

    def test_sig(self):
        for alg_name in oqswrap._enabled_sigs:
            with self.subTest(alg_name=alg_name):
                message = bytes(random.getrandbits(8) for _ in range(100))
                sig = oqswrap.Signature(alg_name)
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
        with self.assertRaises(oqswrap.MechanismNotSupportedError):
            sig = oqswrap.Signature('bogus')
        
    def test_not_enabled(self):
        for alg_name in oqswrap._supported_sigs:
            if alg_name not in oqswrap._enabled_sigs:
                # found an non-enabled but supported alg
                with self.assertRaises(oqswrap.MechanismNotEnabledError):
                    sig = oqswrap.Signature(alg_name)
                return

if __name__ == '__main__':
    unittest.main()
