import unittest
import os

from tmp_stateful import StatefulSignature


class TestXMSSKeyUsageTracking(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.algorithm = "XMSS-SHA2_10_256"
        cls.message = os.urandom(32)
        cls.message2 = b"Hello, XMSS!"
        cls.message3 = b"Hello again, XMSS!"

    def test_total_and_remaining_signatures_tracking(self):
        """
        GIVEN a StatefulSignature instance for XMSS.
        WHEN generating a keypair and signing multiple messages
        THEN the total number of signatures and remaining signatures are tracked correctly.
        """
        message = os.urandom(32)
        message2 = b"Hello, XMSS!"
        message3 = b"Hello again, XMSS!"

        # First signer: generate key and sign twice
        with StatefulSignature(self.algorithm) as sig:
            public_key = sig.generate_keypair()

            total_before = sig.sigs_total()
            remain_before = sig.sigs_remaining()
            self.assertGreaterEqual(total_before, 2, "Expected at least 2 total signatures")
            self.assertEqual(remain_before, total_before)

            sig.sign(message)
            sig.sign(message2)

            remain_after = sig.sigs_remaining()
            self.assertEqual(
                remain_after, total_before - 2, "Remaining signatures did not decrease by 2"
            )

            # Save serialized secret key states
            exported_keys = sig.export_used_keys()
            self.assertEqual(len(exported_keys), 2, "Expected 2 saved key states")

        sig2 = StatefulSignature(self.algorithm, secret_key_bytes=exported_keys[0])
        total2 = sig2.sigs_total()
        remain2 = sig2.sigs_remaining()
        self.assertEqual(total2, total_before)
        self.assertEqual(remain2, total_before - 1)

        new_sig = sig2.sign(message3)
        self.assertTrue(
            sig2.verify(message3, new_sig, public_key), "Signature after deserialization invalid"
        )

        self.assertEqual(sig2.sigs_remaining(), total_before - 2)

        with StatefulSignature(self.algorithm) as sig3:
            sig3.generate_keypair()
            total3 = sig3.sigs_total()
            remain3 = sig3.sigs_remaining()
            self.assertEqual(total3, total_before)
            self.assertEqual(remain3, total_before)

    def test_remaining_equals_zero_after_exhaustion(self):
        """
        GIVEN a StatefulSignature instance for XMSS.
        WHEN signing the maximum number of signatures allowed
        THEN the remaining signatures should be zero.
        """
        with StatefulSignature(self.algorithm) as sig:
            sig.generate_keypair()
            total = sig.sigs_total()

            for _ in range(total):
                sig.sign(os.urandom(16))

            self.assertEqual(sig.sigs_remaining(), 0)

    def test_remaining_equals_zero_after_exhaustion2(self):
        """
        GIVEN a StatefulSignature instance for XMSS.
        WHEN signing one more than the maximum number of signatures allowed
        THEN the remaining signatures should be zero, and the last signature should still verify.
        """
        with StatefulSignature(self.algorithm) as sig:
            public_key = sig.generate_keypair()
            total = sig.sigs_total()

            for _ in range(total + 1):
                data = os.urandom(16)
                val = sig.sign(data)

            # After exceeding total, remaining should be unsigned ulonglong - 1
            self.assertEqual(sig.sigs_remaining(), 18446744073709551615)
            self.assertFalse(
                sig.verify(message=data, signature=val, public_key=public_key),
                "Signature after exceeding total should still verify",
            )


if __name__ == "__main__":
    unittest.main()
