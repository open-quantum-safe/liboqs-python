import unittest
import os

from tmp_stateful import StatefulSignature


class TestXMSSStatefulSignature(unittest.TestCase):
    def test_xmss_saved_used_keys(self):
        """
        GIVEN a StatefulSignature instance for XMSS.
        WHEN generating a keypair and signing messages,
        THEN the used keys should be correctly tracked and exported.
        """
        # Generate key and sign a message
        with StatefulSignature("XMSS-SHA2_10_256") as sig:
            public_key = sig.generate_keypair()
            self.assertIsNotNone(public_key, "Public key generation failed")
            message = os.urandom(32)
            signature = sig.sign(message)
            self.assertTrue(
                sig.verify(message, signature, public_key), "Signature verification failed"
            )
            signature2 = sig.sign(b"Hello, XMSS!")
            self.assertTrue(
                sig.verify(b"Hello, XMSS!", signature2, public_key),
                "Second signature verification failed",
            )
            out = sig.export_used_keys()
            self.assertEqual(len(out), 2, f"Exported keys should contain 2 keys. Got: {len(out)}")

    def test_xmss_key_generation_signing_serialization(self):
        """
        GIVEN a StatefulSignature instance for XMSS.
        WHEN generating a keypair, signing messages, and exporting used keys,
        THEN the keys should be correctly serialized and deserialized.
        """
        message = os.urandom(32)
        message2 = b"Hello, XMSS!"
        new_message = b"Hello again, XMSS!"

        # Generate key and sign twice
        with StatefulSignature("XMSS-SHA2_10_256") as sig:
            public_key = sig.generate_keypair()
            # Sign two messages
            signature = sig.sign(message)
            self.assertTrue(
                sig.verify(message, signature, public_key), "First signature verification failed"
            )

            second_sig = sig.sign(message2)
            self.assertTrue(
                sig.verify(message2, second_sig, public_key),
                "Second signature verification failed",
            )
            self.assertFalse(
                sig.verify(message2, signature, public_key),
                "Old signature should not verify new message",
            )

            # Export used keys
            out = sig.export_used_keys()

        self.assertEqual(len(out), 2, f"Exported keys should contain 2 keys. Got: {len(out)}")

        # Deserialize from first saved key state
        sig2 = StatefulSignature("XMSS-SHA2_10_256", secret_key_bytes=out[0])
        self.assertEqual(
            len(sig2.export_used_keys()), 0, "Used keys list should be empty after deserialization"
        )

        # Sign a new message with restored key
        new_signature = sig2.sign(new_message)
        self.assertTrue(
            sig2.verify(new_message, new_signature, public_key),
            "Signature verification after deserialization failed",
        )

        # Ensure state advancement occurred
        out2 = sig2.export_used_keys()
        self.assertNotEqual(out2[0], out[0], "Deserialized key should have advanced after signing")


if __name__ == "__main__":
    unittest.main()
