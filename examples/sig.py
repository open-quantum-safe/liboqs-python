# signature Python example

import oqs
from pprint import pprint

#######################################################################
# signature example
#######################################################################

print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())
print("Enabled signature mechanisms:")
sigs = oqs.get_enabled_sig_mechanisms()
pprint(sigs, compact=True)

message = "This is the message to sign".encode()

# create signer and verifier with sample signature mechanisms
sigalg = "Dilithium2"
with oqs.Signature(sigalg) as signer:
    with oqs.Signature(sigalg) as verifier:
        print("\nSignature details:")
        pprint(signer.details)

        # signer generates its keypair
        signer_public_key = signer.generate_keypair()
        # optionally, the secret key can be obtained by calling export_secret_key()
        # and the signer can later be re-instantiated with the key pair:
        # secret_key = signer.export_secret_key()
        # store key pair, wait... (session resumption):
        # signer = oqs.Signature(sigalg, secret_key)

        # signer signs the message
        signature = signer.sign(message)

        # verifier verifies the signature
        is_valid = verifier.verify(message, signature, signer_public_key)

        print("\nValid signature?", is_valid)
