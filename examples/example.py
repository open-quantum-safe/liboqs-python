# illustrates how to use the python OQS wrapper

import oqs


#######################################################################
# KEM example
#######################################################################

oqs.print_enabled_KEM_mechanisms()
# (or obtain a list and go through them)
kems = oqs.get_enabled_KEM_mechanisms()

# create a client and server with the default KEM mechanism
kemalg = "DEFAULT"
with oqs.OQS_KEM(kemalg) as client:
    with oqs.OQS_KEM(kemalg) as server:
        print("Starting key encapsulation")
        print(client.details)

        # client generates its keypair
        public_key = client.generate_keypair()
        # optionally, the secret key can be obtained by calling export_secret_key()
        # and the client can later be reinstantiated with the key pair:
        # secret_key = client.export_secret_key()
        # store key pair, wait... (session resumption):
        # client = oqs.OQS_KEM(kemalg, secret_key)

        # the server encapsulates its secret using the client's public key
        ciphertext, shared_secret_server = server.encap_secret(public_key)

        # the client decapsulates the the server's ciphertext to obtain the shared secret
        shared_secret_client = client.decap_secret(ciphertext)

        if shared_secret_client == shared_secret_server:
            print("success: shared secrets are equal")
        else:
            print("error: shared secrets are NOT equal")

print()

#######################################################################
# Signature example
#######################################################################

oqs.print_enabled_sig_mechanisms()
# (or obtain a list and go through them)
sigs = oqs.get_enabled_sig_mechanisms()

# create a signer and verifier with the default signature mechanism
sigalg = "DEFAULT"
with oqs.OQS_SIG(sigalg) as signer:
    with oqs.OQS_SIG(sigalg) as verifier:
        print("Starting signature")
        print(signer.details)

        # the signer generates its keypair
        signer_public_key = signer.generate_keypair()
        # optionally, the secret key can be obtained by calling export_secret_key()
        # and the signer can later be reinstantiated with the key pair:
        # signer_secret_key = signer.export_secret_key()
        # store key pair, wait... (session resumption):
        # signer = oqs.OQS_SIG(sigalg, signer_secret_key)

        # the message to sign
        message = b'This is the message to sign'

        # the signer signs the message
        signature = signer.sign(message)

        # the verifier verifies the signature on the message
        is_valid = verifier.verify(message, signature, signer_public_key)

        if is_valid:
            print("signature is valid")
        else:
            print("signature is invalid")
