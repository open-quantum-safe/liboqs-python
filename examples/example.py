# illustrates how to use the python OQS wrapper

import oqs

#######################################################################
# KEM example
#######################################################################

# print the available KEM mechanisms
oqs.print_enabled_KEM_mechanisms()
# (or obtain a list and go through them)
kems = oqs.get_enabled_KEM_mechanisms()

# create a client and server with the default KEM mechanism
kemalg = "DEFAULT"
client = oqs.KeyEncapsulation(kemalg)
server = oqs.KeyEncapsulation(kemalg)
print("Starting key encapsulation")
print(client.details)

# client generates its keypair
public_key = client.generate_keypair()
# optionally, the secret key can be obtained by calling export_secret_key()
# and the client can later be reinstantiated with the key pair:
# secret_key = client.export_secret_key()
# store key pair, wait... (session resumption):
# client = oqs.KeyEncapsulation(kemalg, secret_key)

# the server encapsulates its secret using the client's public key
ciphertext, shared_secret_server = server.encap_secret(public_key)

# the client decapsulates the the server's ciphertext to obtain the shared secret
shared_secret_client = client.decap_secret(ciphertext)

if shared_secret_client == shared_secret_server:
    print("success: shared secrets are equal")
else:
    print("error: shared secrets are NOT equal")

# clean up
server.free()
client.free()

print()

#######################################################################
# Signature example
#######################################################################

# print the available signature mechanisms
oqs.print_enabled_sig_mechanisms()
# (or obtain a list and go through them)
sigs = oqs.get_enabled_sig_mechanisms()

# create a signer and verifier with the default signature mechanism
sigalg = "DEFAULT"
signer = oqs.Signature(sigalg)
verifier = oqs.Signature(sigalg)
print("Starting signature")
print(signer.details)

# the signer generates its keypair
signer_public_key = signer.generate_keypair()
# optionally, the secret key can be obtained by calling export_secret_key()
# and the signer can later be reinstantiated with the key pair:
# signer_secret_key = signer.export_secret_key()
# store key pair, wait... (session resumption):
# signer = oqs.Signature(sigalg, signer_secret_key)

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

# clean up
signer.free()
verifier.free()
