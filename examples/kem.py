# Key encapsulation Python example
import logging
from pprint import pformat

import oqs

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

logger.info("liboqs version: %s", oqs.oqs_version())
logger.info("liboqs-python version: %s", oqs.oqs_python_version())
logger.info("Enabled KEM mechanisms: %s", pformat(oqs.get_enabled_kem_mechanisms(), compact=True))

# Create client and server with sample KEM mechanisms
kemalg = "Kyber512"
with oqs.KeyEncapsulation(kemalg) as client, oqs.KeyEncapsulation(kemalg) as server:
    # print("\nKey encapsulation details:")
    logger.info("Client details: %s", pformat(client.details))

    # Client generates its keypair
    public_key_client = client.generate_keypair()
    # Optionally, the secret key can be obtained by calling export_secret_key()
    # and the client can later be re-instantiated with the key pair:
    # secret_key_client = client.export_secret_key()

    # Store key pair, wait... (session resumption):
    # client = oqs.KeyEncapsulation(kemalg, secret_key_client)

    # The server encapsulates its secret using the client's public key
    ciphertext, shared_secret_server = server.encap_secret(public_key_client)

    # The client decapsulates the server's ciphertext to obtain the shared secret
    shared_secret_client = client.decap_secret(ciphertext)

    logger.info(
        "Shared secretes coincide: %s",
        shared_secret_client == shared_secret_server,
    )
