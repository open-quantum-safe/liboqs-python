import ssl
import urllib.request
import json
import os
import oqs

# Example code testing oqs signature functionality. See more example code at
# https://github.com/open-quantum-safe/liboqs-python/tree/main/examples

message = "This is the message to sign".encode()

# create signer and verifier with sample signature mechanisms
sigalg = "Dilithium2"
with oqs.Signature(sigalg) as signer:
    with oqs.Signature(sigalg) as verifier:
        signer_public_key = signer.generate_keypair()
        signature = signer.sign(message)
        is_valid = verifier.verify(message, signature, signer_public_key)

if (not is_valid):
    print("Failed to validate signature. Exiting.")
    exit(1)
else:
    print("Validated signature for OQS algorithm %s" % (sigalg))

# Example code iterating over all supported OQS algorithms integrated into TLS

sslContext= ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
sslContext.verify_mode = ssl.CERT_REQUIRED
# Trust LetsEncrypt root CA:
sslContext.load_verify_locations(cafile="isrgrootx1.pem")

# Retrieve interop test server root CA
with urllib.request.urlopen('https://test.openquantumsafe.org/CA.crt', context=sslContext) as response:
    data=response.read()
    with open("CA.crt", "w+b") as f:
        f.write(data)

# Retrieve JSON structure of all alg/port combinations:
with urllib.request.urlopen('https://test.openquantumsafe.org/assignments.json', context=sslContext) as response:
    assignments=json.loads(response.read())

# Trust test.openquantumsafe.org root CA:
sslContext.load_verify_locations(cafile="CA.crt")

# Iterate over all algorithm/port combinations:
for sigs, kexs in assignments.items():
    for kex, port in kexs.items():
       if (kex != "*"): # '*' denoting any classic KEX alg
            # Enable use of the specific QSC KEX algorithm
            os.environ["TLS_DEFAULT_GROUPS"]=kex
       try:
          with urllib.request.urlopen('https://test.openquantumsafe.org:'+str(port), context=sslContext) as response:
            if response.getcode() != 200:
               print("Failed to test %s successfully" % (kex))
            else:
               print("Success testing %s at port %d" % (kex, port))
       except:
          print("Test of algorithm combination SIG %s/KEX %s failed. Are all algorithms supported by current OQS library?" % (sigs, kex))

    if "SHORT_TEST" in os.environ:
        exit(0)
