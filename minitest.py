import ssl
import urllib.request
import json
import os

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
       with urllib.request.urlopen('https://test.openquantumsafe.org:'+str(port), context=sslContext) as response:
            if response.getcode() != 200:
               print("Failed to test %s successfully" % (kex))
            else:
               print("Success testing %s at port %d" % (kex, port))
