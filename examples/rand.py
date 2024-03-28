# Various RNGs Python example

import platform  # to learn the OS we're on
import oqs.rand as oqsrand  # must be explicitly imported
from oqs import oqs_version, oqs_python_version

print("liboqs version:", oqs_version())
print("liboqs-python version:", oqs_python_version())

oqsrand.randombytes_switch_algorithm("system")
print(
    "{:17s}".format("System (default):"),
    " ".join("{:02X}".format(x) for x in oqsrand.randombytes(32)),
)

# We do not yet support OpenSSL under Windows
if platform.system() != "Windows":
    oqsrand.randombytes_switch_algorithm("OpenSSL")
    print(
        "{:17s}".format("OpenSSL:"),
        " ".join("{:02X}".format(x) for x in oqsrand.randombytes(32)),
    )
