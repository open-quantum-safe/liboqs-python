# Various RNGs Python example
import logging
import platform  # to learn the OS we're on

import oqs.rand as oqsrand  # must be explicitly imported
from oqs import oqs_python_version, oqs_version

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

logger.info("liboqs version: %s", oqs_version())
logger.info("liboqs-python version: %s", oqs_python_version())

oqsrand.randombytes_switch_algorithm("system")
logger.info(
    "System (default): %s",
    " ".join(f"{x:02X}" for x in oqsrand.randombytes(32)),
)

# We do not yet support OpenSSL under Windows
if platform.system() != "Windows":
    oqsrand.randombytes_switch_algorithm("OpenSSL")
    logger.info(
        "OpenSSL: %s",
        " ".join(f"{x:02X}" for x in oqsrand.randombytes(32)),
    )
