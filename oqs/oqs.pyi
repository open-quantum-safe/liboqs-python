import ctypes
from types import TracebackType
from typing import Final, TypeVar, final, TypedDict

_TKeyEncapsulation = TypeVar("_TKeyEncapsulation", bound="KeyEncapsulation")
_TSignature = TypeVar("_TSignature", bound="Signature")

OQS_SUCCESS: Final[int]
OQS_ERROR: Final[int]
OQS_VERSION: str | None

def oqs_python_version() -> str | None: ...
def native() -> ctypes.CDLL: ...
def oqs_version() -> str: ...

class MechanismNotSupportedError(Exception):
    alg_name: str
    message: str
    def __init__(self, alg_name: str) -> None: ...

class MechanismNotEnabledError(MechanismNotSupportedError):
    # alg_name and message are inherited from MechanismNotSupportedError
    def __init__(self, alg_name: str) -> None: ...

class KeyEncapsulationDetails(TypedDict):
    name: str
    version: str
    claimed_nist_level: int
    is_ind_cca: bool
    length_public_key: int
    length_secret_key: int
    length_ciphertext: int
    length_shared_secret: int

@final
class KeyEncapsulation:
    # Attributes from the underlying ctypes.Structure, exposed with Python types
    method_name: bytes
    alg_version: bytes
    claimed_nist_level: int
    ind_cca: int
    length_public_key: int
    length_secret_key: int
    length_ciphertext: int
    length_shared_secret: int

    # Custom attributes set during initialization
    alg_name: str
    details: KeyEncapsulationDetails

    def __init__(self, alg_name: str, secret_key: int | bytes | None = None) -> None: ...
    def __enter__(self: _TKeyEncapsulation) -> _TKeyEncapsulation: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def generate_keypair(self) -> bytes: ...
    def export_secret_key(self) -> bytes: ...
    def encap_secret(self, public_key: int | bytes) -> tuple[bytes, bytes]: ...
    def decap_secret(self, ciphertext: int | bytes) -> bytes: ...
    def free(self) -> None: ...
    def __repr__(self) -> str: ...

class SignatureDetails(TypedDict):
    name: str
    version: str
    claimed_nist_level: int
    is_euf_cma: bool
    sig_with_ctx_support: bool
    length_public_key: int
    length_secret_key: int
    length_signature: int

@final
class Signature:
    # Attributes from the underlying ctypes.Structure, exposed with Python types
    method_name: bytes
    alg_version: bytes
    claimed_nist_level: int
    euf_cma: int
    sig_with_ctx_support: int
    length_public_key: int
    length_secret_key: int
    length_signature: int

    # Custom attributes set during initialization
    alg_name: str
    details: SignatureDetails

    def __init__(self, alg_name: str, secret_key: int | bytes | None = None) -> None: ...
    def __enter__(self: _TSignature) -> _TSignature: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def generate_keypair(self) -> bytes: ...
    def export_secret_key(self) -> bytes: ...
    def sign(self, message: bytes) -> bytes: ...
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool: ...
    def sign_with_ctx_str(self, message: bytes, context: bytes) -> bytes: ...
    def verify_with_ctx_str(
        self, message: bytes, signature: bytes, context: bytes, public_key: bytes
    ) -> bool: ...
    def free(self) -> None: ...
    def __repr__(self) -> str: ...

def is_kem_enabled(alg_name: str) -> bool: ...
def get_enabled_kem_mechanisms() -> tuple[str, ...]: ...
def get_supported_kem_mechanisms() -> tuple[str, ...]: ...
def is_sig_enabled(alg_name: str) -> bool: ...
def get_enabled_sig_mechanisms() -> tuple[str, ...]: ...
def get_supported_sig_mechanisms() -> tuple[str, ...]: ...
