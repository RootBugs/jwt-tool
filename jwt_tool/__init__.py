"""jwt-tool: zero-dependency HS256/384/512 JWT sign/verify library."""

from .core import (
    SUPPORTED_ALGORITHMS,
    KeyRing,
    b64url_decode,
    b64url_encode,
    decode,
    decode_header,
    decode_payload,
    encode,
    forge_none_alg,
)
from .exceptions import (
    AlgorithmError,
    ClaimError,
    InvalidSignatureError,
    JWTError,
    MalformedTokenError,
    UnknownKeyError,
)

__version__ = "1.0.0"

__all__ = [
    "SUPPORTED_ALGORITHMS",
    "AlgorithmError",
    "ClaimError",
    "InvalidSignatureError",
    "JWTError",
    "KeyRing",
    "MalformedTokenError",
    "UnknownKeyError",
    "b64url_decode",
    "b64url_encode",
    "decode",
    "decode_header",
    "decode_payload",
    "encode",
    "forge_none_alg",
]
