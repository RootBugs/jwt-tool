"""Exception hierarchy for jwt-tool.

Every failure mode maps to a distinct exception type so callers (and
tests) can assert exactly *what* went wrong instead of matching free
text: structure problems, algorithm policy, signature mismatch, unknown
key, and claim validation.
"""
from __future__ import annotations

__all__ = [
    "JWTError",
    "MalformedTokenError",
    "AlgorithmError",
    "InvalidSignatureError",
    "UnknownKeyError",
    "ClaimError",
]


class JWTError(Exception):
    """Base class for every jwt-tool failure."""


class MalformedTokenError(JWTError):
    """The token is structurally invalid (segments, base64url, JSON)."""


class AlgorithmError(JWTError):
    """The ``alg`` header is missing, unsupported, forbidden or not allowed."""


class InvalidSignatureError(JWTError):
    """The HMAC does not match — wrong key or tampered token."""


class UnknownKeyError(JWTError):
    """The token's ``kid`` is not present in the provided key ring."""


class ClaimError(JWTError):
    """A registered claim failed validation (``exp``, ``nbf``, ``aud``...)."""

    def __init__(self, claim: str, message: str) -> None:
        super().__init__(f"{claim}: {message}")
        self.claim = claim
        self.message = message
