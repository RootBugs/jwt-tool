"""Core JWT logic: strict base64url, HS256/384/512 sign & verify,
claim validation with an injected clock, key rotation and the
``alg=none`` attack demo.

Design notes
------------
* Signature verification always happens **before** any claim is
  inspected, so an attacker cannot influence validation order.
* The ``alg`` header is checked against an explicit allow-list
  *before* the signature is even computed; ``alg="none"`` is rejected
  unconditionally, even if a caller lists it in the allow-list.
* All time checks take ``now`` (injected) plus ``leeway`` seconds, so
  expiry tests are deterministic — no sleeps, no wall-clock flakiness.
* Keys are either a single secret (``key=``) or a :class:`KeyRing`
  keyed by the token's ``kid`` header (``keys=``), which is how key
  rotation works: rotate the secret under the same ``kid`` and old
  tokens stop verifying while new ones keep working.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import time
from collections.abc import Mapping, Sequence

from .exceptions import (
    AlgorithmError,
    ClaimError,
    InvalidSignatureError,
    JWTError,
    MalformedTokenError,
    UnknownKeyError,
)

__all__ = [
    "b64url_encode",
    "b64url_decode",
    "encode",
    "decode",
    "decode_header",
    "decode_payload",
    "forge_none_alg",
    "KeyRing",
    "SUPPORTED_ALGORITHMS",
]

#: HMAC hash constructors per allowed ``alg`` header value.
SUPPORTED_ALGORITHMS: dict[str, object] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_MISSING = object()


# --------------------------------------------------------------- base64url


def b64url_encode(data: bytes) -> str:
    """RFC 4648 base64url without ``=`` padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strict inverse of :func:`b64url_encode`.

    Rejects ``=`` padding, any character outside the base64url alphabet
    and lengths congruent to 1 mod 4 (which can never be valid).
    """
    if not isinstance(text, str):
        raise MalformedTokenError("base64url input must be a string")
    if "=" in text:
        raise MalformedTokenError("base64url input must not contain '=' padding")
    for char in text:
        if char not in _B64URL_ALPHABET:
            raise MalformedTokenError(f"invalid base64url character {char!r}")
    if len(text) % 4 == 1:
        raise MalformedTokenError("invalid base64url length")
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - guarded
        raise MalformedTokenError("invalid base64url data") from exc


def _json_bytes(value: Mapping) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _decode_json_object(part: str, what: str) -> dict:
    raw = b64url_decode(part)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedTokenError(f"{what} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise MalformedTokenError(f"{what} must be a JSON object")
    return value


def _to_bytes(value: object, what: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"{what} must be str or bytes")


# ---------------------------------------------------------------- key ring


class KeyRing:
    """A ``kid -> secret`` table used for verification and rotation.

    Rotation = :meth:`rotate`, which replaces the secret stored under an
    existing ``kid``.  Tokens signed with the retired secret then fail
    with :class:`InvalidSignatureError` while tokens signed with the new
    secret verify normally.
    """

    def __init__(self, keys: Mapping[str, object] | None = None) -> None:
        self._keys: dict[str, bytes] = {}
        if keys:
            for kid, key in keys.items():
                self.add(kid, key)

    def add(self, kid: object, key: object) -> None:
        self._keys[str(kid)] = _to_bytes(key, "key")

    def rotate(self, kid: object, key: object) -> None:
        key_id = str(kid)
        if key_id not in self._keys:
            raise UnknownKeyError(f"cannot rotate unknown kid {key_id!r}")
        self._keys[key_id] = _to_bytes(key, "key")

    def remove(self, kid: object) -> None:
        self._keys.pop(str(kid), None)

    def get(self, kid: object) -> bytes | None:
        return self._keys.get(str(kid))

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def __contains__(self, kid: object) -> bool:
        return str(kid) in self._keys

    def __len__(self) -> int:
        return len(self._keys)


def _resolve_key(
    key: object, keys: object, header: Mapping
) -> bytes:
    if key is not None and keys is not None:
        raise JWTError("provide either 'key' or 'keys', not both")
    if keys is None:
        if key is None:
            raise JWTError("a verification key is required")
        return _to_bytes(key, "key")
    kid = header.get("kid")
    if kid is None:
        raise MalformedTokenError(
            "token carries no 'kid' header but a key ring was provided"
        )
    if not isinstance(kid, str):
        raise MalformedTokenError("'kid' header must be a string")
    if isinstance(keys, KeyRing):
        secret = keys.get(kid)
    elif isinstance(keys, Mapping):
        raw = keys.get(kid)
        secret = None if raw is None else _to_bytes(raw, "key")
    else:
        raise TypeError("keys must be a KeyRing or a mapping of kid -> key")
    if secret is None:
        raise UnknownKeyError(f"no key registered for kid {kid!r}")
    return secret


# ------------------------------------------------------------------ sign


def encode(
    payload: Mapping,
    key: object,
    *,
    alg: str = "HS256",
    kid: object | None = None,
) -> str:
    """Serialize and sign ``payload`` as ``header.payload.signature``."""
    if alg not in SUPPORTED_ALGORITHMS:
        raise AlgorithmError(f"unsupported signing algorithm: {alg!r}")
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    header: dict = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = str(kid)
    header_b64 = b64url_encode(_json_bytes(header))
    payload_b64 = b64url_encode(_json_bytes(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    digest = hmac.new(
        _to_bytes(key, "key"), signing_input, SUPPORTED_ALGORITHMS[alg]
    ).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(digest)}"


# ------------------------------------------------------------------ split


def _split(token: str) -> tuple[dict, dict, bytes, bytes]:
    if not isinstance(token, str):
        raise MalformedTokenError("token must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedTokenError(
            f"expected 3 dot-separated segments, got {len(parts)}"
        )
    header = _decode_json_object(parts[0], "header")
    payload = _decode_json_object(parts[1], "payload")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = b64url_decode(parts[2])
    return header, payload, signing_input, signature


def decode_header(token: str) -> dict:
    """Parse the header without verifying anything."""
    return _split(token)[0]


def decode_payload(token: str) -> dict:
    """Parse the payload without verifying anything (untrusted!)."""
    return _split(token)[1]


# ------------------------------------------------------------------ verify


def _check_alg(header: Mapping, algorithms: Sequence[str]) -> str:
    alg = header.get("alg")
    if not isinstance(alg, str):
        raise MalformedTokenError("header 'alg' must be a string")
    if alg == "none":
        # Unconditional: an explicit allow-list entry cannot enable it.
        raise AlgorithmError("the 'none' algorithm is never accepted")
    if alg not in SUPPORTED_ALGORITHMS:
        raise AlgorithmError(f"unsupported algorithm: {alg!r}")
    allowed = tuple(algorithms)
    if alg not in allowed:
        raise AlgorithmError(
            f"algorithm {alg!r} is not allowed (allowed: {allowed})"
        )
    return alg


def _require_number(payload: Mapping, claim: str):
    value = payload.get(claim, _MISSING)
    if value is _MISSING:
        return _MISSING
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ClaimError(claim, f"{claim} must be a number")
    if not math.isfinite(value):
        raise ClaimError(claim, f"{claim} must be finite")
    return float(value)


def _validate_claims(
    payload: Mapping,
    *,
    now: float | None,
    leeway: float,
    audience: str | None,
    issuer: str | None,
    required: Sequence[str],
) -> None:
    if leeway < 0:
        raise ValueError("leeway must be >= 0")
    current = time.time() if now is None else float(now)

    exp = _require_number(payload, "exp")
    if exp is not _MISSING and current > exp + leeway:
        raise ClaimError("exp", "token has expired")

    nbf = _require_number(payload, "nbf")
    if nbf is not _MISSING and current < nbf - leeway:
        raise ClaimError("nbf", "token is not valid yet")

    iat = _require_number(payload, "iat")
    if iat is not _MISSING and current < iat - leeway:
        raise ClaimError("iat", "token was issued in the future")

    for claim in required:
        if claim not in payload:
            raise ClaimError(claim, "required claim is missing")

    if audience is not None:
        aud = payload.get("aud", _MISSING)
        if aud is _MISSING:
            raise ClaimError("aud", "'aud' claim is required")
        if isinstance(aud, str):
            matches = aud == audience
        elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
            matches = audience in aud
        else:
            raise ClaimError("aud", "'aud' must be a string or list of strings")
        if not matches:
            raise ClaimError("aud", "audience mismatch")

    if issuer is not None:
        iss = payload.get("iss", _MISSING)
        if iss is _MISSING:
            raise ClaimError("iss", "'iss' claim is required")
        if not isinstance(iss, str) or iss != issuer:
            raise ClaimError("iss", "issuer mismatch")


def decode(
    token: str,
    key: object = None,
    *,
    keys: object = None,
    algorithms: Sequence[str] = ("HS256",),
    audience: str | None = None,
    issuer: str | None = None,
    leeway: float = 0.0,
    now: float | None = None,
    required: Sequence[str] = (),
) -> dict:
    """Verify ``token`` and return its payload.

    Order of operations (each step raises a distinct exception type):

    1. structure — :class:`MalformedTokenError`;
    2. algorithm policy — :class:`AlgorithmError` (``none`` rejected
       unconditionally, allow-list checked *before* the signature);
    3. key resolution — :class:`JWTError` / :class:`UnknownKeyError`;
    4. signature — :class:`InvalidSignatureError`;
    5. claims (exp/nbf/iat/aud/iss/required) — :class:`ClaimError`.
    """
    header, payload, signing_input, signature = _split(token)
    alg = _check_alg(header, algorithms)
    secret = _resolve_key(key, keys, header)
    expected = hmac.new(
        secret, signing_input, SUPPORTED_ALGORITHMS[alg]
    ).digest()
    if not hmac.compare_digest(expected, signature):
        raise InvalidSignatureError("signature verification failed")
    _validate_claims(
        payload,
        now=now,
        leeway=leeway,
        audience=audience,
        issuer=issuer,
        required=required,
    )
    return payload


# ------------------------------------------------------------ attack demo


def forge_none_alg(token: str) -> str:
    """Rewrite ``token`` into an ``alg=none`` forgery (attack demo).

    Strips the signature and sets ``alg: "none"`` — the classic attack
    against servers that honour the header instead of their own
    configuration.  :func:`decode` rejects the result with
    :class:`AlgorithmError`; this helper exists so the attack is
    reproducible and testable.
    """
    if not isinstance(token, str):
        raise MalformedTokenError("token must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedTokenError(
            f"expected 3 dot-separated segments, got {len(parts)}"
        )
    header = _decode_json_object(parts[0], "header")
    header["alg"] = "none"
    forged_header = b64url_encode(_json_bytes(header))
    return f"{forged_header}.{parts[1]}."
