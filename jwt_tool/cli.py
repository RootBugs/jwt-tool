"""Command-line interface: ``sign``, ``verify`` and ``decode``.

Exit codes: 0 = success (token valid / decoded), 1 = JWT failure
(bad signature, expired, malformed, ...), 2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import sys

from .core import SUPPORTED_ALGORITHMS, decode, decode_header, decode_payload, encode
from .exceptions import JWTError

__all__ = ["main", "build_parser"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwt-tool",
        description="Sign and verify HS* JWTs with strict validation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sign = sub.add_parser("sign", help="sign a JSON payload")
    sign.add_argument("--payload", required=True, help="JSON object string")
    sign.add_argument("--key", required=True, help="HMAC secret")
    sign.add_argument(
        "--alg", default="HS256", choices=sorted(SUPPORTED_ALGORITHMS)
    )
    sign.add_argument("--kid", default=None, help="key id header")
    sign.add_argument("--json", action="store_true", dest="as_json")

    verify = sub.add_parser("verify", help="verify a token and print its payload")
    verify.add_argument("token")
    verify.add_argument("--key", default=None, help="HMAC secret")
    verify.add_argument(
        "--alg",
        action="append",
        dest="algorithms",
        default=None,
        choices=sorted(SUPPORTED_ALGORITHMS),
        help="allowed algorithm (repeatable; default HS256)",
    )
    verify.add_argument("--now", type=float, default=None, help="injected clock")
    verify.add_argument("--leeway", type=float, default=0.0)
    verify.add_argument("--aud", default=None, dest="audience")
    verify.add_argument("--iss", default=None, dest="issuer")
    verify.add_argument(
        "--require", action="append", default=[], help="required claim"
    )
    verify.add_argument("--json", action="store_true", dest="as_json")

    show = sub.add_parser("decode", help="decode without verifying (untrusted)")
    show.add_argument("token")
    show.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _cmd_sign(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        print(f"error: --payload is not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("error: --payload must be a JSON object", file=sys.stderr)
        return 1
    token = encode(
        payload, args.key, alg=args.alg, kid=args.kid
    )
    if args.as_json:
        print(json.dumps({"token": token}, indent=2, sort_keys=True))
    else:
        print(token)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    algorithms = tuple(args.algorithms) if args.algorithms else ("HS256",)
    try:
        payload = decode(
            args.token,
            args.key,
            algorithms=algorithms,
            audience=args.audience,
            issuer=args.issuer,
            leeway=args.leeway,
            now=args.now,
            required=tuple(args.require),
        )
    except JWTError as exc:
        if args.as_json:
            print(
                json.dumps(
                    {"valid": False, "error": type(exc).__name__, "message": str(exc)},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.as_json:
        print(
            json.dumps(
                {"valid": True, "payload": payload}, indent=2, sort_keys=True
            )
        )
    else:
        print("valid")
        print(json.dumps(payload, sort_keys=True))
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    try:
        header = decode_header(args.token)
        payload = decode_payload(args.token)
    except JWTError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.as_json:
        print(
            json.dumps(
                {"header": header, "payload": payload, "verified": False},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"verified: false (do not trust this payload)")
        print(f"header:   {json.dumps(header, sort_keys=True)}")
        print(f"payload:  {json.dumps(payload, sort_keys=True)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "sign":
        return _cmd_sign(args)
    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "decode":
        return _cmd_decode(args)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
