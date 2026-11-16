"""Tests for jwt-tool: sign/verify, claim validation, attacks, rotation.

All time-dependent tests inject ``now``; nothing sleeps or touches the
wall clock, so the suite is fully deterministic.
"""
from __future__ import annotations

import contextlib
import io
import json
import unittest

from jwt_tool import (
    AlgorithmError,
    ClaimError,
    InvalidSignatureError,
    JWTError,
    KeyRing,
    MalformedTokenError,
    UnknownKeyError,
    b64url_decode,
    b64url_encode,
    decode,
    decode_header,
    decode_payload,
    encode,
    forge_none_alg,
)
from jwt_tool.cli import main

SECRET = "correct-horse-battery-staple"
NOW = 1_700_000_000.0


def capture(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestBase64Url(unittest.TestCase):
    def test_roundtrip(self):
        for raw in (b"", b"\x00", b"hello world", bytes(range(256))):
            self.assertEqual(b64url_decode(b64url_encode(raw)), raw)

    def test_rejects_padding(self):
        with self.assertRaises(MalformedTokenError):
            b64url_decode("aGVsbG8=")

    def test_rejects_invalid_character(self):
        with self.assertRaises(MalformedTokenError):
            b64url_decode("abc!")
        with self.assertRaises(MalformedTokenError):
            b64url_decode("ab+d")  # standard-base64 alphabet

    def test_rejects_impossible_length(self):
        with self.assertRaises(MalformedTokenError):
            b64url_decode("A")  # len % 4 == 1 can never decode

    def test_encode_has_no_padding_or_std_chars(self):
        text = b64url_encode(bytes(range(256)))
        self.assertNotIn("=", text)
        self.assertNotIn("+", text)
        self.assertNotIn("/", text)


class TestSignVerify(unittest.TestCase):
    def test_roundtrip_hs256(self):
        payload = {"sub": "alice", "role": "admin"}
        token = encode(payload, SECRET)
        self.assertEqual(decode(token, SECRET, now=NOW), payload)

    def test_roundtrip_all_algorithms(self):
        for alg in ("HS256", "HS384", "HS512"):
            with self.subTest(alg=alg):
                token = encode({"a": 1}, SECRET, alg=alg)
                self.assertEqual(
                    decode(token, SECRET, algorithms=(alg,), now=NOW), {"a": 1}
                )

    def test_encode_is_deterministic(self):
        payload = {"sub": "bob", "n": 42}
        self.assertEqual(encode(payload, SECRET), encode(payload, SECRET))

    def test_kid_header_roundtrip(self):
        token = encode({"sub": "carol"}, SECRET, kid="key-1")
        self.assertEqual(decode_header(token)["kid"], "key-1")
        self.assertEqual(decode(token, SECRET, now=NOW), {"sub": "carol"})

    def test_tampered_payload_rejected(self):
        token = encode({"sub": "alice", "role": "user"}, SECRET)
        header, payload, sig = token.split(".")
        forged = b64url_encode(
            json.dumps({"sub": "alice", "role": "admin"}).encode()
        )
        with self.assertRaises(InvalidSignatureError):
            decode(f"{header}.{forged}.{sig}", SECRET, now=NOW)

    def test_tampered_signature_rejected(self):
        token = encode({"sub": "alice"}, SECRET)
        header, payload, sig = token.split(".")
        broken = ("A" if sig[0] != "A" else "B") + sig[1:]
        with self.assertRaises(InvalidSignatureError):
            decode(f"{header}.{payload}.{broken}", SECRET, now=NOW)

    def test_wrong_key_rejected(self):
        token = encode({"sub": "alice"}, SECRET)
        with self.assertRaises(InvalidSignatureError):
            decode(token, "attacker-key", now=NOW)

    def test_empty_signature_rejected(self):
        token = encode({"sub": "alice"}, SECRET)
        header, payload, _ = token.split(".")
        with self.assertRaises(InvalidSignatureError):
            decode(f"{header}.{payload}.", SECRET, now=NOW)

    def test_sign_rejects_unsupported_alg(self):
        with self.assertRaises(AlgorithmError):
            encode({"a": 1}, SECRET, alg="none")
        with self.assertRaises(AlgorithmError):
            encode({"a": 1}, SECRET, alg="RS256")

    def test_sign_requires_mapping_payload(self):
        with self.assertRaises(TypeError):
            encode(["not", "a", "dict"], SECRET)

    def test_decode_requires_key(self):
        token = encode({"a": 1}, SECRET)
        with self.assertRaises(JWTError):
            decode(token, now=NOW)


class TestAlgorithmPolicy(unittest.TestCase):
    def test_none_alg_attack_rejected(self):
        token = encode({"sub": "admin", "role": "admin"}, SECRET)
        forged = forge_none_alg(token)
        self.assertEqual(forged.split(".")[2], "")
        self.assertEqual(decode_header(forged)["alg"], "none")
        with self.assertRaises(AlgorithmError):
            decode(forged, SECRET, now=NOW)

    def test_none_never_allowed_even_if_listed(self):
        token = encode({"a": 1}, SECRET)
        forged = forge_none_alg(token)
        with self.assertRaises(AlgorithmError):
            decode(forged, "", algorithms=("none",), now=NOW)
        with self.assertRaises(AlgorithmError):
            decode(forged, None, algorithms=("none",), now=NOW)

    def test_allow_list_checked_before_signature(self):
        # Signed with HS512 under attacker's own key, header claims the
        # token is fine — the allow-list must reject before any MAC work.
        token = encode({"a": 1}, "attacker-key", alg="HS512")
        with self.assertRaises(AlgorithmError):
            decode(token, "attacker-key", algorithms=("HS256",), now=NOW)

    def test_alg_header_tamper_detected(self):
        # Flip HS256 -> HS384 in the header; signature was HS256.
        token = encode({"a": 1}, SECRET)
        header, payload, sig = token.split(".")
        obj = json.loads(b64url_decode(header))
        obj["alg"] = "HS384"
        tampered = b64url_encode(json.dumps(obj).encode())
        # HS384 not allowed -> policy error, not a garbage signature check.
        with self.assertRaises(AlgorithmError):
            decode(f"{tampered}.{payload}.{sig}", SECRET, algorithms=("HS256",))
        # Even when HS384 is allowed, the HS256 MAC fails cleanly.
        with self.assertRaises(InvalidSignatureError):
            decode(
                f"{tampered}.{payload}.{sig}",
                SECRET,
                algorithms=("HS256", "HS384"),
                now=NOW,
            )

    def test_alg_tamper_to_none_rejected(self):
        token = encode({"a": 1}, SECRET)
        forged = forge_none_alg(token)
        with self.assertRaises(AlgorithmError):
            decode(forged, SECRET, algorithms=("HS256", "none"), now=NOW)

    def test_non_string_alg_rejected(self):
        token = encode({"a": 1}, SECRET)
        header, payload, sig = token.split(".")
        obj = json.loads(b64url_decode(header))
        obj["alg"] = 256
        tampered = b64url_encode(json.dumps(obj).encode())
        with self.assertRaises(MalformedTokenError):
            decode(f"{tampered}.{payload}.{sig}", SECRET)


class TestClaimValidation(unittest.TestCase):
    def test_expired_token_rejected(self):
        token = encode({"exp": NOW - 10}, SECRET)
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW)
        self.assertEqual(ctx.exception.claim, "exp")

    def test_valid_token_within_leeway(self):
        token = encode({"exp": NOW - 5}, SECRET)
        self.assertEqual(
            decode(token, SECRET, now=NOW, leeway=10), {"exp": NOW - 5}
        )

    def test_not_yet_valid_rejected(self):
        token = encode({"nbf": NOW + 60}, SECRET)
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW)
        self.assertEqual(ctx.exception.claim, "nbf")

    def test_nbf_within_leeway_accepted(self):
        token = encode({"nbf": NOW + 5}, SECRET)
        decode(token, SECRET, now=NOW, leeway=10)

    def test_future_iat_rejected(self):
        token = encode({"iat": NOW + 120}, SECRET)
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW)
        self.assertEqual(ctx.exception.claim, "iat")

    def test_injected_clock_changes_outcome(self):
        token = encode({"exp": NOW + 60}, SECRET)
        decode(token, SECRET, now=NOW)  # before expiry
        with self.assertRaises(ClaimError):
            decode(token, SECRET, now=NOW + 3600)  # after expiry

    def test_non_numeric_exp_rejected(self):
        token = encode({"exp": "tomorrow"}, SECRET)
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW)
        self.assertEqual(ctx.exception.claim, "exp")

    def test_boolean_exp_rejected(self):
        # bool is an int subclass; it must not slip through as a timestamp.
        token = encode({"exp": True}, SECRET)
        with self.assertRaises(ClaimError):
            decode(token, SECRET, now=NOW)

    def test_required_claim_missing(self):
        token = encode({"sub": "alice"}, SECRET)
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW, required=("exp",))
        self.assertEqual(ctx.exception.claim, "exp")

    def test_audience_match_and_mismatch(self):
        token = encode({"aud": "service-a"}, SECRET)
        self.assertEqual(
            decode(token, SECRET, now=NOW, audience="service-a"),
            {"aud": "service-a"},
        )
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW, audience="service-b")
        self.assertEqual(ctx.exception.claim, "aud")

    def test_audience_list_membership(self):
        token = encode({"aud": ["one", "two"]}, SECRET)
        decode(token, SECRET, now=NOW, audience="two")
        with self.assertRaises(ClaimError):
            decode(token, SECRET, now=NOW, audience="three")

    def test_audience_missing_claim(self):
        token = encode({"sub": "alice"}, SECRET)
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW, audience="any")
        self.assertEqual(ctx.exception.claim, "aud")

    def test_issuer_match_and_mismatch(self):
        token = encode({"iss": "auth.example"}, SECRET)
        decode(token, SECRET, now=NOW, issuer="auth.example")
        with self.assertRaises(ClaimError) as ctx:
            decode(token, SECRET, now=NOW, issuer="evil.example")
        self.assertEqual(ctx.exception.claim, "iss")


class TestKeyRotation(unittest.TestCase):
    def test_rotation_rejects_old_key_accepts_new(self):
        ring = KeyRing({"1": "old-secret"})
        old_token = encode({"sub": "alice"}, "old-secret", kid="1")
        # Before rotation the old token verifies.
        self.assertEqual(decode(old_token, keys=ring, now=NOW), {"sub": "alice"})
        # Rotate: same kid, new secret -> old token now fails cleanly.
        ring.rotate("1", "new-secret")
        with self.assertRaises(InvalidSignatureError):
            decode(old_token, keys=ring, now=NOW)
        new_token = encode({"sub": "alice"}, "new-secret", kid="1")
        self.assertEqual(decode(new_token, keys=ring, now=NOW), {"sub": "alice"})

    def test_unknown_kid_rejected(self):
        ring = KeyRing({"1": SECRET})
        token = encode({"a": 1}, "other", kid="99")
        with self.assertRaises(UnknownKeyError):
            decode(token, keys=ring, now=NOW)

    def test_missing_kid_with_ring_rejected(self):
        ring = KeyRing({"1": SECRET})
        token = encode({"a": 1}, SECRET)  # no kid header
        with self.assertRaises(MalformedTokenError):
            decode(token, keys=ring, now=NOW)

    def test_key_and_keys_together_rejected(self):
        ring = KeyRing({"1": SECRET})
        token = encode({"a": 1}, SECRET, kid="1")
        with self.assertRaises(JWTError):
            decode(token, SECRET, keys=ring, now=NOW)

    def test_plain_dict_key_ring(self):
        token = encode({"a": 1}, SECRET, kid="k")
        self.assertEqual(decode(token, keys={"k": SECRET}, now=NOW), {"a": 1})

    def test_rotate_unknown_kid_raises(self):
        ring = KeyRing({"1": SECRET})
        with self.assertRaises(UnknownKeyError):
            ring.rotate("2", "x")
        self.assertEqual(len(ring), 1)
        self.assertIn("1", ring)
        self.assertEqual(ring.kids, ("1",))


class TestMalformedTokens(unittest.TestCase):
    def test_wrong_segment_count(self):
        for bad in ("", "a.b", "a.b.c.d", "onlyone"):
            with self.subTest(token=bad):
                with self.assertRaises(MalformedTokenError):
                    decode(bad, SECRET, now=NOW)

    def test_non_string_token(self):
        with self.assertRaises(MalformedTokenError):
            decode(None, SECRET)  # type: ignore[arg-type]

    def test_header_not_json(self):
        with self.assertRaises(MalformedTokenError):
            decode("!!!.eyJhIjoxfQ.sig", SECRET)

    def test_payload_not_object(self):
        header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
        payload = b64url_encode(b"[1,2,3]")
        with self.assertRaises(MalformedTokenError):
            decode(f"{header}.{payload}.x", SECRET)

    def test_payload_not_json(self):
        header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
        payload = b64url_encode(b"not json")
        with self.assertRaises(MalformedTokenError):
            decode(f"{header}.{payload}.x", SECRET)


class TestCLI(unittest.TestCase):
    def test_sign_then_verify_roundtrip(self):
        code, out, _ = capture(
            ["sign", "--payload", '{"sub":"alice"}', "--key", SECRET]
        )
        self.assertEqual(code, 0)
        token = out.strip()
        code, out, err = capture(["verify", token, "--key", SECRET])
        self.assertEqual(code, 0, err)
        self.assertIn('"sub": "alice"', out)

    def test_verify_wrong_key_fails(self):
        code, out, _ = capture(
            ["sign", "--payload", '{"sub":"alice"}', "--key", SECRET]
        )
        code, out, err = capture(["verify", out.strip(), "--key", "wrong"])
        self.assertEqual(code, 1)
        self.assertIn("InvalidSignatureError", err)

    def test_verify_expired_with_injected_clock(self):
        token = encode({"sub": "alice", "exp": NOW + 60}, SECRET)
        code, _, _ = capture(
            ["verify", token, "--key", SECRET, "--now", str(NOW)]
        )
        self.assertEqual(code, 0)
        code, _, err = capture(
            ["verify", token, "--key", SECRET, "--now", str(NOW + 3600)]
        )
        self.assertEqual(code, 1)
        self.assertIn("ClaimError", err)

    def test_verify_none_attack_fails(self):
        token = forge_none_alg(encode({"role": "admin"}, SECRET))
        code, _, err = capture(["verify", token, "--key", SECRET])
        self.assertEqual(code, 1)
        self.assertIn("AlgorithmError", err)

    def test_sign_json_output(self):
        code, out, _ = capture(
            ["sign", "--payload", '{"a":1}', "--key", SECRET, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertIn("token", json.loads(out))

    def test_verify_json_failure_is_structured(self):
        code, out, _ = capture(
            ["verify", "garbage", "--key", SECRET, "--json"]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["error"], "MalformedTokenError")

    def test_decode_is_marked_unverified(self):
        token = encode({"sub": "alice"}, SECRET)
        code, out, _ = capture(["decode", token, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertFalse(payload["verified"])
        self.assertEqual(payload["payload"], {"sub": "alice"})

    def test_sign_rejects_non_object_payload(self):
        code, _, err = capture(
            ["sign", "--payload", "[1,2]", "--key", SECRET]
        )
        self.assertEqual(code, 1)
        self.assertIn("JSON object", err)


if __name__ == "__main__":
    unittest.main()
