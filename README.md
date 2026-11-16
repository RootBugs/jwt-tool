# jwt-tool

A zero-dependency, strict **JWT implementation** in pure Python:
HS256/HS384/HS512 sign & verify, `exp`/`nbf`/`iat`/`aud`/`iss`
validation with an injected clock, a reproducible **`alg=none` attack
demo** (and its fix), and **key rotation** via `kid`-keyed secrets.

## Why

Most JWT vulnerabilities are not broken crypto — they are *policy*
bugs: trusting the `alg` header instead of server configuration,
skipping expiry checks, or never rotating leaked keys.  This project
makes each of those failure modes explicit and testable:

* **strict parsing** — base64url without padding, no non-alphabet
  characters, three segments exactly, header/payload must be JSON
  objects; every violation raises `MalformedTokenError`;
* **algorithm policy before signature** — the `alg` header is checked
  against an allow-list *before* any MAC is computed, and `alg="none"`
  is rejected unconditionally, even if a caller lists it;
* **claim validation** — `exp`, `nbf`, `iat` (numbers only, `bool`
  excluded), `aud`, `iss` and arbitrary required claims, all driven by
  an injected `now` + `leeway` so tests never sleep;
* **key rotation** — a `KeyRing` maps `kid` → secret; rotating replaces
  the secret under the same `kid`, so old tokens stop verifying and new
  ones keep working.

## Architecture

```
jwt_tool/
  exceptions.py   # JWTError hierarchy: MalformedTokenError, AlgorithmError,
                  #   InvalidSignatureError, UnknownKeyError, ClaimError(.claim)
  core.py         # b64url helpers, encode/decode, KeyRing, claim checks,
                  #   forge_none_alg() attack demo
  cli.py          # `sign`, `verify`, `decode` subcommands (--json, --now)
```

`decode()` order: structure → algorithm policy → key resolution →
signature (`hmac.compare_digest`) → claims.  Each step raises a
distinct exception type, so a test can assert *exactly* what failed.

## Run it

From the project root (`projects/jwt-tool`):

```console
> python -m jwt_tool sign --payload "{\"sub\":\"alice\",\"role\":\"user\"}" --key s3cret
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.y_JVI8ctP8MenjSZWiItYdCe9ek6Vm6cz-gh_shiLUc

> python -m jwt_tool verify <token> --key s3cret
valid
{"role": "user", "sub": "alice"}
```

Wrong key fails cleanly (exit code 1):

```console
> python -m jwt_tool verify <token> --key wrong
error: InvalidSignatureError: signature verification failed
```

The `alg=none` attack, reproduced and rejected:

```console
> python -c "from jwt_tool import encode, forge_none_alg; print(forge_none_alg(encode({'sub':'admin'}, 's3cret')))"
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

> python -m jwt_tool verify <forged> --key s3cret
error: AlgorithmError: the 'none' algorithm is never accepted
```

Key rotation from the library:

```python
from jwt_tool import KeyRing, encode, decode, InvalidSignatureError

ring = KeyRing({"1": "old-secret"})
old = encode({"sub": "alice"}, "old-secret", kid="1")
decode(old, keys=ring)                 # ok before rotation

ring.rotate("1", "new-secret")         # same kid, new secret
decode(old, keys=ring)                 # InvalidSignatureError (old key retired)
new = encode({"sub": "alice"}, "new-secret", kid="1")
decode(new, keys=ring)                 # ok
```

Expiry with an injected clock (what the tests use — no sleeps):

```python
decode(token, key, now=1_700_000_000, leeway=30)
# ClaimError: exp: token has expired   when now > exp + leeway
```

Exit codes: `0` valid, `1` JWT failure (bad signature, expired,
malformed, forbidden algorithm), `2` usage error.  `--json` works on
every subcommand; `decode` prints `"verified": false` to make clear the
payload is untrusted.

## Test

```console
> python -m unittest discover -s tests -v
```

54 tests cover base64url strictness, sign/verify round-trips across all
three algorithms, tampered payload/signature/key, the `none` attack and
allow-list ordering, exp/nbf/iat/aud/iss via injected clocks, key
rotation (old rejected / new accepted), malformed tokens and the CLI
exit codes — all deterministic, no network, no sleeps.

## License

MIT — see [LICENSE](LICENSE).
